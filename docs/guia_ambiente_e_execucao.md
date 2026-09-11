# Guia de Configuração do Ambiente e Pipeline de Execução (DuckDB + Parquet)

Este guia prático explica como o ambiente Python foi configurado, como operá-lo no dia a dia com o gerenciador `uv`, e detalha a mecânica do pipeline de dados que transforma **160 GB de logs brutos em CSV** em **arquivos colunares Parquet de alta performance**.

---

## 1. O Ambiente de Execução

Utilizamos o **`uv`**, o gerenciador de pacotes e ambientes virtuais em Rust extremamente rápido, dispensando instalações manuais complexas.

### A. Estrutura do Ambiente Criado
* **Ambiente Virtual**: `.venv/` (criado na raiz do projeto `analise-logs-willen`)
* **Arquivo de Dependências**: [requirements.txt](file:///home/saar/code/mestrado/analise-logs-willen/requirements.txt)
* **Principais Pacotes Instalados**:
  * `duckdb` (v1.5.5): Motor analítico SQL *out-of-core*.
  * `polars` (v1.44.1): Processamento vetorial em Rust.
  * `pyarrow` (v25.0.1): Manipulação nativa de Apache Parquet.
  * `matplotlib` & `seaborn`: Geração de figuras científicas.
  * `jupyterlab`: Ambiente interativo de experimentação.

### B. Como Ativar e Usar o Ambiente

Sempre que abrir um novo terminal para trabalhar no projeto:

```bash
# 1. Navegar até a pasta do projeto
cd /home/saar/code/mestrado/analise-logs-willen

# 2. Ativar o ambiente virtual
source .venv/bin/activate

# 3. (Opcional) Iniciar o JupyterLab para análise interativa
jupyter lab
```

Caso precise adicionar uma nova biblioteca no futuro:
```bash
uv pip install nome-do-pacote
```

---

## 2. A Mecânica do Pipeline: Do CSV Bruto ao Parquet

Entenda o que acontece passo a passo quando processamos os logs gigantes:

```
[ 160 GB de CSVs no Disco ]
            │
            ▼  (1) Leitura em Streaming / Chunks em C++
[ DuckDB: In-Process Engine ] ──▶ Filtra linhas (WHERE protocol = 'ssh')
                                ──▶ Seleciona apenas as colunas úteis
            │
            ▼  (2) Compressão Colunar Zstandard + Dicionário
[ Apache Parquet (.parquet) ]
            │
            ▼
[ Resultados: ~1 a 2 GB ] ──▶ Consultas SQL em milissegundos / DataFrames
```

### O que o Log Bruto é?
* Arquivos CSV no disco (`dpipot-pods-2026.07.27.csv`, etc.).
* É texto puro, sem índice e linha a linha (formato *row-oriented*). Cada linha possui mais de 100 colunas, a maioria irrelevante para a análise imediata de SSH (ex: colunas de Kubernetes DaemonSets, métricas de memória interna do Filebeat, etc.).
* Se você tentar abrir no Pandas: ele tenta converter cada valor de texto para ponteiro de objeto em RAM, estourando a memória e travando o computador.

### O que o DuckDB faz?
1. **Streaming em Bloco (Multi-threaded)**: O DuckDB divide o arquivo CSV em múltiplos segmentos físicos no disco e lê blocos de 122.880 tuplas em paralelo, distribuindo o trabalho por todos os núcleos da CPU.
2. **Pushdown de Predicado (*Predicate Pushdown*)**: O filtro `WHERE protocol = 'ssh'` ou `WHERE honeypot LIKE '%cowrie%'` é avaliado diretamente durante a leitura do disco. Registros de outros protocolos (HTTP, DNS, etc.) são descartados antes mesmo de serem alocados.
3. **Pushdown de Projeção (*Projection Pushdown*)**: O DuckDB ignora os bytes das colunas que não foram solicitadas na consulta `SELECT`.
4. **Execução Out-of-Core**: Se uma operação analítica (como um `GROUP BY` complexo) demandar mais RAM do que o computador tem disponível, o DuckDB escreve temporariamente em disco (*spill to disk*) em vez de abortar com erro de falta de memória (*Out of Memory*).

### O que o Apache Parquet faz?
1. **Armazenamento Colunar**: Em vez de gravar linha após linha, o Parquet grava coluna após coluna. Se você quer calcular o TOP 10 de `hassh`, o leitor só lê os blocos da coluna `hassh` no disco, ignorando 98% do arquivo.
2. **Compressão Inteligente**: Como os dados de uma mesma coluna têm o mesmo tipo e muitos valores repetidos (ex: o mesmo hash HASSH se repete milhares de vezes), o Parquet aplica *Dictionary Encoding* e compressão *Zstandard*. Isso reduz o tamanho do arquivo em até **90%**.
3. **Estatísticas Embutidas (*Row Groups*)**: O arquivo Parquet armazena valores mínimos e máximos de cada bloco de dados no cabeçalho. Ao buscar por uma data ou IP, ele consegue "pular" blocos inteiros sem sequer descompactá-los.

---

## 3. Comandos e Scripts de Execução

Para rodar os scripts criados neste projeto, utilizaremos o Python do ambiente virtual:

```bash
# Executar script de extração SSH
python scripts/extrair_ssh_parquet.py

# Rodar consulta interativa rápida via CLI do DuckDB
python -c "
import duckdb
con = duckdb.connect()
print(con.sql('SELECT COUNT(*) FROM read_parquet(\"data/dpipot_ssh_pods.parquet\")').show())
"
```
