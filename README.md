# dpipot-analytics(1) — TUI Log Processor & DuckDB Query Engine para DPIpot-NG

```
       ___       _             _                             _       _   _
    __| _ \_ _  (_)_ __  ___ _| |_      __ _ _ _  __ _ | |_  _ __| |_(_)__ ___
   / _` |  _/ | | | '_ \/ _ \_  __|    / _` | ' \/ _` || | || (_-<  _| / _(_-<
   \__,_|_| |_| |_| .__/\___/ |_|      \__,_|_||_\__,_||_|\_, /__/\__|_\__/__/
                  |_|                                     |__/
```

> Analisador especializado para os logs do **DPIpot-NG**: processamento de CSVs completos por dia em Parquet (Zstandard), consultas analíticas DuckDB com filtro por intervalo de datas e dicionário de metadados configurável via TOML.

---

## 🚀 VISÃO GERAL & REQUISITOS ATENDIDOS

O `dpipot-analytics` é dedicado e otimizado exclusivamente para a análise dos quatro tipos de logs gerados pela arquitetura DPIpot:

1. **`classifier`**: Logs de classificação profunda de tráfego de rede na borda (nDPI / DPIpot Classifier).
2. **`infra`**: Logs operacionais de infraestrutura Kubernetes, agentes Filebeat e telemetria de nós.
3. **`pods`**: Logs de sessões e interações diretas de invasores com os honeypots (Cowrie SSH/Telnet, Heralding, etc.).
4. **`proxy`**: Logs de fluxos de rede capturados pelo proxy transparente (TPROXY) com enriquecimento GeoIP/ASN e telemetria.

### Principais Funcionalidades:

* **Ingestão Específica por Dia**: Varre a pasta `logs/` identificando os arquivos no formato `dpipot-<tipo>-<data>.csv` e converte para a pasta `data/` preservando 100% das colunas em formato colunar Apache Parquet com o mesmo nome e extensão `.parquet` (ex: `dpipot-classifier-2026.07.27.parquet`).
* **Consultas por Intervalo de Datas**: Permite filtrar o período de análise (ex: `2026-07-01` a `2026-07-31`). O motor DuckDB carrega dinamicamente a união dos arquivos Parquet correspondentes ao período selecionado para execução de consultas ANSI SQL de alta performance em milissegundos.
* **Esquema Configurável em TOML (`dpipot_types.toml`)**: Cada um dos 4 tipos possui uma seção no arquivo com o nome de cada coluna, tipo SQL, exemplo real e descrição semântica. O arquivo pode ser editado pelo usuário.
* **Dicionário Interativo na TUI**: Aba dedicada exibindo todas as colunas de cada tipo de arquivo, com pesquisa/filtro em tempo real e botão de recarga instantânea (`Recarregar TOML`).
* **CLI Headless**: Utilitário de linha de comando (`scripts/dpipot_cli.py`) para automações em scripts e pipelines.

---

## 💻 EXECUÇÃO

```bash
# Iniciar a Interface TUI Especializada
python tui.py
# ou
python scripts/tui.py

# Utilizar a CLI (Headless)
python scripts/dpipot_cli.py list
python scripts/dpipot_cli.py schema --type proxy --filter "geo"
python scripts/dpipot_cli.py query --type infra --start 2026-07-27 --end 2026-07-28 --sql "SELECT \"log.level\", COUNT(*) FROM logs GROUP BY 1"
```

---

## ⌨️ ATALHOS DE TECLADO NA TUI

| Atalho | Contexto | Ação |
| :--- | :--- | :--- |
| `F1` | Global | Alternar para a Aba 1: **Ingestão de Logs (CSV ➔ Parquet)** |
| `F2` | Global | Alternar para a Aba 2: **Consultas por Intervalo de Datas** |
| `F3` | Global | Alternar para a Aba 3: **Dicionário de Colunas (Config TOML)** |
| `Ctrl + R` | Global | Recarregar lista de arquivos e esquemas TOML |
| `Ctrl + Q` | Global | Sair da aplicação |
| `Tab` / `Shift + Tab` | Global | Alternar foco entre componentes |

---

## 📁 ESTRUTURA DOS ARQUIVOS E PASTAS

* `logs/`: Diretório contendo os arquivos CSV brutos por dia:
  * `dpipot-classifier-YYYY.MM.DD.csv`
  * `dpipot-infra-YYYY.MM.DD.csv`
  * `dpipot-pods-YYYY.MM.DD.csv`
  * `dpipot-proxy-YYYY.MM.DD.csv`
* `data/`: Diretório de destino dos arquivos Parquet completos gerados (com o mesmo nome base):
  * `dpipot-classifier-YYYY.MM.DD.parquet`
  * `dpipot-infra-YYYY.MM.DD.parquet`
  * `dpipot-pods-YYYY.MM.DD.parquet`
  * `dpipot-proxy-YYYY.MM.DD.parquet`
* `dpipot_types.toml`: Arquivo de configuração e documentação das colunas de cada tipo (`classifier`, `infra`, `pods`, `proxy`).

---

## ⚙️ FORMATO DO ARQUIVO TOML (`dpipot_types.toml`)

O arquivo TOML permite personalização direta pelo usuário. Para cada tipo de log:

```toml
[proxy]
name = "proxy"
label = "Proxy MITM & Fluxos de Rede"
description = "Logs de fluxos capturados pelo proxy transparente (TPROXY) com enriquecimento GeoIP/ASN e telemetria."
total_columns = 89

[[proxy.columns]]
name = "src_ip"
type = "VARCHAR"
example = "193.34.212.238"
description = "Endereço IP de origem do tráfego ou atacante"

[[proxy.columns]]
name = "src_geo.country_name"
type = "VARCHAR"
example = "Poland"
description = "País de origem do atacante"

[[proxy.columns]]
name = "duration_ms"
type = "DOUBLE"
example = "683.945299"
description = "Duração total do fluxo de conexão em milissegundos"
```

A TUI recarrega essas alterações em tempo real na Aba 3 através do botão **Recarregar TOML**.
