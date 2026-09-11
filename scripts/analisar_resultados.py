#!/usr/bin/env python3
"""
Script de Análise e Geração de Figuras para o Artigo
Gera visualizações científicas usando DuckDB, Polars, Matplotlib e Seaborn.
"""

import os
import duckdb
import matplotlib.pyplot as plt
import seaborn as sns

sns.set_theme(style="whitegrid", palette="deep")
plt.rcParams.update({
    "font.size": 11,
    "axes.labelsize": 12,
    "axes.titlesize": 14,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "figure.titlesize": 16
})

DOCS_DIR = "docs"
DATA_DIR = "data"
PODS_PARQUET = os.path.join(DATA_DIR, "dpipot_ssh_pods.parquet")
PROXY_PARQUET = os.path.join(DATA_DIR, "dpipot_ssh_proxy.parquet")


def gerar_grafico_paises(con):
    print("Gerando gráfico: Top 10 Países Atacantes...")
    df = con.sql(f"""
        SELECT 
            COALESCE(src_country, 'Desconhecido') AS pais,
            COUNT(*) AS total_conexoes,
            COUNT(DISTINCT real_attacker_ip) AS ips_unicos
        FROM read_parquet('{PROXY_PARQUET}')
        WHERE src_country IS NOT NULL AND src_country != ''
        GROUP BY src_country
        ORDER BY total_conexoes DESC
        LIMIT 10
    """).df()

    plt.figure(figsize=(10, 5))
    ax = sns.barplot(data=df, x="total_conexoes", y="pais", color="#2b5c8f")
    plt.title("Top 10 Países de Origem dos Ataques SSH (DPIpot-NG)", pad=15)
    plt.xlabel("Total de Conexões Interceptadas")
    plt.ylabel("País de Origem")
    
    # Adicionar rótulos nas barras
    for p in ax.patches:
        width = p.get_width()
        ax.annotate(f"{int(width):,}", (width, p.get_y() + p.get_height() / 2.),
                    ha="left", va="center", xytext=(5, 0), textcoords="offset points", fontsize=9)
        
    plt.tight_layout()
    output_path = os.path.join(DOCS_DIR, "grafico_top_paises.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"Salvo em: {output_path}")


def gerar_grafico_credenciais(con):
    print("Gerando gráfico: Top 10 Senhas Interceptadas...")
    df = con.sql(f"""
        SELECT 
            attack_type AS senha,
            COUNT(*) AS tentativas
        FROM read_parquet('{PROXY_PARQUET}')
        WHERE ndpi_app = 'password' AND attack_type IS NOT NULL AND attack_type != ''
        GROUP BY attack_type
        ORDER BY tentativas DESC
        LIMIT 10
    """).df()

    plt.figure(figsize=(10, 5))
    ax = sns.barplot(data=df, x="tentativas", y="senha", color="#d95f02")
    plt.title("Top 10 Senhas Tentadas via Força Bruta SSH", pad=15)
    plt.xlabel("Número de Tentativas de Autenticação")
    plt.ylabel("Senha Tentada")

    for p in ax.patches:
        width = p.get_width()
        ax.annotate(f"{int(width):,}", (width, p.get_y() + p.get_height() / 2.),
                    ha="left", va="center", xytext=(5, 0), textcoords="offset points", fontsize=9)

    plt.tight_layout()
    output_path = os.path.join(DOCS_DIR, "grafico_top_senhas.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"Salvo em: {output_path}")


def main():
    con = duckdb.connect()
    gerar_grafico_paises(con)
    gerar_grafico_credenciais(con)
    print("\nTodos os gráficos foram gerados com sucesso na pasta docs/!")


if __name__ == "__main__":
    main()
