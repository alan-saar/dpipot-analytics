#!/usr/bin/env python3
"""
Script de Extração e Enriquecimento SSH: CSV -> Apache Parquet
Extrai eventos de SSH do Honeypot (Pods) e do Proxy MITM com alta fidelidade,
incluindo IPs reais de atacantes, países, ASNs, credenciais e comandos.
"""

import os
import sys
import time
import duckdb
from rich.console import Console
from rich.table import Table

console = Console()

DATA_DIR = "data"
PODS_CSV = "dpipot-pods-2026.07.27.csv"
PROXY_CSV = "dpipot-proxy-2026.07.27.csv"

PODS_PARQUET = os.path.join(DATA_DIR, "dpipot_ssh_pods.parquet")
PROXY_PARQUET = os.path.join(DATA_DIR, "dpipot_ssh_proxy.parquet")


def setup():
    os.makedirs(DATA_DIR, exist_ok=True)


def extrair_pods_ssh(con):
    console.print(f"\n[bold cyan]1. Extraindo e enriquecendo eventos SSH do Cowrie ({PODS_CSV})...[/bold cyan]")
    t0 = time.time()

    query = f"""
    COPY (
        SELECT 
            "@timestamp" AS timestamp,
            eventid,
            session,
            protocol,
            src_ip AS pod_src_ip,
            TRY_CAST(src_port AS INTEGER) AS pod_src_port,
            dst_ip AS pod_dst_ip,
            TRY_CAST(dst_port AS INTEGER) AS pod_dst_port,
            username,
            password,
            hassh,
            hasshAlgorithms,
            kexAlgs,
            keyAlgs,
            REGEXP_EXTRACT("event.original", 'CMD: (.*)', 1) AS executed_command,
            "event.original" AS raw_log
        FROM read_csv(
            '{PODS_CSV}',
            ignore_errors=true,
            all_varchar=true
        )
        WHERE (
            protocol = 'ssh' 
            OR isSSH = 'true' 
            OR eventid LIKE 'cowrie%'
            OR hassh IS NOT NULL
        )
    ) TO '{PODS_PARQUET}' (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000);
    """
    
    con.execute(query)
    elapsed = time.time() - t0
    size_mb = os.path.getsize(PODS_PARQUET) / (1024 * 1024)
    count = con.execute(f"SELECT COUNT(*) FROM read_parquet('{PODS_PARQUET}')").fetchone()[0]
    
    console.print(f"[bold green]✓ Pods concluído em {elapsed:.1f}s![/bold green]")
    console.print(f"  • Linhas extraídas: [yellow]{count:,}[/yellow]")
    console.print(f"  • Tamanho Parquet: [yellow]{size_mb:.2f} MB[/yellow] (Arquivo original: 86.5 GB)")


def extrair_proxy_ssh(con):
    console.print(f"\n[bold cyan]2. Extraindo fluxos SSH enriquecidos do Proxy TPROXY ({PROXY_CSV})...[/bold cyan]")
    t0 = time.time()

    query = f"""
    COPY (
        SELECT 
            "@timestamp" AS timestamp,
            flow_id,
            tuple_id,
            src_ip AS real_attacker_ip,
            TRY_CAST(src_port AS INTEGER) AS attacker_port,
            dst_ip AS target_node_ip,
            TRY_CAST(dst_port AS INTEGER) AS target_port,
            honeypot,
            ndpi_proto,
            ndpi_app,
            attack_type,
            "src_geo.country_name" AS src_country,
            "src_geo.city_name" AS src_city,
            TRY_CAST("src_asn.asn" AS INTEGER) AS src_asn,
            "src_asn.organization_name" AS src_org,
            TRY_CAST(duration_ms AS DOUBLE) AS duration_ms,
            TRY_CAST(tcp_window AS INTEGER) AS tcp_window,
            TRY_CAST(ttl AS INTEGER) AS ttl,
            TRY_CAST(tos AS INTEGER) AS tos,
            payload_src_text
        FROM read_csv(
            '{PROXY_CSV}',
            ignore_errors=true,
            all_varchar=true
        )
        WHERE (
            honeypot LIKE '%cowrie%' 
            OR ndpi_proto = 'SSH'
            OR dst_port IN ('22', '2222')
        )
    ) TO '{PROXY_PARQUET}' (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000);
    """
    
    con.execute(query)
    elapsed = time.time() - t0
    size_mb = os.path.getsize(PROXY_PARQUET) / (1024 * 1024)
    count = con.execute(f"SELECT COUNT(*) FROM read_parquet('{PROXY_PARQUET}')").fetchone()[0]
    
    console.print(f"[bold green]✓ Proxy concluído em {elapsed:.1f}s![/bold green]")
    console.print(f"  • Linhas extraídas: [yellow]{count:,}[/yellow]")
    console.print(f"  • Tamanho Parquet: [yellow]{size_mb:.2f} MB[/yellow] (Arquivo original: 20.5 GB)")


def exibir_estatisticas(con):
    console.print("\n[bold cyan]3. Panorama Preliminar para a Orientadora:[/bold cyan]")
    
    # Top Países
    res_paises = con.execute(f"""
        SELECT 
            src_country,
            COUNT(*) AS total_flows,
            COUNT(DISTINCT real_attacker_ip) AS ips_unicos
        FROM read_parquet('{PROXY_PARQUET}')
        WHERE src_country IS NOT NULL
        GROUP BY src_country
        ORDER BY total_flows DESC
        LIMIT 5
    """).fetchall()

    t_paises = Table(title="Top 5 Países de Origem dos Ataques SSH (Proxy TPROXY)")
    t_paises.add_column("País", style="cyan")
    t_paises.add_column("Total de Conexões", style="green", justify="right")
    t_paises.add_column("IPs Atacantes Únicos", style="yellow", justify="right")
    for r in res_paises:
        t_paises.add_row(r[0], f"{r[1]:,}", f"{r[2]:,}")
    console.print(t_paises)

    # Top Credenciais Interceptadas no Proxy MITM
    res_cred = con.execute(f"""
        SELECT 
            ndpi_app,
            attack_type,
            COUNT(*) AS tentativas
        FROM read_parquet('{PROXY_PARQUET}')
        WHERE ndpi_app IN ('username', 'password') AND attack_type IS NOT NULL
        GROUP BY ndpi_app, attack_type
        ORDER BY tentativas DESC
        LIMIT 8
    """).fetchall()

    t_cred = Table(title="Top Credenciais SSH Interceptadas pelo MITM")
    t_cred.add_column("Tipo", style="magenta")
    t_cred.add_column("Valor Interceptado", style="white")
    t_cred.add_column("Tentativas", style="green", justify="right")
    for r in res_cred:
        t_cred.add_row(r[0].upper(), r[1], f"{r[2]:,}")
    console.print(t_cred)

    # Sessões Cowrie
    res_cowrie = con.execute(f"""
        SELECT 
            COUNT(DISTINCT session) AS sessoes,
            COUNT(CASE WHEN executed_command IS NOT NULL THEN 1 END) AS comandos_executados,
            COUNT(DISTINCT executed_command) AS comandos_distintos
        FROM read_parquet('{PODS_PARQUET}')
    """).fetchone()

    t_cowrie = Table(title="Atividade Pós-Acesso no Cowrie (Pods)")
    t_cowrie.add_column("Sessões Totais", style="cyan", justify="right")
    t_cowrie.add_column("Comandos Executados", style="red", justify="right")
    t_cowrie.add_column("Comandos Distintos", style="yellow", justify="right")
    t_cowrie.add_row(f"{res_cowrie[0]:,}", f"{res_cowrie[1]:,}", f"{res_cowrie[2]:,}")
    console.print(t_cowrie)


def main():
    setup()
    con = duckdb.connect()
    con.execute("PRAGMA threads=8;")
    con.execute("PRAGMA preserve_insertion_order=false;")
    
    extrair_pods_ssh(con)
    extrair_proxy_ssh(con)
    exibir_estatisticas(con)
    
    console.print("\n[bold green]Pipeline concluído com sucesso![/bold green]\n")


if __name__ == "__main__":
    main()
