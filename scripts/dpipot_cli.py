#!/usr/bin/env python3
"""
Interface de Linha de Comando (CLI) para DPIpot-Analytics
Permite listar, converter por dia e consultar logs do DPIpot via terminal (headless).
"""

import argparse
import sys
from pathlib import Path

# Garantir raiz do projeto no PYTHONPATH
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from rich.console import Console
from rich.table import Table

from scripts.dpipot_core import (
    DPIPOT_TYPES,
    convert_csv_to_parquet,
    find_parquets_in_date_range,
    load_schema_config,
    scan_dpipot_logs,
)
import duckdb

console = Console()


def cmd_list(args):
    files = scan_dpipot_logs()
    table = Table(title="📦 Logs do DPIpot Encontrados (logs/ ➔ data/)")
    table.add_column("Tipo", style="cyan", no_wrap=True)
    table.add_column("Data", style="yellow")
    table.add_column("CSV", style="dim")
    table.add_column("Tamanho CSV", justify="right")
    table.add_column("Status Parquet", style="bold")
    table.add_column("Tamanho Parquet", justify="right")
    table.add_column("Taxa Comp.", justify="right")

    for f in files:
        if args.type and f.log_type != args.type:
            continue
        status = "[green]✓ Convertido[/green]" if f.is_converted else "[yellow]⏳ Pendente[/yellow]"
        p_size = f"{f.parquet_size_mb:.2f} MB" if f.is_converted else "-"
        ratio = f"{f.compression_ratio:.1f}x" if f.is_converted and f.compression_ratio > 0 else "-"
        csv_size = f"{f.csv_size_mb:.1f} MB" if f.csv_size_mb < 1024 else f"{f.csv_size_gb:.2f} GB"
        table.add_row(f.log_type.upper(), f.date_iso, f.csv_name, csv_size, status, p_size, ratio)

    console.print(table)


def cmd_convert(args):
    files = scan_dpipot_logs()
    to_convert = []

    for f in files:
        if args.type and f.log_type != args.type:
            continue
        if args.date and f.date_iso != args.date and f.raw_date_str != args.date:
            continue
        if args.pending_only and f.is_converted:
            continue
        to_convert.append(f)

    if not to_convert:
        console.print("[yellow]Nenhum arquivo encontrado para conversão com os filtros fornecidos.[/yellow]")
        return

    console.print(f"[bold cyan]Iniciando conversão de {len(to_convert)} arquivo(s)...[/bold cyan]")
    con = duckdb.connect()
    for idx, item in enumerate(to_convert):
        console.print(f"\n[{idx+1}/{len(to_convert)}] Convertendo {item.csv_name} ({item.csv_size_mb:.1f} MB)...")
        res = convert_csv_to_parquet(item.csv_path, item.parquet_path, con=con)
        console.print(f"  [green]✓ Concluído em {res['elapsed_sec']:.2f}s![/green]")
        console.print(f"  • Linhas: {res['row_count']:,} | Colunas: {res['col_count']}")
        console.print(f"  • Parquet: {res['parquet_size_mb']:.2f} MB (Compressão: ~{res['ratio']:.1f}x)")


def cmd_query(args):
    files, msg = find_parquets_in_date_range(args.type, args.start, args.end)
    if not files:
        console.print(f"[red]{msg}[/red]")
        return

    console.print(f"[green]{msg}[/green]")
    file_paths = [str(f.resolve()) for f in files]
    paths_str = ", ".join([f"'{p}'" for p in file_paths])

    con = duckdb.connect()
    con.execute(f"CREATE OR REPLACE VIEW logs AS SELECT * FROM read_parquet([{paths_str}], union_by_name=true);")
    con.execute("CREATE OR REPLACE VIEW dpipot AS SELECT * FROM logs;")

    sql = args.sql or "SELECT * FROM logs LIMIT 20;"
    console.print(f"[bold]Executando:[/bold] [cyan]{sql}[/cyan]\n")

    rel = con.sql(sql)
    if rel:
        rows = rel.limit(args.limit).fetchall()
        cols = rel.columns
        table = Table(title=f"Resultado ({len(rows)} linhas)")
        for c in cols:
            table.add_column(c)
        for r in rows:
            table.add_row(*[str(val) if val is not None else "[dim]NULL[/dim]" for val in r])
        console.print(table)


def cmd_schema(args):
    cfg = load_schema_config()
    target_type = args.type or "classifier"
    if target_type not in cfg:
        console.print(f"[red]Tipo '{target_type}' não encontrado no TOML.[/red]")
        return

    data = cfg[target_type]
    table = Table(title=f"📋 Esquema: {data.get('label', target_type)} ({len(data.get('columns', []))} colunas)")
    table.add_column("#", justify="right")
    table.add_column("Coluna", style="cyan")
    table.add_column("Tipo", style="yellow")
    table.add_column("Exemplo Real", style="dim")
    table.add_column("Descrição")

    filter_term = (args.filter or "").lower()
    for idx, col in enumerate(data.get("columns", [])):
        name = col.get("name", "")
        desc = col.get("description", "")
        if filter_term and filter_term not in name.lower() and filter_term not in desc.lower():
            continue
        table.add_row(str(idx + 1), name, col.get("type", ""), col.get("example", "")[:40], desc)

    console.print(table)


def main():
    parser = argparse.ArgumentParser(description="CLI DPIpot-Analytics")
    subparsers = parser.add_subparsers(dest="command")

    # list
    p_list = subparsers.add_parser("list", help="Listar logs e status por dia")
    p_list.add_argument("--type", choices=DPIPOT_TYPES, help="Filtrar por tipo")

    # convert
    p_conv = subparsers.add_parser("convert", help="Converter logs CSV em Parquet")
    p_conv.add_argument("--type", choices=DPIPOT_TYPES, help="Tipo do log")
    p_conv.add_argument("--date", help="Data específica (ex: 2026-07-27 ou 2026.07.27)")
    p_conv.add_argument("--pending-only", action="store_true", help="Converter apenas arquivos não convertidos")

    # query
    p_query = subparsers.add_parser("query", help="Executar consulta com intervalo de datas")
    p_query.add_argument("--type", choices=DPIPOT_TYPES, required=True, help="Tipo de log")
    p_query.add_argument("--start", required=True, help="Data inicial (AAAA-MM-DD)")
    p_query.add_argument("--end", required=True, help="Data final (AAAA-MM-DD)")
    p_query.add_argument("--sql", help="Comando SQL (tabela ativa: logs)")
    p_query.add_argument("--limit", type=int, default=50, help="Limite de linhas")

    # schema
    p_sch = subparsers.add_parser("schema", help="Exibir esquema TOML de colunas")
    p_sch.add_argument("--type", choices=DPIPOT_TYPES, default="classifier", help="Tipo de log")
    p_sch.add_argument("--filter", help="Filtrar por coluna ou descrição")

    args = parser.parse_args()
    if args.command == "list":
        cmd_list(args)
    elif args.command == "convert":
        cmd_convert(args)
    elif args.command == "query":
        cmd_query(args)
    elif args.command == "schema":
        cmd_schema(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
