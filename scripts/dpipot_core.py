#!/usr/bin/env python3
"""
Módulo Central do DPIpot-Analytics:
- Gerenciamento dos tipos de logs: classifier, infra, pods, proxy
- Mapeamento de arquivos por dia (CSV na pasta logs/ e Parquet na pasta data/)
- Conversão streaming de CSV completo para Apache Parquet via DuckDB
- Consulta e seleção de Parquets por intervalo de datas
- Carregamento e leitura do dicionário de tipos TOML (dpipot_types.toml)
"""

import os
import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import tomllib

import duckdb

DPIPOT_TYPES = ["classifier", "infra", "pods", "proxy"]
DEFAULT_LOGS_DIR = "logs"
DEFAULT_DATA_DIR = "data"
DEFAULT_CONFIG_PATH = "dpipot_types.toml"

# Expressão regular para casar nomes como: dpipot-proxy-2026.07.27.csv ou dpipot-pods-2026-07-28.csv
FILENAME_PATTERN = re.compile(
    r"^dpipot-(classifier|infra|pods|proxy)[-_.](\d{4})[.-](\d{2})[.-](\d{2})\.(csv|parquet)$",
    re.IGNORECASE,
)


@dataclass
class LogFileInfo:
    log_type: str
    date_iso: str  # YYYY-MM-DD
    raw_date_str: str  # Original como no arquivo (ex: 2026.07.27)
    csv_name: str
    csv_path: Path
    csv_size_bytes: int
    parquet_name: str
    parquet_path: Path
    parquet_size_bytes: int
    is_converted: bool

    @property
    def csv_size_mb(self) -> float:
        return self.csv_size_bytes / (1024 * 1024)

    @property
    def csv_size_gb(self) -> float:
        return self.csv_size_bytes / (1024 * 1024 * 1024)

    @property
    def parquet_size_mb(self) -> float:
        return self.parquet_size_bytes / (1024 * 1024)

    @property
    def compression_ratio(self) -> float:
        if self.parquet_size_bytes > 0:
            return self.csv_size_bytes / self.parquet_size_bytes
        return 0.0


def parse_dpipot_filename(filename: str) -> Optional[Tuple[str, str, str]]:
    """
    Retorna (log_type, date_iso, raw_date_str) ou None se não casar o padrão.
    Exemplo: dpipot-proxy-2026.07.27.csv -> ('proxy', '2026-07-27', '2026.07.27')
    """
    match = FILENAME_PATTERN.match(filename)
    if not match:
        return None
    log_type = match.group(1).lower()
    year, month, day = match.group(2), match.group(3), match.group(4)
    date_iso = f"{year}-{month}-{day}"
    raw_date_str = f"{year}.{month}.{day}"
    return log_type, date_iso, raw_date_str


def parse_date_input(date_str: str) -> Optional[str]:
    """
    Normaliza entradas de data diversas para ISO YYYY-MM-DD.
    Aceita: YYYY-MM-DD, YYYY.MM.DD, DD/MM/YYYY, DD-MM-YYYY.
    """
    if not date_str:
        return None
    clean = date_str.strip()
    
    # Testar YYYY-MM-DD ou YYYY.MM.DD
    m1 = re.match(r"^(\d{4})[./-](\d{1,2})[./-](\d{1,2})$", clean)
    if m1:
        y, m, d = int(m1.group(1)), int(m1.group(2)), int(m1.group(3))
        return f"{y:04d}-{m:02d}-{d:02d}"

    # Testar DD/MM/YYYY ou DD-MM-YYYY
    m2 = re.match(r"^(\d{1,2})[./-](\d{1,2})[./-](\d{4})$", clean)
    if m2:
        d, m, y = int(m2.group(1)), int(m2.group(2)), int(m2.group(3))
        return f"{y:04d}-{m:02d}-{d:02d}"

    return None


def scan_dpipot_logs(
    logs_dir: str = DEFAULT_LOGS_DIR, data_dir: str = DEFAULT_DATA_DIR
) -> List[LogFileInfo]:
    """
    Varre a pasta de logs buscando arquivos dos 4 tipos do DPIpot,
    verificando a existência do respectivo Parquet na pasta data.
    """
    logs_p = Path(logs_dir)
    data_p = Path(data_dir)
    data_p.mkdir(parents=True, exist_ok=True)

    items: List[LogFileInfo] = []
    if not logs_p.exists():
        return items

    for f in logs_p.glob("*.csv"):
        parsed = parse_dpipot_filename(f.name)
        if not parsed:
            continue
        log_type, date_iso, raw_date = parsed

        # O arquivo parquet tem o mesmo nome do CSV com extensão .parquet
        parquet_name = f"{f.stem}.parquet"
        parquet_path = data_p / parquet_name

        csv_size = f.stat().st_size
        p_size = parquet_path.stat().st_size if parquet_path.exists() else 0
        is_conv = parquet_path.exists() and p_size > 0

        items.append(
            LogFileInfo(
                log_type=log_type,
                date_iso=date_iso,
                raw_date_str=raw_date,
                csv_name=f.name,
                csv_path=f,
                csv_size_bytes=csv_size,
                parquet_name=parquet_name,
                parquet_path=parquet_path,
                parquet_size_bytes=p_size,
                is_converted=is_conv,
            )
        )

    # Ordenar por data (decrescente) e tipo
    items.sort(key=lambda x: (x.date_iso, x.log_type), reverse=True)
    return items


def convert_csv_to_parquet(
    csv_path: Path, parquet_path: Path, con: Optional[duckdb.DuckDBPyConnection] = None
) -> dict:
    """
    Converte um arquivo CSV completo do DPIpot para Parquet com compressão ZSTD.
    Preserva 100% das colunas e dados sem filtros.
    """
    parquet_path.parent.mkdir(parents=True, exist_ok=True)
    db_con = con or duckdb.connect()

    t0 = time.time()
    query = f"""
    COPY (
        SELECT * FROM read_csv('{csv_path}', ignore_errors=true)
    ) TO '{parquet_path}' (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000);
    """
    db_con.execute(query)
    elapsed = time.time() - t0

    parquet_size = parquet_path.stat().st_size
    csv_size = csv_path.stat().st_size
    row_count = db_con.execute(f"SELECT COUNT(*) FROM read_parquet('{parquet_path}')").fetchone()[0]
    col_count = len(db_con.execute(f"DESCRIBE SELECT * FROM read_parquet('{parquet_path}')").fetchall())

    return {
        "csv_path": str(csv_path),
        "parquet_path": str(parquet_path),
        "elapsed_sec": elapsed,
        "row_count": row_count,
        "col_count": col_count,
        "csv_size_mb": csv_size / (1024 * 1024),
        "parquet_size_mb": parquet_size / (1024 * 1024),
        "ratio": (csv_size / parquet_size) if parquet_size > 0 else 0,
    }


def find_parquets_in_date_range(
    log_type: str,
    start_date_str: str,
    end_date_str: str,
    data_dir: str = DEFAULT_DATA_DIR,
) -> Tuple[List[Path], str]:
    """
    Localiza os arquivos Parquet do tipo especificado contidos no intervalo de datas [start_date, end_date].
    Retorna (lista_de_caminhos, mensagem_status).
    """
    start_iso = parse_date_input(start_date_str)
    end_iso = parse_date_input(end_date_str)

    if not start_iso or not end_iso:
        return [], f"Datas inválidas: início '{start_date_str}', fim '{end_date_str}'"

    if start_iso > end_iso:
        start_iso, end_iso = end_iso, start_iso

    data_p = Path(data_dir)
    if not data_p.exists():
        return [], f"Diretório de dados '{data_dir}' não existe."

    matched: List[Tuple[str, Path]] = []
    for f in data_p.glob("*.parquet"):
        parsed = parse_dpipot_filename(f.name)
        if not parsed:
            continue
        f_type, f_date_iso, _ = parsed
        if f_type == log_type.lower() and (start_iso <= f_date_iso <= end_iso):
            matched.append((f_date_iso, f))

    matched.sort(key=lambda x: x[0])
    files = [m[1] for m in matched]

    msg = f"Encontrado(s) {len(files)} arquivo(s) Parquet para '{log_type}' de {start_iso} a {end_iso}."
    return files, msg


def load_schema_config(config_path: str = DEFAULT_CONFIG_PATH) -> dict:
    """
    Carrega o arquivo TOML com as definições de colunas e metadados dos 4 tipos de logs do DPIpot.
    """
    p = Path(config_path)
    if not p.exists():
        return {}
    with open(p, "rb") as f:
        return tomllib.load(f)


def get_available_date_range(
    logs_dir: str = DEFAULT_LOGS_DIR, data_dir: str = DEFAULT_DATA_DIR
) -> Tuple[Optional[str], Optional[str]]:
    """
    Retorna a menor e maior data encontrada nos arquivos do DPIpot (ISO YYYY-MM-DD).
    """
    dates: set[str] = set()
    for d in (Path(logs_dir), Path(data_dir)):
        if d.exists():
            for f in list(d.glob("*.csv")) + list(d.glob("*.parquet")):
                parsed = parse_dpipot_filename(f.name)
                if parsed:
                    dates.add(parsed[1])
    if not dates:
        return None, None
    sorted_dates = sorted(list(dates))
    return sorted_dates[0], sorted_dates[-1]
