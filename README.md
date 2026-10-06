# dpipot-analytics(1) — Specialized DPIpot Log Ingestion & Analytics Engine

```
       ___       _             _                             _       _   _
    __| _ \_ _  (_)_ __  ___ _| |_      __ _ _ _  __ _ | |_  _ __| |_(_)__ ___
   / _` |  _/ | | | '_ \/ _ \_  __|    / _` | ' \/ _` || | || (_-<  _| / _(_-<
   \__,_|_| |_| |_| .__/\___/ |_|      \__,_|_||_\__,_||_|\_, /__/\__|_\__/__/
                  |_|                                     |__/
```

> Out-of-core columnar transformation and temporal query engine for DPIpot-NG telemetry.

---

## SYNOPSIS

```bash
# Terminal User Interface (interactive)
python tui.py
python scripts/tui.py

# Headless command-line interface
python scripts/dpipot_cli.py list
python scripts/dpipot_cli.py query --type proxy --start 2026-07-27 --end 2026-07-28 --sql "SELECT * FROM logs LIMIT 20;"
python scripts/dpipot_cli.py schema --type classifier --filter "ndpi"
python scripts/dpipot_cli.py convert --type infra --date 2026-07-27

# One-liner ad-hoc query via DuckDB
python -c "import duckdb; duckdb.sql('SELECT COUNT(*) FROM read_parquet(\"data/dpipot-infra-2026.07.27.parquet\")').show()"
```

---

## DESCRIPTION

`dpipot-analytics` is a domain-specific, terminal-native telemetry engine designed for processing and querying high-volume honeypot logs from the **DPIpot-NG** architecture deployed on academic backbones.

The system replaces generic CSV handlers with a zero-copy, out-of-core columnar pipeline driven by **DuckDB** and **Apache Parquet (Zstandard)**. It specifically targets the four canonical DPIpot telemetry profiles:

1. **`classifier`** — Edge nDPI deep packet inspection and network traffic classification.
2. **`infra`** — Kubernetes cluster operations, Filebeat harvesters, and container runtime telemetry.
3. **`pods`** — Interactive honeypot execution logs (Cowrie SSH/Telnet, Heralding, credentials, and shells).
4. **`proxy`** — Transparent MITM (TPROXY) network flows enriched with MaxMind GeoIP, ASN metadata, and TCP stack metrics.

---

## CORE ARCHITECTURE

```
+--------------------------------------------------------------------------+
| RAW LOG INGESTION (logs/dpipot-<type>-<YYYY.MM.DD>.csv)                 |
| Full-width raw CSV logs partitioned daily (~50-100 GB/day)              |
+--------------------------------------------------------------------------+
                                     |
                                     | [1] Streaming ZSTD Block Ingestion
                                     v
+--------------------------------------------------------------------------+
| VECTORIZED DUCKDB ENGINE                                                 |
| - 100% column preservation (no discarded telemetry fields)              |
| - Out-of-core disk spill execution below RAM limits                      |
| - Automatic row group optimization (100k tuples/block)                   |
+--------------------------------------------------------------------------+
                                     |
                                     | [2] Columnar Parquet Serialization
                                     v
+--------------------------------------------------------------------------+
| STORAGE TIER (data/dpipot-<type>-<YYYY.MM.DD>.parquet)                   |
| 1:1 filename equivalence (lossless ZSTD compression ~25x-60x)            |
+--------------------------------------------------------------------------+
                                     |
                                     | [3] Temporal Partition Union
                                     v
+--------------------------------------------------------------------------+
| TEMPORAL QUERY & ANALYTICS                                               |
| - Date-range window evaluation (e.g. 2026-07-01 -> 2026-07-31)          |
| - Dynamic unified view creation: read_parquet([...], union_by_name=true) |
| - Sub-second ANSI SQL execution over multi-gigabyte partitions           |
+--------------------------------------------------------------------------+
```

---

## LOG PROFILES

The engine enforces strict profiling based on the DPIpot-NG logging pipeline:

| Profile | Origin | Volume | Description |
| :--- | :--- | :--- | :--- |
| `classifier` | Network Edge (nDPI) | ~50 GB/day | Flow category IDs, L4/L7 protocol signatures, IP proto, TCP flags, packet lengths. |
| `infra` | Kubernetes / Filebeat | ~20 MB/day | DaemonSet metrics, container IDs, node health, harvester states, log levels. |
| `pods` | Cowrie / Heralding | ~90 GB/day | Session tokens, raw shell inputs (`CMD:`), authentication pairs, HASSH fingerprints. |
| `proxy` | TPROXY / AF_PACKET | ~20 GB/day | Attacker IPs, GeoIP country/city, ASN ownership, RTT, TCP window, TTL, payloads. |

---

## TEMPORAL QUERY ENGINE

Queries operate over immutable Parquet partitions bounded by temporal intervals. 

When a date range is supplied (e.g., `2026-07-27` to `2026-07-28`), the engine resolves matching parquet files in `data/`, binds them into an in-memory unified view `logs` (and alias `dpipot`), and executes vectorized SQL:

```sql
-- Example: Top adversary origins across a multi-day window
SELECT 
    COALESCE("src_geo.country_name", 'Unknown') AS country,
    "src_asn.organization_name" AS asn_org,
    COUNT(*) AS total_flows
FROM logs
WHERE honeypot LIKE '%cowrie%'
GROUP BY 1, 2
ORDER BY 3 DESC
LIMIT 20;
```

---

## TOML SCHEMA SPECIFICATION (`dpipot_types.toml`)

All column semantics, data types, and empirical examples are decoupled into `dpipot_types.toml`.

```toml
[proxy]
name = "proxy"
label = "Proxy MITM & Network Flows"
description = "Transparent MITM proxy telemetry with GeoIP/ASN enrichment."
total_columns = 89

[[proxy.columns]]
name = "src_ip"
type = "VARCHAR"
example = "193.34.212.238"
description = "Adversary source IP address observed at the edge socket"

[[proxy.columns]]
name = "duration_ms"
type = "DOUBLE"
example = "683.945299"
description = "Total flow duration in milliseconds"
```

The configuration is user-editable. The TUI dictionary viewer dynamically reloads changes without restarting via the `Reload TOML` trigger.

---

## KEYBINDINGS

| Keybinding | Context | Action |
| :--- | :--- | :--- |
| `F1` | Global | Switch to Ingestion & Parquet tab |
| `F2` | Global | Switch to Date-Range Query tab |
| `F3` | Global | Switch to TOML Schema Dictionary tab |
| `Ctrl + Enter` | SQL Editor | Execute SQL query |
| `Ctrl + R` | Global | Refresh disk partitions and reload TOML schema |
| `Ctrl + Q` | Global | Terminate application |
| `Tab` / `Shift + Tab` | Global | Cycle focus between UI regions |
| `Up` / `Down` | Table | Navigate records |

---

## CLI REFERENCE

Headless operations are available through `scripts/dpipot_cli.py`:

```bash
# List local dataset status
python scripts/dpipot_cli.py list

# Convert a specific daily partition
python scripts/dpipot_cli.py convert --type classifier --date 2026-07-27

# Convert all pending daily logs
python scripts/dpipot_cli.py convert --pending-only

# Execute analytical query over date range
python scripts/dpipot_cli.py query \
    --type proxy \
    --start 2026-07-27 \
    --end 2026-07-28 \
    --sql "SELECT dst_port, COUNT(*) FROM logs GROUP BY 1 ORDER BY 2 DESC LIMIT 10"

# Inspect schema dictionary
python scripts/dpipot_cli.py schema --type pods --filter "password"
```

---

## DIRECTORY STRUCTURE

```
.
|-- tui.py                      # TUI bootstrap entrypoint
|-- dpipot_types.toml           # Authoritative TOML schema dictionary
|-- requirements.txt            # System dependencies
|-- logs/                       # Daily raw CSV logs (dpipot-<type>-<date>.csv)
|-- data/                       # Columnar Parquet partitions (dpipot-<type>-<date>.parquet)
|-- docs/                       # Research documentation and figures
`-- scripts/
    |-- dpipot_core.py          # Vectorized ingestion, date-range partitioner, TOML parser
    |-- dpipot_cli.py           # Headless command-line utility
    |-- tui.py                  # Textual asynchronous terminal interface
    |-- extrair_ssh_parquet.py  # Specialized SSH extraction routine
    `-- analisar_resultados.py  # Plotting pipelines for academic reporting
```
