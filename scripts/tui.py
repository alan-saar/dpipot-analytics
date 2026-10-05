#!/usr/bin/env python3
"""
DPIpot-Analytics: TUI Específica para Logs do DPIpot-NG
Processa exclusivamente os 4 tipos de logs: classifier, infra, pods, proxy.
- Conversão de CSV completo por dia em logs/ para Parquet completo em data/
- Consultas analíticas DuckDB com filtro por intervalo de datas (ex: 2026-07-01 a 2026-07-31)
- Dicionário interativo de colunas sincronizado com dpipot_types.toml
"""

import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

# Garantir raiz do projeto no PYTHONPATH
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import duckdb
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ProgressBar,
    RichLog,
    Rule,
    Select,
    TabbedContent,
    TabPane,
    TextArea,
)

from scripts.dpipot_core import (
    DPIPOT_TYPES,
    LogFileInfo,
    convert_csv_to_parquet,
    find_parquets_in_date_range,
    get_available_date_range,
    load_schema_config,
    parse_date_input,
    scan_dpipot_logs,
)


class DpipotAnalyticsApp(App):
    """Aplicação TUI oficial para análise de logs do DPIpot."""

    CSS = """
    Screen {
        background: $surface;
    }

    .section-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }

    .section-subtitle {
        color: $text-muted;
        margin-bottom: 1;
    }

    .form-group {
        margin-bottom: 1;
    }

    .action-bar {
        margin-top: 1;
        margin-bottom: 1;
        height: auto;
    }

    .action-bar Button {
        margin-right: 1;
    }

    /* Aba 1: Conversor */
    #convert_left {
        width: 65%;
        border-right: solid $primary;
        padding: 1;
    }

    #convert_right {
        width: 35%;
        padding: 1;
    }

    #table_logs {
        height: 1fr;
        border: solid $primary;
        margin-top: 1;
    }

    #log_exec {
        height: 1fr;
        border: solid $accent;
        background: $surface-darken-1;
        margin-top: 1;
    }

    /* Aba 2: Consultas */
    #query_sidebar {
        width: 38;
        border-right: solid $primary;
        padding: 1;
    }

    #query_sidebar Button {
        width: 100%;
        margin-bottom: 1;
    }

    #query_main {
        padding: 1;
    }

    #sql_editor {
        height: 9;
        border: solid $accent;
        margin-bottom: 1;
    }

    #table_results {
        height: 1fr;
        border: solid $primary;
    }

    #lbl_query_status {
        color: $success;
        padding: 0 1;
        text-style: bold;
    }

    #lbl_files_loaded {
        color: $accent;
        margin-bottom: 1;
    }

    /* Aba 3: Dicionário */
    #dict_main {
        padding: 1;
    }

    #table_dict {
        height: 1fr;
        border: solid $primary;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit", "Sair", priority=True),
        Binding("ctrl+r", "refresh_all", "Atualizar", priority=True),
        Binding("f1", "tab_convert", "Aba Ingestão/Parquet"),
        Binding("f2", "tab_query", "Aba Consultas"),
        Binding("f3", "tab_dict", "Aba Dicionário TOML"),
    ]

    def __init__(self):
        super().__init__()
        self.con = duckdb.connect()
        self.log_files: List[LogFileInfo] = []
        self.log_files_map: Dict[str, LogFileInfo] = {}
        self.selected_log_file: Optional[LogFileInfo] = None
        self.schema_config: dict = {}
        
        # Estado de consulta por período
        self.current_query_type: str = "proxy"
        self.current_loaded_parquets: List[Path] = []
        self.current_start_date: str = ""
        self.current_end_date: str = ""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(id="tabs"):
            # -------------------------------------------------------------
            # ABA 1: Ingestão de Logs DPIpot (CSV ➔ Parquet Completo)
            # -------------------------------------------------------------
            with TabPane("🔄 Ingestão de Logs (CSV ➔ Parquet)", id="tab_pane_convert"):
                with Horizontal():
                    with Vertical(id="convert_left"):
                        yield Label("📁 [bold]Logs DPIpot por Dia (logs/ ➔ data/)[/bold]", classes="section-title")
                        yield Label("Monitora os 4 tipos: classifier, infra, pods e proxy. Selecione uma linha para converter.", classes="section-subtitle")
                        
                        with Horizontal(classes="action-bar"):
                            yield Select(
                                [("Todos os Tipos", "all")] + [(t.upper(), t) for t in DPIPOT_TYPES],
                                id="sel_filter_type",
                                value="all",
                                prompt="Filtrar tipo..."
                            )
                            yield Button("🚀 Converter Selecionado", variant="primary", id="btn_convert_selected")
                            yield Button("⚡ Converter Todos Pendentes", variant="warning", id="btn_convert_pending")
                            yield Button("🔄 Atualizar", variant="default", id="btn_refresh_files")

                        yield Label("Selecionado: [nenhum]", id="lbl_selected_csv", classes="section-subtitle")
                        yield DataTable(id="table_logs", zebra_stripes=True, cursor_type="row")

                    with Vertical(id="convert_right"):
                        yield Label("📊 [bold]Painel de Execução & Conversão[/bold]", classes="section-title")
                        yield Label("Conversão completa DuckDB com compressão colunar ZSTD.", classes="section-subtitle")
                        
                        yield ProgressBar(id="convert_progress", show_eta=False, total=100)
                        yield Label("Registro de Execução:")
                        yield RichLog(id="log_exec", wrap=True, highlight=True, markup=True)

            # -------------------------------------------------------------
            # ABA 2: Consultas Analíticas com Filtro por Intervalo de Datas
            # -------------------------------------------------------------
            with TabPane("🔍 Consultas por Intervalo de Datas", id="tab_pane_query"):
                with Horizontal():
                    with VerticalScroll(id="query_sidebar"):
                        yield Label("🎯 [bold]Configuração do Período[/bold]:", classes="section-title")
                        
                        yield Label("Tipo de Log:")
                        yield Select(
                            [(t.upper(), t) for t in DPIPOT_TYPES],
                            id="sel_query_type",
                            value="proxy"
                        )

                        yield Label("Data Inicial (AAAA-MM-DD):")
                        yield Input(value="2026-07-27", id="inp_date_start", placeholder="Ex: 2026-07-01")

                        yield Label("Data Final (AAAA-MM-DD):")
                        yield Input(value="2026-07-28", id="inp_date_end", placeholder="Ex: 2026-07-31")

                        yield Button("📅 Carregar Período", variant="primary", id="btn_load_period")
                        
                        yield Rule()
                        yield Label("⚡ [bold]Consultas Rápidas[/bold]:")
                        yield Button("🔍 Schema (DESCRIBE)", id="btn_q_describe")
                        yield Button("🔢 Contar Linhas (COUNT)", id="btn_q_count")
                        yield Button("👁️ Amostra (LIMIT 50)", id="btn_q_sample")
                        yield Button("📈 Resumo (SUMMARIZE)", id="btn_q_summarize")
                        
                        # Botões dinâmicos específicos por tipo
                        yield Button("⚡ Consulta Contextual 1", id="btn_q_custom_1")
                        yield Button("⚡ Consulta Contextual 2", id="btn_q_custom_2")
                        yield Button("⚡ Consulta Contextual 3", id="btn_q_custom_3")

                    with Vertical(id="query_main"):
                        yield Label("📊 [bold]Arquivos Carregados no Período[/bold]:", classes="section-title")
                        yield Label("Nenhum período carregado.", id="lbl_files_loaded")

                        yield Label("📝 [bold]Editor SQL (Tabela ativa: [cyan]logs[/cyan] ou [cyan]dpipot[/cyan])[/bold]:")
                        yield TextArea("SELECT * FROM logs LIMIT 50;", language="sql", id="sql_editor")
                        
                        with Horizontal(classes="action-bar"):
                            yield Button("▶️ Executar SQL", variant="success", id="btn_run_sql")
                            yield Label("Aguardando execução...", id="lbl_query_status")

                        yield DataTable(id="table_results", zebra_stripes=True, cursor_type="cell")

            # -------------------------------------------------------------
            # ABA 3: Dicionário de Colunas e Esquema TOML
            # -------------------------------------------------------------
            with TabPane("📋 Dicionário de Colunas (Config TOML)", id="tab_pane_dict"):
                with Vertical(id="dict_main"):
                    with Horizontal(classes="action-bar"):
                        yield Label("Tipo de Log:")
                        yield Select(
                            [(t.upper(), t) for t in DPIPOT_TYPES],
                            id="sel_dict_type",
                            value="classifier"
                        )
                        yield Input(placeholder="🔍 Filtrar coluna ou descrição...", id="inp_filter_dict")
                        yield Button("🔄 Recarregar TOML", variant="default", id="btn_reload_toml")

                    yield Label("", id="lbl_dict_header", classes="section-subtitle")
                    yield DataTable(id="table_dict", zebra_stripes=True, cursor_type="row")

        yield Footer()

    def on_mount(self) -> None:
        self.title = "DPIpot-Analytics | Analisador Especializado de Logs"
        self.sub_title = "DPIpot-NG • DuckDB Colunar • TOML Schemas"
        
        # 1. Carregar Configuração TOML
        self._load_toml_schema()

        # 2. Configurar tabela de logs (Aba 1)
        self._init_logs_table()
        self._reload_logs_list()

        # 3. Configurar intervalo inicial disponível
        min_d, max_d = get_available_date_range()
        if min_d and max_d:
            self.query_one("#inp_date_start", Input).value = min_d
            self.query_one("#inp_date_end", Input).value = max_d

        # 4. Configurar tabela de resultados (Aba 2)
        # Iniciar período inicial padrão
        self._load_active_period()

        # 5. Configurar tabela de dicionário (Aba 3)
        self._init_dict_table()
        self._refresh_dict_view()

        log_box = self.query_one("#log_exec", RichLog)
        log_box.write("[bold green]DPIpot-Analytics iniciado com sucesso![/bold green]")
        log_box.write("Os 4 tipos de logs do DPIpot estão disponíveis: [cyan]classifier, infra, pods, proxy[/cyan].")

    # -------------------------------------------------------------------------
    # Ações Globais e Atalhos
    # -------------------------------------------------------------------------
    def action_tab_convert(self) -> None:
        self.query_one("#tabs", TabbedContent).active = "tab_pane_convert"

    def action_tab_query(self) -> None:
        self.query_one("#tabs", TabbedContent).active = "tab_pane_query"

    def action_tab_dict(self) -> None:
        self.query_one("#tabs", TabbedContent).active = "tab_pane_dict"

    def action_refresh_all(self) -> None:
        self._reload_logs_list()
        self._load_toml_schema()
        self._refresh_dict_view()
        self.notify("Dados e esquemas atualizados!")

    # -------------------------------------------------------------------------
    # ABA 1: Ingestão de Logs (CSV ➔ Parquet)
    # -------------------------------------------------------------------------
    def _init_logs_table(self) -> None:
        tbl = self.query_one("#table_logs", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns("Tipo", "Data", "Arquivo CSV", "Tamanho CSV", "Status Parquet", "Tamanho Parquet", "Compressão")

    def _update_selected_log_label(self, item: Optional[LogFileInfo]) -> None:
        try:
            lbl = self.query_one("#lbl_selected_csv", Label)
            if item:
                size_str = f"{item.csv_size_mb:.1f} MB" if item.csv_size_mb < 1024 else f"{item.csv_size_gb:.2f} GB"
                status = "[green]✓ Convertido[/green]" if item.is_converted else "[yellow]⏳ Pendente[/yellow]"
                lbl.update(f"Selecionado para conversão: [bold cyan]{item.csv_name}[/bold cyan] ({size_str}) — {status}")
            else:
                lbl.update("Selecionado para conversão: [dim]Nenhum arquivo selecionado[/dim]")
        except Exception:
            pass

    def _get_currently_selected_log_file(self) -> Optional[LogFileInfo]:
        try:
            tbl = self.query_one("#table_logs", DataTable)
            if tbl.cursor_row is not None and 0 <= tbl.cursor_row < len(tbl.ordered_rows):
                row = tbl.ordered_rows[tbl.cursor_row]
                key_val = row.key.value
                if key_val in self.log_files_map:
                    return self.log_files_map[key_val]
        except Exception:
            pass
        return self.selected_log_file

    def _reload_logs_list(self) -> None:
        self.log_files = scan_dpipot_logs()
        self.log_files_map = {f.csv_name: f for f in self.log_files}
        tbl = self.query_one("#table_logs", DataTable)
        tbl.clear()

        filter_type = self.query_one("#sel_filter_type", Select).value
        filter_type = str(filter_type) if filter_type != Select.BLANK else "all"

        for item in self.log_files:
            if filter_type != "all" and item.log_type != filter_type:
                continue

            status_str = f"[bold green]✓ Convertido[/bold green]" if item.is_converted else "[yellow]⏳ Pendente[/yellow]"
            parquet_size_str = f"{item.parquet_size_mb:.2f} MB" if item.is_converted else "-"
            ratio_str = f"{item.compression_ratio:.1f}x" if item.is_converted and item.compression_ratio > 0 else "-"

            tbl.add_row(
                item.log_type.upper(),
                item.date_iso,
                item.csv_name,
                f"{item.csv_size_mb:.1f} MB" if item.csv_size_mb < 1024 else f"{item.csv_size_gb:.2f} GB",
                status_str,
                parquet_size_str,
                ratio_str,
                key=item.csv_name,
            )

        current = self._get_currently_selected_log_file()
        if not current and self.log_files:
            current = self.log_files[0]
        self.selected_log_file = current
        self._update_selected_log_label(current)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "table_logs" and event.row_key:
            key_val = event.row_key.value
            if key_val in self.log_files_map:
                self.selected_log_file = self.log_files_map[key_val]
                self._update_selected_log_label(self.selected_log_file)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "table_logs" and event.row_key:
            key_val = event.row_key.value
            if key_val in self.log_files_map:
                self.selected_log_file = self.log_files_map[key_val]
                self._update_selected_log_label(self.selected_log_file)

    def _convert_single_item(self, item: LogFileInfo) -> None:
        self._run_conversion_worker([item])

    def _convert_pending_items(self) -> None:
        pending = [f for f in self.log_files if not f.is_converted]
        if not pending:
            self.notify("Não há arquivos pendentes para conversão!", severity="information")
            return
        self._run_conversion_worker(pending)

    @work(thread=True)
    def _run_conversion_worker(self, items_to_convert: List[LogFileInfo]) -> None:
        log_box = self.query_one("#log_exec", RichLog)
        progress = self.query_one("#convert_progress", ProgressBar)
        
        total = len(items_to_convert)
        self.app.call_from_thread(progress.update, progress=0)

        self.app.call_from_thread(
            log_box.write,
            f"\n[bold cyan]=== Início da Ingestão de {total} arquivo(s) DPIpot ===[/bold cyan]"
        )

        db_con = duckdb.connect()

        for idx, item in enumerate(items_to_convert):
            self.app.call_from_thread(
                log_box.write,
                f"[{idx+1}/{total}] Convertendo [cyan]{item.csv_name}[/cyan] ({item.csv_size_mb:.1f} MB)..."
            )

            try:
                res = convert_csv_to_parquet(item.csv_path, item.parquet_path, con=db_con)
                self.app.call_from_thread(
                    log_box.write,
                    f"  [green]✓ Concluído em {res['elapsed_sec']:.2f}s![/green]\n"
                    f"    • Linhas: [yellow]{res['row_count']:,}[/yellow] | Colunas: [yellow]{res['col_count']}[/yellow]\n"
                    f"    • Parquet: [green]{res['parquet_size_mb']:.2f} MB[/green] (Compressão: ~{res['ratio']:.1f}x)\n"
                    f"    • Destino: [dim]{item.parquet_path}[/dim]"
                )
            except Exception as err:
                self.app.call_from_thread(
                    log_box.write,
                    f"  [bold red]❌ Erro ao converter {item.csv_name}:[/bold red] {err}"
                )

            pct = int(((idx + 1) / total) * 100)
            self.app.call_from_thread(progress.update, progress=pct)

        self.app.call_from_thread(log_box.write, "[bold green]🎉 Processamento concluído![/bold green]\n")
        self.app.call_from_thread(self._reload_logs_list)

    # -------------------------------------------------------------------------
    # ABA 2: Consultas Analíticas DuckDB por Intervalo de Datas
    # -------------------------------------------------------------------------
    def _load_active_period(self) -> None:
        sel_type = self.query_one("#sel_query_type", Select).value
        log_type = str(sel_type) if sel_type != Select.BLANK else "proxy"
        self.current_query_type = log_type

        start_date = self.query_one("#inp_date_start", Input).value.strip()
        end_date = self.query_one("#inp_date_end", Input).value.strip()

        lbl_loaded = self.query_one("#lbl_files_loaded", Label)
        lbl_status = self.query_one("#lbl_query_status", Label)

        files, msg = find_parquets_in_date_range(log_type, start_date, end_date)
        self.current_loaded_parquets = files

        if not files:
            lbl_loaded.update(f"[red]{msg}[/red] Converta os CSVs na Aba 1 se ainda não o fez.")
            lbl_status.update("[yellow]Nenhum arquivo Parquet no período selecionado.[/yellow]")
            return

        # Criar ou substituir VIEW logs e VIEW dpipot no DuckDB
        file_paths = [str(f.resolve()) for f in files]
        paths_str = ", ".join([f"'{p}'" for p in file_paths])
        view_query = f"""
        CREATE OR REPLACE VIEW logs AS 
        SELECT * FROM read_parquet([{paths_str}], union_by_name=true);
        CREATE OR REPLACE VIEW dpipot AS SELECT * FROM logs;
        """
        try:
            self.con.execute(view_query)
            count = self.con.execute("SELECT COUNT(*) FROM logs;").fetchone()[0]
            total_size_mb = sum(f.stat().st_size for f in files) / (1024 * 1024)

            file_names = ", ".join([f.name for f in files])
            lbl_loaded.update(
                f"[bold green]✓ {len(files)} arquivo(s) carregado(s)[/bold green]: {file_names}\n"
                f"Total de registros: [yellow]{count:,}[/yellow] | Tamanho em disco: [yellow]{total_size_mb:.2f} MB[/yellow]"
            )
            lbl_status.update(f"Dataset pronto: [cyan]{log_type.upper()}[/cyan] ({len(files)} arquivos, {count:,} linhas).")
            self.notify(f"Período carregado: {len(files)} arquivos do tipo {log_type.upper()}")
        except Exception as e:
            lbl_loaded.update(f"[red]Erro ao carregar arquivos Parquet:[/red] {e}")

        # Atualizar os botões contextuais por tipo
        self._update_quick_query_buttons(log_type)

    def _update_quick_query_buttons(self, log_type: str) -> None:
        btn1 = self.query_one("#btn_q_custom_1", Button)
        btn2 = self.query_one("#btn_q_custom_2", Button)
        btn3 = self.query_one("#btn_q_custom_3", Button)

        if log_type == "proxy":
            btn1.label = "🌍 Top Países (src_country)"
            btn2.label = "🚪 Top Portas Alvo (dst_port)"
            btn3.label = "🛡️ Protocolos nDPI (ndpi_proto)"
        elif log_type == "pods":
            btn1.label = "👤 Top Usuários (username)"
            btn2.label = "🔑 Top Senhas (password)"
            btn3.label = "⚡ Comandos (message)"
        elif log_type == "classifier":
            btn1.label = "🏷️ Categorias nDPI (category)"
            btn2.label = "🚩 Flags TCP (tcp_flags)"
            btn3.label = "🎯 Protocolos nDPI (ndpi_proto)"
        elif log_type == "infra":
            btn1.label = "📦 Logs por Pod (kubernetes)"
            btn2.label = "⚠️ Logs por Nível (log.level)"
            btn3.label = "⏱️ Hostnames dos Nós"

    def _execute_sql_query(self) -> None:
        if not self.current_loaded_parquets:
            self.notify("Carregue um período com arquivos Parquet primeiro!", severity="warning")
            return

        sql = self.query_one("#sql_editor", TextArea).text.strip()
        if not sql:
            return

        table = self.query_one("#table_results", DataTable)
        lbl_status = self.query_one("#lbl_query_status", Label)

        lbl_status.update("Executando consulta SQL...")
        table.clear(columns=True)

        t0 = time.time()
        try:
            rel = self.con.sql(sql)
            if rel is None:
                lbl_status.update("[green]Comando executado com sucesso.[/green]")
                return

            columns = rel.columns
            MAX_ROWS = 500
            rows = rel.limit(MAX_ROWS).fetchall()
            elapsed = time.time() - t0

            for col in columns:
                table.add_column(col)

            for row in rows:
                formatted_row = [str(val) if val is not None else "[dim]NULL[/dim]" for val in row]
                table.add_row(*formatted_row)

            msg = f"[green]Sucesso[/green]: {len(rows)} linhas em {elapsed:.3f}s"
            if len(rows) == MAX_ROWS:
                msg += f" [yellow](limitado a {MAX_ROWS} linhas na exibição)[/yellow]"
            lbl_status.update(msg)

        except Exception as e:
            elapsed = time.time() - t0
            lbl_status.update(f"[red]Erro SQL ({elapsed:.3f}s):[/red] {e}")

    def _set_and_run_sql(self, sql: str) -> None:
        editor = self.query_one("#sql_editor", TextArea)
        editor.text = sql
        self._execute_sql_query()

    # -------------------------------------------------------------------------
    # ABA 3: Dicionário de Colunas e Esquema TOML
    # -------------------------------------------------------------------------
    def _init_dict_table(self) -> None:
        tbl = self.query_one("#table_dict", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns("#", "Nome da Coluna", "Tipo SQL", "Exemplo Real", "Descrição do Significado")

    def _load_toml_schema(self) -> None:
        try:
            self.schema_config = load_schema_config()
        except Exception as err:
            self.notify(f"Erro ao ler dpipot_types.toml: {err}", severity="error")

    def _refresh_dict_view(self) -> None:
        tbl = self.query_one("#table_dict", DataTable)
        tbl.clear()

        sel_type = self.query_one("#sel_dict_type", Select).value
        log_type = str(sel_type) if sel_type != Select.BLANK else "classifier"

        type_cfg = self.schema_config.get(log_type, {})
        columns = type_cfg.get("columns", [])

        # Filtro de busca de colunas
        filter_text = self.query_one("#inp_filter_dict", Input).value.strip().lower()

        filtered_cols = []
        for c in columns:
            name = c.get("name", "")
            desc = c.get("description", "")
            if filter_text:
                if filter_text not in name.lower() and filter_text not in desc.lower():
                    continue
            filtered_cols.append(c)

        lbl_header = self.query_one("#lbl_dict_header", Label)
        label_title = type_cfg.get("label", log_type.upper())
        type_desc = type_cfg.get("description", "")
        lbl_header.update(
            f"[bold cyan]{label_title}[/bold cyan] ({len(filtered_cols)} de {len(columns)} colunas) — {type_desc}\n"
            f"[dim]Arquivo configurável: dpipot_types.toml[/dim]"
        )

        for idx, col in enumerate(filtered_cols):
            tbl.add_row(
                str(idx + 1),
                col.get("name", ""),
                col.get("type", "VARCHAR"),
                col.get("example", ""),
                col.get("description", ""),
            )

    # -------------------------------------------------------------------------
    # Tratamento de Eventos (Botões, Seletores, Filtros)
    # -------------------------------------------------------------------------
    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id

        # Aba 1: Ingestão
        if btn_id == "btn_refresh_files":
            self._reload_logs_list()
            self.notify("Lista de logs atualizada.")
        elif btn_id == "btn_convert_selected":
            target = self._get_currently_selected_log_file()
            if target:
                self._convert_single_item(target)
            else:
                self.notify("Selecione um log na tabela para converter!", severity="warning")
        elif btn_id == "btn_convert_pending":
            self._convert_pending_items()

        # Aba 2: Consultas
        elif btn_id == "btn_load_period":
            self._load_active_period()
        elif btn_id == "btn_run_sql":
            self._execute_sql_query()
        elif btn_id == "btn_q_describe":
            self._set_and_run_sql("DESCRIBE SELECT * FROM logs;")
        elif btn_id == "btn_q_count":
            self._set_and_run_sql("SELECT COUNT(*) AS total_registros FROM logs;")
        elif btn_id == "btn_q_sample":
            self._set_and_run_sql("SELECT * FROM logs LIMIT 50;")
        elif btn_id == "btn_q_summarize":
            self._set_and_run_sql("SUMMARIZE logs;")
        elif btn_id == "btn_q_custom_1":
            self._handle_context_query_1()
        elif btn_id == "btn_q_custom_2":
            self._handle_context_query_2()
        elif btn_id == "btn_q_custom_3":
            self._handle_context_query_3()

        # Aba 3: Dicionário
        elif btn_id == "btn_reload_toml":
            self._load_toml_schema()
            self._refresh_dict_view()
            self.notify("Arquivo dpipot_types.toml recarregado!")

    def _handle_context_query_1(self) -> None:
        t = self.current_query_type
        if t == "proxy":
            self._set_and_run_sql(
                "SELECT COALESCE(\"src_geo.country_name\", 'Desconhecido') AS pais, "
                "COUNT(*) AS total_conexoes "
                "FROM logs GROUP BY 1 ORDER BY 2 DESC LIMIT 20;"
            )
        elif t == "pods":
            self._set_and_run_sql(
                "SELECT COALESCE(username, 'NULL') AS usuario, "
                "COUNT(*) AS tentativas "
                "FROM logs WHERE username IS NOT NULL "
                "GROUP BY 1 ORDER BY 2 DESC LIMIT 20;"
            )
        elif t == "classifier":
            self._set_and_run_sql(
                "SELECT category, COUNT(*) AS contagem "
                "FROM logs GROUP BY 1 ORDER BY 2 DESC LIMIT 20;"
            )
        elif t == "infra":
            self._set_and_run_sql(
                "SELECT \"kubernetes.pod.name\", COUNT(*) AS total_logs "
                "FROM logs GROUP BY 1 ORDER BY 2 DESC LIMIT 20;"
            )

    def _handle_context_query_2(self) -> None:
        t = self.current_query_type
        if t == "proxy":
            self._set_and_run_sql(
                "SELECT dst_port AS porta_alvo, honeypot, COUNT(*) AS conexoes "
                "FROM logs GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 20;"
            )
        elif t == "pods":
            self._set_and_run_sql(
                "SELECT COALESCE(password, 'NULL') AS senha, "
                "COUNT(*) AS tentativas "
                "FROM logs WHERE password IS NOT NULL "
                "GROUP BY 1 ORDER BY 2 DESC LIMIT 20;"
            )
        elif t == "classifier":
            self._set_and_run_sql(
                "SELECT COALESCE(tcp_flags, 'NENHUMA') AS flags, COUNT(*) AS total "
                "FROM logs GROUP BY 1 ORDER BY 2 DESC LIMIT 20;"
            )
        elif t == "infra":
            self._set_and_run_sql(
                "SELECT \"log.level\", COUNT(*) AS total "
                "FROM logs GROUP BY 1 ORDER BY 2 DESC LIMIT 20;"
            )

    def _handle_context_query_3(self) -> None:
        t = self.current_query_type
        if t == "proxy":
            self._set_and_run_sql(
                "SELECT COALESCE(ndpi_proto, 'Desconhecido') AS protocolo_ndpi, "
                "COUNT(*) AS total "
                "FROM logs GROUP BY 1 ORDER BY 2 DESC LIMIT 20;"
            )
        elif t == "pods":
            self._set_and_run_sql(
                "SELECT message, COUNT(*) AS ocorrencias "
                "FROM logs WHERE message IS NOT NULL "
                "GROUP BY 1 ORDER BY 2 DESC LIMIT 20;"
            )
        elif t == "classifier":
            self._set_and_run_sql(
                "SELECT COALESCE(ndpi_proto, 'Outro') AS protocolo, COUNT(*) AS total "
                "FROM logs GROUP BY 1 ORDER BY 2 DESC LIMIT 20;"
            )
        elif t == "infra":
            self._set_and_run_sql(
                "SELECT \"host.name\", COUNT(*) AS logs "
                "FROM logs GROUP BY 1 ORDER BY 2 DESC LIMIT 20;"
            )

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "sel_filter_type":
            self._reload_logs_list()
        elif event.select.id == "sel_query_type" and event.value != Select.BLANK:
            self._load_active_period()
        elif event.select.id == "sel_dict_type" and event.value != Select.BLANK:
            self._refresh_dict_view()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "inp_filter_dict":
            self._refresh_dict_view()


def main():
    app = DpipotAnalyticsApp()
    app.run()


if __name__ == "__main__":
    main()
