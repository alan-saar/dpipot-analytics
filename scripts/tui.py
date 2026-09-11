#!/usr/bin/env python3
"""
TUI Interativa para Análise de Logs: CSV ➔ Apache Parquet ➔ Consultas DuckDB
Desenvolvido para análise de logs de honeypots e fluxos de rede (DPIpot-NG).
"""

import os
import glob
import time
from pathlib import Path
from typing import List, Optional

import duckdb
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    DirectoryTree,
    Footer,
    Header,
    Input,
    Label,
    ProgressBar,
    RadioButton,
    RadioSet,
    RichLog,
    Rule,
    Select,
    TabbedContent,
    TabPane,
    TextArea,
)


class FilteredDirectoryTree(DirectoryTree):
    """Árvore de diretórios que foca em pastas e arquivos CSV/Parquet."""
    def filter_paths(self, paths: list[Path]) -> list[Path]:
        filtered = []
        for p in paths:
            # Ignorar diretórios ocultos e caches comuns
            if p.name.startswith(".") or p.name in ("__pycache__", "venv", ".venv"):
                continue
            if p.is_dir():
                filtered.append(p)
            elif p.suffix.lower() in (".csv", ".parquet", ".tsv"):
                filtered.append(p)
        return filtered


class LogAnalyzerApp(App):
    """Aplicação TUI completa de processamento e análise de logs."""

    CSS = """
    Screen {
        background: $surface;
    }

    #left_nav {
        width: 38;
        border-right: solid $primary;
        padding: 1;
    }

    #main_convert {
        padding: 1 2;
    }

    .section-title {
        text-style: bold;
        color: $accent;
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

    #log_convert {
        height: 14;
        border: solid $accent;
        background: $surface-darken-1;
        margin-top: 1;
    }

    #query_sidebar {
        width: 36;
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
        height: 10;
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
    """

    BINDINGS = [
        Binding("ctrl+q", "quit", "Sair", priority=True),
        Binding("ctrl+r", "refresh_all", "Atualizar", priority=True),
        Binding("f1", "tab_convert", "Aba Conversão"),
        Binding("f2", "tab_query", "Aba Consultas"),
    ]

    def __init__(self):
        super().__init__()
        self.con = duckdb.connect()
        self.selected_path: Optional[Path] = None
        self.current_parquet: Optional[str] = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(id="tabs"):
            with TabPane("📁 Conversor CSV ➔ Parquet", id="tab_pane_convert"):
                with Horizontal():
                    with Vertical(id="left_nav"):
                        yield Label("📂 [bold]Explorador[/bold]:", classes="section-title")
                        yield FilteredDirectoryTree(Path.cwd(), id="dir_tree")
                        yield Button("🔄 Recarregar Árvore", id="btn_reload_tree", variant="default")

                    with VerticalScroll(id="main_convert"):
                        yield Label("⚙️ [bold]Configuração de Conversão[/bold]", classes="section-title")
                        
                        yield Label("Caminho Selecionado (Arquivo CSV ou Pasta):")
                        yield Input(placeholder="Clique em um arquivo ou pasta no explorador à esquerda...", id="inp_selected_path")

                        with Horizontal(classes="form-group"):
                            with Vertical():
                                yield Label("Modo de Conversão:")
                                with RadioSet(id="radio_mode"):
                                    yield RadioButton("Genérico (Inferência Automática DuckDB)", value=True, id="mode_auto")
                                    yield RadioButton("Genérico 100% Texto (Fidelidade Total all_varchar)", id="mode_varchar")
                                    yield RadioButton("Preset: Pods Cowrie (DPIpot-NG SSH)", id="mode_pods")
                                    yield RadioButton("Preset: Proxy TPROXY (DPIpot-NG MITM)", id="mode_proxy")

                            with Vertical():
                                yield Label("Destino e Opções:")
                                yield Label("Pasta de Saída:")
                                yield Input(value="data", id="inp_out_dir")
                                yield Checkbox("Mesclar CSVs em 1 arquivo (se pasta)", id="chk_merge", value=False)
                                yield Checkbox("Ignorar linhas com erros (ignore_errors)", id="chk_ignore_errors", value=True)

                        with Horizontal(classes="action-bar"):
                            yield Button("🚀 Iniciar Conversão", variant="primary", id="btn_start_convert")
                            yield Button("🧹 Limpar Log", variant="default", id="btn_clear_log")

                        yield ProgressBar(id="convert_progress", show_eta=False, total=100)
                        yield Label("Registro de Execução:")
                        yield RichLog(id="log_convert", wrap=True, highlight=True, markup=True)

            with TabPane("🔍 Consultas DuckDB", id="tab_pane_query"):
                with Horizontal():
                    with Vertical(id="query_sidebar"):
                        yield Label("📊 [bold]Datasets Parquet[/bold]:", classes="section-title")
                        yield Select([], id="sel_parquet", prompt="Selecione um Parquet...")
                        yield Button("🔄 Atualizar Datasets", id="btn_refresh_datasets", variant="default")
                        
                        yield Rule()
                        yield Label("⚡ [bold]Consultas Rápidas[/bold]:")
                        yield Button("🔍 Schema (DESCRIBE)", id="btn_q_describe")
                        yield Button("🔢 Contar Linhas (COUNT)", id="btn_q_count")
                        yield Button("👁️ Amostra (LIMIT 50)", id="btn_q_sample")
                        yield Button("📈 Resumo (SUMMARIZE)", id="btn_q_summarize")
                        yield Button("🌍 Top Países (src_country)", id="btn_q_paises")
                        yield Button("🔑 Top Senhas / Logins", id="btn_q_senhas")

                    with Vertical(id="query_main"):
                        yield Label("📝 [bold]Consulta SQL (Tabela ativa: [cyan]logs[/cyan])[/bold]:", classes="section-title")
                        yield TextArea("SELECT * FROM logs LIMIT 50;", language="sql", id="sql_editor")
                        
                        with Horizontal(classes="action-bar"):
                            yield Button("▶️ Executar SQL", variant="success", id="btn_run_sql")
                            yield Label("Pronto para executar.", id="lbl_query_status")

                        yield DataTable(id="table_results", zebra_stripes=True, cursor_type="cell")

        yield Footer()

    def on_mount(self) -> None:
        self.title = "DPIpot-NG | Analisador de Logs & Conversor Parquet"
        self.sub_title = "DuckDB + Textual"
        self._refresh_parquet_list()
        log_box = self.query_one("#log_convert", RichLog)
        log_box.write("[bold green]Sistema pronto.[/bold green] Selecione um arquivo CSV ou pasta à esquerda para iniciar.")

    def action_tab_convert(self) -> None:
        self.query_one("#tabs", TabbedContent).active = "tab_pane_convert"

    def action_tab_query(self) -> None:
        self.query_one("#tabs", TabbedContent).active = "tab_pane_query"

    def action_refresh_all(self) -> None:
        self._refresh_parquet_list()
        self.notify("Lista de Parquets atualizada.")

    def on_directory_tree_directory_selected(self, event: DirectoryTree.DirectorySelected) -> None:
        self.selected_path = event.path
        self.query_one("#inp_selected_path", Input).value = str(event.path)

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        self.selected_path = event.path
        self.query_one("#inp_selected_path", Input).value = str(event.path)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn_reload_tree":
            tree = self.query_one("#dir_tree", FilteredDirectoryTree)
            tree.reload()
            self.notify("Árvore de arquivos recarregada.")
        elif btn_id == "btn_clear_log":
            self.query_one("#log_convert", RichLog).clear()
        elif btn_id == "btn_start_convert":
            self._start_conversion_process()
        elif btn_id == "btn_refresh_datasets":
            self._refresh_parquet_list()
            self.notify("Datasets atualizados!")
        elif btn_id == "btn_run_sql":
            self._execute_sql_query()
        elif btn_id == "btn_q_describe":
            self._set_and_run_sql("DESCRIBE SELECT * FROM logs;")
        elif btn_id == "btn_q_count":
            self._set_and_run_sql("SELECT COUNT(*) AS total_linhas FROM logs;")
        elif btn_id == "btn_q_sample":
            self._set_and_run_sql("SELECT * FROM logs LIMIT 50;")
        elif btn_id == "btn_q_summarize":
            self._set_and_run_sql("SUMMARIZE logs;")
        elif btn_id == "btn_q_paises":
            self._set_and_run_sql(
                "SELECT COALESCE(src_country, 'Desconhecido') AS pais, "
                "COUNT(*) AS total_conexoes "
                "FROM logs GROUP BY 1 ORDER BY 2 DESC LIMIT 15;"
            )
        elif btn_id == "btn_q_senhas":
            self._set_and_run_sql(
                "SELECT COALESCE(password, attack_type, executed_command) AS credencial_comando, "
                "COUNT(*) AS tentativas "
                "FROM logs GROUP BY 1 ORDER BY 2 DESC LIMIT 15;"
            )

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "sel_parquet" and event.value != Select.BLANK:
            self._load_active_parquet(str(event.value))

    def _refresh_parquet_list(self) -> None:
        out_dir = self.query_one("#inp_out_dir", Input).value.strip() or "data"
        parquets = glob.glob(f"{out_dir}/**/*.parquet", recursive=True) + glob.glob("*.parquet")
        parquets = sorted(list(set(parquets)))
        
        select = self.query_one("#sel_parquet", Select)
        options = [(f"{Path(p).name} ({Path(p).parent})", p) for p in parquets]
        select.set_options(options)

        if options and (not self.current_parquet or self.current_parquet not in parquets):
            select.value = options[0][1]

    def _load_active_parquet(self, path: str) -> None:
        self.current_parquet = path
        try:
            self.con.execute(f"CREATE OR REPLACE VIEW logs AS SELECT * FROM read_parquet('{path}');")
            count = self.con.execute("SELECT COUNT(*) FROM logs;").fetchone()[0]
            size_mb = os.path.getsize(path) / (1024 * 1024)
            lbl = self.query_one("#lbl_query_status", Label)
            lbl.update(f"Ativo: [bold cyan]{Path(path).name}[/bold cyan] ({count:,} linhas, {size_mb:.2f} MB)")
            self.notify(f"Dataset carregado: {Path(path).name}")
        except Exception as e:
            self.notify(f"Erro ao carregar Parquet: {e}", severity="error")

    def _set_and_run_sql(self, sql: str) -> None:
        editor = self.query_one("#sql_editor", TextArea)
        editor.text = sql
        self._execute_sql_query()

    def _execute_sql_query(self) -> None:
        if not self.current_parquet:
            self.notify("Selecione um arquivo Parquet primeiro!", severity="warning")
            return

        sql = self.query_one("#sql_editor", TextArea).text.strip()
        if not sql:
            return

        table = self.query_one("#table_results", DataTable)
        lbl_status = self.query_one("#lbl_query_status", Label)
        
        lbl_status.update("Executando consulta...")
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
                msg += f" [yellow](limitado a {MAX_ROWS} para visualização rápida)[/yellow]"
            lbl_status.update(msg)

        except Exception as e:
            elapsed = time.time() - t0
            lbl_status.update(f"[red]Erro SQL ({elapsed:.3f}s):[/red] {e}")

    def _start_conversion_process(self) -> None:
        path_str = self.query_one("#inp_selected_path", Input).value.strip()
        if not path_str:
            self.notify("Por favor, selecione um arquivo ou pasta CSV!", severity="warning")
            return

        path = Path(path_str)
        if not path.exists():
            self.notify(f"Caminho não encontrado: {path}", severity="error")
            return

        out_dir = self.query_one("#inp_out_dir", Input).value.strip() or "data"
        merge = self.query_one("#chk_merge", Checkbox).value
        ignore_errors = self.query_one("#chk_ignore_errors", Checkbox).value

        radio_mode = self.query_one("#radio_mode", RadioSet)
        mode = "auto"
        if radio_mode.pressed_button:
            btn_id = radio_mode.pressed_button.id
            if btn_id == "mode_varchar":
                mode = "varchar"
            elif btn_id == "mode_pods":
                mode = "pods"
            elif btn_id == "mode_proxy":
                mode = "proxy"

        self._run_conversion_worker(path, out_dir, mode, merge, ignore_errors)

    @work(thread=True)
    def _run_conversion_worker(
        self, path: Path, out_dir: str, mode: str, merge: bool, ignore_errors: bool
    ) -> None:
        log_box = self.query_one("#log_convert", RichLog)
        progress = self.query_one("#convert_progress", ProgressBar)
        
        self.app.call_from_thread(progress.update, progress=0)
        os.makedirs(out_dir, exist_ok=True)

        csv_files: List[Path] = []
        if path.is_file():
            if path.suffix.lower() == ".csv":
                csv_files = [path]
            else:
                self.app.call_from_thread(
                    log_box.write, f"[red]Arquivo selecionado não é CSV: {path.name}[/red]"
                )
                return
        else:
            csv_files = sorted(list(path.glob("*.csv")) + list(path.glob("**/*.csv")))
            if not csv_files:
                self.app.call_from_thread(
                    log_box.write, f"[yellow]Nenhum arquivo .csv encontrado em: {path}[/yellow]"
                )
                return

        total_files = len(csv_files)
        self.app.call_from_thread(
            log_box.write,
            f"\n[bold cyan]=== Iniciando Ingestão de {total_files} arquivo(s) CSV ===[/bold cyan]\n"
            f"• Modo: [bold yellow]{mode}[/bold yellow] | Destino: [bold yellow]{out_dir}/[/bold yellow]"
        )

        db_con = duckdb.connect()

        # Caso 1: Mesclar pasta inteira de CSVs em um único Parquet
        if merge and path.is_dir() and len(csv_files) > 1 and mode in ("auto", "varchar"):
            out_parquet = Path(out_dir) / f"{path.name}_merged.parquet"
            self.app.call_from_thread(
                log_box.write, f"🔄 Mesclando todos os CSVs de [yellow]{path.name}[/yellow] em [green]{out_parquet.name}[/green]..."
            )
            t0 = time.time()
            varchar_opt = ", all_varchar=true" if mode == "varchar" else ""
            err_opt = ", ignore_errors=true" if ignore_errors else ""
            
            query = f"""
            COPY (
                SELECT * FROM read_csv('{path}/*.csv', union_by_name=true{varchar_opt}{err_opt})
            ) TO '{out_parquet}' (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000);
            """
            try:
                db_con.execute(query)
                elapsed = time.time() - t0
                count = db_con.execute(f"SELECT COUNT(*) FROM read_parquet('{out_parquet}')").fetchone()[0]
                size_mb = os.path.getsize(out_parquet) / (1024 * 1024)
                self.app.call_from_thread(
                    log_box.write,
                    f"[bold green]✓ Mesclagem concluída em {elapsed:.1f}s![/bold green]\n"
                    f"  • Total de Linhas: [yellow]{count:,}[/yellow]\n"
                    f"  • Tamanho Parquet: [yellow]{size_mb:.2f} MB[/yellow]\n"
                    f"  • Arquivo Gerado: [green]{out_parquet}[/green]"
                )
                self.app.call_from_thread(progress.update, progress=100)
            except Exception as err:
                self.app.call_from_thread(log_box.write, f"[bold red]❌ Erro na mesclagem:[/bold red] {err}")
            
            self.app.call_from_thread(self._refresh_parquet_list)
            return

        # Caso 2: Conversão arquivo a arquivo
        for idx, csv_p in enumerate(csv_files):
            t0 = time.time()
            out_parquet = Path(out_dir) / f"{csv_p.stem}.parquet"
            
            orig_size_mb = os.path.getsize(csv_p) / (1024 * 1024)
            self.app.call_from_thread(
                log_box.write,
                f"[{idx+1}/{total_files}] Convertendo [cyan]{csv_p.name}[/cyan] ({orig_size_mb:.1f} MB)..."
            )

            try:
                if mode == "auto":
                    err_opt = "ignore_errors=true" if ignore_errors else "ignore_errors=false"
                    query = f"""
                    COPY (
                        SELECT * FROM read_csv('{csv_p}', {err_opt})
                    ) TO '{out_parquet}' (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000);
                    """
                elif mode == "varchar":
                    err_opt = "ignore_errors=true" if ignore_errors else "ignore_errors=false"
                    query = f"""
                    COPY (
                        SELECT * FROM read_csv('{csv_p}', all_varchar=true, {err_opt})
                    ) TO '{out_parquet}' (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000);
                    """
                elif mode == "pods":
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
                        FROM read_csv('{csv_p}', ignore_errors=true, all_varchar=true)
                        WHERE (
                            protocol = 'ssh' 
                            OR isSSH = 'true' 
                            OR eventid LIKE 'cowrie%' 
                            OR hassh IS NOT NULL
                        )
                    ) TO '{out_parquet}' (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000);
                    """
                elif mode == "proxy":
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
                        FROM read_csv('{csv_p}', ignore_errors=true, all_varchar=true)
                        WHERE (
                            honeypot LIKE '%cowrie%' 
                            OR ndpi_proto = 'SSH' 
                            OR dst_port IN ('22', '2222')
                        )
                    ) TO '{out_parquet}' (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000);
                    """

                db_con.execute(query)
                elapsed = time.time() - t0
                dest_size_mb = os.path.getsize(out_parquet) / (1024 * 1024)
                count = db_con.execute(f"SELECT COUNT(*) FROM read_parquet('{out_parquet}')").fetchone()[0]
                ratio = (orig_size_mb / dest_size_mb) if dest_size_mb > 0 else 0

                self.app.call_from_thread(
                    log_box.write,
                    f"  [green]✓ Concluído em {elapsed:.1f}s[/green] | Linhas: [yellow]{count:,}[/yellow] | "
                    f"Tamanho: [yellow]{dest_size_mb:.2f} MB[/yellow] (Compressão: ~{ratio:.1f}x)\n"
                    f"  Arquivo: [dim]{out_parquet}[/dim]"
                )
            except Exception as err:
                self.app.call_from_thread(
                    log_box.write, f"  [bold red]❌ Falha na conversão de {csv_p.name}:[/bold red] {err}"
                )

            pct = int(((idx + 1) / total_files) * 100)
            self.app.call_from_thread(progress.update, progress=pct)

        self.app.call_from_thread(log_box.write, "[bold green]🎉 Todos os arquivos foram processados![/bold green]")
        self.app.call_from_thread(self._refresh_parquet_list)


def main():
    app = LogAnalyzerApp()
    app.run()


if __name__ == "__main__":
    main()
