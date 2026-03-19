import time

from rich.console import Text
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table


def paint_dashboard(
    ui_mutex,
    pause_event,
    scoreboard: dict,
    thread_dashboard: dict,
    api_signature_count: int,
    is_typing_url: bool,
    input_buffer: str,
    log_history,
    leak_history,
    max_download_size_bytes: int,
) -> Layout:
    with ui_mutex:
        state_tag = "[bold green]▶ RUNNING[/]" if pause_event.is_set() else "[bold blink red]⏸ PAUSED (Press SPACE to Resume)[/]"
        top_bar_text = (
            f"{state_tag}  |  "
            f"[bold white]Queue Remaining:[/] {scoreboard['remaining']}  |  "
            f"[bold cyan]Scanned:[/] {scoreboard['scanned']}  |  "
            f"[bold green]Clean:[/] {scoreboard['clean']}  |  "
            f"[bold red]Leaks:[/] {scoreboard['leaks']}  |  "
            f"[bold yellow]Failed:[/] {scoreboard['failed']}"
        )

        thread_grid = Table(expand=True, border_style="cyan", padding=(0, 1))
        thread_grid.add_column("Worker", style="dim", width=10)
        thread_grid.add_column("Target Repository", width=28)
        thread_grid.add_column("Status / Progress", width=42)
        thread_grid.add_column("Active IP", width=20)
        thread_grid.add_column("Elapsed", justify="right", width=10)

        for thread_tag, current_state in thread_dashboard.items():
            time_spent = "-"
            target_str = current_state["target"]
            if len(target_str) > 25:
                target_str = target_str[:22] + "..."

            action_str = current_state["action"]
            if current_state["dl_bytes"] > 0 and "DL" in action_str:
                mb_downloaded = current_state["dl_bytes"] / (1024 * 1024)
                fill_ratio = min(1.0, current_state["dl_bytes"] / max_download_size_bytes)
                blocks_filled = int(fill_ratio * 12)
                bar_graphic = "█" * blocks_filled + "░" * (12 - blocks_filled)
                action_str = f"[yellow]DL [{bar_graphic}] {mb_downloaded:.1f}MB[/]"

            if current_state["target"] != "Idle":
                if pause_event.is_set() and current_state["clock_start"] > 0:
                    seconds_passed = time.time() - current_state["clock_start"]
                    color_code = "green" if seconds_passed < 5 else "yellow" if seconds_passed < 15 else "red"
                    time_spent = f"[{color_code}]{seconds_passed:.1f}s[/]"
                else:
                    time_spent = "[dim]Paused[/]"

            thread_grid.add_row(thread_tag, target_str, action_str, current_state["active_ip"], time_spent)

        screen_layout = Layout()
        screen_layout.split_column(
            Layout(
                Panel(
                    top_bar_text,
                    title=f"[bold magenta]XeroDay-API Scanner 2.0 (Hunting {api_signature_count} API Types)[/]",
                    border_style="magenta",
                ),
                size=3,
            ),
            Layout(name="bottom_section"),
        )

        input_prompt = (
            "[yellow]Describe GitHub repo URL(s) and press Enter (Esc to cancel):[/] "
            if is_typing_url else "[dim]Press 'i' to ask AI to insert GitHub repo URL(s)[/]"
        )
        display_text = input_prompt + ("[bold white]" + input_buffer + "[/]" if is_typing_url else "")
        input_panel = Panel(display_text, title="[bold green]AI Target Insertion[/]", border_style="green")

        left_layout = Layout(ratio=5)
        left_layout.split_column(
            Layout(Panel(thread_grid, title="[bold cyan]Active Thread Dashboard[/]", border_style="cyan")),
            Layout(input_panel, size=3),
        )

        screen_layout["bottom_section"].split_row(
            left_layout,
            Layout(name="logs_section", ratio=3),
        )

        system_feed = Text.from_markup("\n".join(log_history)) if log_history else Text("Awaiting events...", style="dim")
        bounty_feed = Text.from_markup("\n".join(leak_history)) if leak_history else Text("No leaks found yet.", style="dim")

        screen_layout["logs_section"].split_column(
            Layout(Panel(bounty_feed, title="[bold red]Recent Leaks Found[/]", border_style="red")),
            Layout(Panel(system_feed, title="[bold yellow]System Events[/]", border_style="yellow")),
        )
        return screen_layout
