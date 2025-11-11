"""
"""
from typing import Callable

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()
error_console = Console(stderr=True)


def show_progress(ctx, message: str, fn: Callable):
    """
    Show progress till function is executed
    """
    if ctx["settings"].verbose is False:
        with console.status(f"[bold cyan]{message}"):
            return fn()
    else:
        return fn()


def show_settings(ctx, label: str, settings: dict):
    """
    Show a panel with key/value pairs with settings
    """
    if ctx["settings"].verbose is False:
        return

    header_text = Text()
    header_text.append("\n", style="bold cyan")
    for setting, value in settings.items():
        header_text.append(f"{setting}: ", style="bold white")
        header_text.append(f"{value}\n", style="green")

    console.print(f"\n[bold cyan] {label}")
    console.print(Panel(header_text, expand=False, border_style="cyan"))


def show_error(ctx, message: str):
    """
    Show error message
    """
    error_console.print(
        f"\n[bold yellow on red blink] ERROR [/bold yellow on red blink] [red]{message}[/red]"
    )
