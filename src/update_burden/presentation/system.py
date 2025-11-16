"""
"""
from contextlib import contextmanager
from typing import Callable

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from update_burden.settings import Settings

console = Console()
error_console = Console(stderr=True)


@contextmanager
def show_operation_progress(settings: Settings, message: str):
    """
    Show progress till function is executed if
    verbose is disabled.    
    """
    @contextmanager
    def noop():
        yield lambda: None

    try:
        if settings.verbose is False:
            yield lambda: console.status(f"[bold cyan]{message}")
        else:
            yield noop
    finally:
        pass


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
