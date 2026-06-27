"""
Presentation-related system-level functions
"""

import sys
from contextlib import contextmanager

from ossiq.settings import Settings

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.spinner import Spinner
    from rich.text import Text

    console = Console()
    error_console = Console(stderr=True)
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    console = None
    error_console = None

SCAN_STEPS: list[tuple[str, str]] = [
    ("project", "Reading project dependencies"),
    ("packages", "Fetching package metadata"),
    ("repositories", "Fetching repository info from GitHub"),
    ("vulnerabilities", "Checking for vulnerabilities via OSV.dev"),
    ("versions", "Analyzing version history"),
    ("solver", "Solving dependency constraints"),
]

STEP_INDEX: dict[str, int] = {key: i for i, (key, _) in enumerate(SCAN_STEPS)}


@contextmanager
def show_scan_progress(settings: Settings):
    """
    Show an animated vertical stepper while a scan runs.
    Each call to the yielded callback advances to the named step.
    """
    if settings.verbose or not RICH_AVAILABLE:
        yield lambda _: None
        return

    assert console is not None
    current = [-1]

    def render(idx: int):
        rows: list = [Text("")]
        for i, (_, label) in enumerate(SCAN_STEPS):
            if i < idx:
                rows.append(Text(f"  ✓  {label}", style="green"))
            elif i == idx:
                rows.append(Spinner("dots", text=Text(f"  {label}", style="bold cyan")))
            else:
                rows.append(Text(f"  ○  {label}", style="dim"))
            if i < len(SCAN_STEPS) - 1:
                rows.append(Text("  │", style="dim"))
        return Group(*rows)

    with Live(render(-1), console=console, refresh_per_second=8) as live:

        def on_step(key: str) -> None:
            current[0] = STEP_INDEX.get(key, current[0])
            live.update(render(current[0]))

        yield on_step
        live.update(render(len(SCAN_STEPS)))


@contextmanager
def show_operation_progress(settings: Settings, message: str):
    """
    Show progress till function is executed if
    verbose is disabled.
    """

    @contextmanager
    def noop():
        yield lambda: None

    if not RICH_AVAILABLE:
        yield noop
        return

    assert console is not None
    _console = console
    try:
        if settings.verbose is False:
            yield lambda: _console.status(f"[bold cyan]{message}")
        else:
            yield noop
    finally:
        pass


def show_settings(ctx, label: str, settings: dict):
    """
    Show a panel with key/value pairs with settings
    """
    if not RICH_AVAILABLE:
        return

    assert console is not None
    settings: Settings = ctx.obj
    if settings.verbose is False:
        return

    header_text = Text()
    header_text.append("\n", style="bold cyan")

    for setting, value in settings.model_dump().items():
        header_text.append(f"{setting}: ", style="bold white")
        header_text.append(f"{value}\n", style="green")

    console.print(f"\n[bold cyan] {label}")
    console.print(Panel(header_text, expand=False, border_style="cyan"))


def show_error(message: str, title: str = "Error", hint: str | None = None) -> None:
    """
    Show error message as a Rich panel with an optional hint line.
    """
    if not RICH_AVAILABLE:
        print(f"\n[{title.upper()}] {message}", file=sys.stderr)
        if hint:
            print(f"Hint: {hint}", file=sys.stderr)
        return

    assert error_console is not None
    text = Text()
    text.append(message, style="red")
    if hint:
        text.append("\n\nHint: ", style="bold white")
        text.append(hint, style="dim white")

    error_console.print(Panel(text, title=f"[bold red]{title}[/bold red]", border_style="red", expand=False))


def show_warning(message: str):
    """
    Show warning
    """
    if not RICH_AVAILABLE:
        print(f"\n[WARNING] {message.strip()}", file=sys.stderr)
        return

    assert error_console is not None
    error_console.print(f"\n[bold red on yellow]\\[WARNING][/bold red on yellow] [white]{message.strip()}[/white]")
