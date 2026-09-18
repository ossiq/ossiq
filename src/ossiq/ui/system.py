"""
Presentation-related system-level functions
"""

import sys
from contextlib import contextmanager

from ossiq.domain.common import DataCompleteness, DataSourceStatus, ScanStep
from ossiq.service.project.scan import ScanProgress
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

# Display labels only - ScanStep owns the keys, and the pipeline emits them. Order is the order
# the stepper draws, which is also the order scan() runs them in.
SCAN_STEPS: list[tuple[ScanStep, str]] = [
    (ScanStep.PROJECT, "Reading project dependencies"),
    (ScanStep.PACKAGES, "Fetching package metadata"),
    (ScanStep.REPOSITORIES, "Fetching repository info and activity from GitHub"),
    (ScanStep.VULNERABILITIES, "Checking for vulnerabilities via OSV.dev"),
    (ScanStep.EPSS, "Fetching EPSS scores via api.first.org"),
    (ScanStep.VERSIONS, "Analyzing version history"),
    (ScanStep.SOLVER, "Solving dependency constraints"),
]

STEP_INDEX: dict[ScanStep, int] = {key: i for i, (key, _) in enumerate(SCAN_STEPS)}

# B4: a step reaching completion is not the same as it succeeding. Never draw the plain green
# checkmark for a step whose outcome we know was degraded - each status gets its own icon, color,
# and a short suffix, so the difference is visible even skimming past quickly.
STEP_STATUS_ICON: dict[DataSourceStatus, tuple[str, str, str]] = {
    DataSourceStatus.OK: ("✓", "green", ""),
    DataSourceStatus.PARTIAL: ("⚠", "yellow", "  (partial — some data missing)"),
    DataSourceStatus.UNREACHABLE: ("✗", "red", "  (unreachable — no data)"),
    DataSourceStatus.RATE_LIMITED: ("✗", "red", "  (rate limited — no data)"),
}


def render_scan_steps(idx: int, step_status: dict[ScanStep, DataSourceStatus]) -> "Group":
    """Build the vertical stepper display for scan step `idx` (in progress), with earlier steps
    rendered per their recorded outcome in `step_status` (ok if never reported).

    A standalone function (rather than a closure inside show_scan_progress) specifically so this
    rendering decision - never draw success for a degraded step - is directly testable without
    needing a real terminal or a live Rich session. The return annotation is a string because
    `Group` only exists on the branch where rich imported successfully.
    """
    rows: list = [Text("")]
    for i, (key, label) in enumerate(SCAN_STEPS):
        if i < idx:
            icon, style, suffix = STEP_STATUS_ICON[step_status.get(key, DataSourceStatus.OK)]
            rows.append(Text(f"  {icon}  {label}{suffix}", style=style))
        elif i == idx:
            rows.append(Spinner("dots", text=Text(f"  {label}", style="bold cyan")))
        else:
            rows.append(Text(f"  ○  {label}", style="dim"))
        if i < len(SCAN_STEPS) - 1:
            rows.append(Text("  │", style="dim"))
    return Group(*rows)


@contextmanager
def show_scan_progress(settings: Settings):
    """
    Show an animated vertical stepper while a scan runs.

    Yields a `ScanProgress` whose two callbacks do two different jobs, both keyed by `ScanStep`:
      on_step_start(step)          - advance the spinner to this step.
      on_step_done(step, status)   - record this step's final outcome, without moving the spinner.
                                     Steps that never report one render as ok once passed; see
                                     ScanStep for which steps can report and why the rest can't.

    B4: previously a step was drawn as a green checkmark purely because the scan had moved past
    it - there was no feedback loop from whether the underlying fetch actually succeeded. That's
    why a firewalled OSV host or an exhausted GitHub quota could render a silent, confident ✓.
    """
    if settings.verbose or not RICH_AVAILABLE:
        yield ScanProgress()
        return

    assert error_console is not None
    current = [-1]
    step_status: dict[ScanStep, DataSourceStatus] = {}

    with Live(render_scan_steps(-1, step_status), console=error_console, refresh_per_second=8) as live:

        def on_step_start(step: ScanStep) -> None:
            current[0] = STEP_INDEX.get(step, current[0])
            live.update(render_scan_steps(current[0], step_status))

        def on_step_done(step: ScanStep, status: DataSourceStatus) -> None:
            step_status[step] = status
            live.update(render_scan_steps(current[0], step_status))

        yield ScanProgress(on_step_start=on_step_start, on_step_done=on_step_done)
        live.update(render_scan_steps(len(SCAN_STEPS), step_status))
    print("\n", file=sys.stderr)

    warn_about_degraded_steps(DataCompleteness(by_step=step_status))


def warn_about_degraded_steps(completeness: DataCompleteness) -> None:
    """Warn on stderr when any scan step came back degraded.

    Takes the domain value rather than a bare dict so `degraded_steps` decides what counts as
    degraded — this used to re-implement that filter as its own comprehension. A smaller icon is
    easy to scroll past, and a log line no one is watching is not a warning at all.

    Args:
        completeness: Per-step outcomes accumulated over the scan.
    """
    degraded = completeness.degraded_steps
    if not degraded:
        return
    labels = dict(SCAN_STEPS)
    lines = [f"  - {labels.get(key, key)}: {status.value}" for key, status in degraded.items()]
    show_warning(
        "Some data sources did not fully respond, so this report may be based on incomplete data:\n" + "\n".join(lines)
    )


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

    assert error_console is not None
    _console = error_console
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

    B8: diagnostic output, not the requested payload - goes to stderr like everything else in
    this module, so it never lands in a piped/redirected stdout regardless of command or format.
    """
    if not RICH_AVAILABLE:
        return

    assert error_console is not None
    settings: Settings = ctx.obj
    if settings.verbose is False:
        return

    header_text = Text()
    header_text.append("\n", style="bold cyan")

    for setting, value in settings.model_dump().items():
        if setting == "github_token":
            value = "set from environment" if value else None
        header_text.append(f"{setting}: ", style="bold white")
        header_text.append(f"{value}\n", style="green")

    error_console.print(f"\n[bold cyan] {label}")
    error_console.print(Panel(header_text, expand=False, border_style="cyan"))


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
