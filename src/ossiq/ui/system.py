"""
Presentation-related system-level functions
"""

import sys
import time
from contextlib import contextmanager
from dataclasses import replace

from ossiq.domain.common import (
    DataCompleteness,
    DataSourceStatus,
    DegradeReason,
    FetchDiagnostics,
    RateLimitBudget,
    ScanStep,
)
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

    Yields a `ScanProgress` whose callbacks do three different jobs:
      on_step_start(step)                       - advance the spinner to this step.
      on_step_done(step, status, diagnostics)   - record this step's final outcome and what
                                     degraded it, without moving the spinner. Steps that never
                                     report one render as ok once passed; see ScanStep for which
                                     steps can report and why the rest can't.
      on_budget(budgets)           - a pre-flight quota reading, warned about immediately when it
                                     doesn't cover the scan, and repeated in the closing warning.

    B4: previously a step was drawn as a green checkmark purely because the scan had moved past
    it - there was no feedback loop from whether the underlying fetch actually succeeded. That's
    why a firewalled OSV host or an exhausted GitHub quota could render a silent, confident ✓.
    """
    step_status: dict[ScanStep, DataSourceStatus] = {}
    step_diagnostics: dict[ScanStep, FetchDiagnostics] = {}

    def record_step_done(step: ScanStep, status: DataSourceStatus, diagnostics: FetchDiagnostics | None = None) -> None:
        step_status[step] = status
        if diagnostics is not None:
            step_diagnostics[step] = diagnostics

    def record_budget(budgets: tuple[RateLimitBudget, ...]) -> None:
        # Up front, because the point of the forecast is to be heard before the scan spends the
        # quota it is warning about. Rich prints it above a running Live region.
        warn_about_budget(budgets)

    try:
        # --verbose and a missing Rich both skip the stepper, but neither is a reason to skip the
        # warning: a verbose CI log is exactly where someone would look for it, and it used to be
        # the one place it could never appear. The outcome callback still runs so there is
        # something to warn about; only the animation is dropped.
        if settings.verbose or not RICH_AVAILABLE:
            yield ScanProgress(on_step_done=record_step_done, on_budget=record_budget)
            return

        assert error_console is not None
        current = [-1]

        with Live(render_scan_steps(-1, step_status), console=error_console, refresh_per_second=8) as live:

            def on_step_start(step: ScanStep) -> None:
                current[0] = STEP_INDEX.get(step, current[0])
                live.update(render_scan_steps(current[0], step_status))

            def on_step_done(
                step: ScanStep, status: DataSourceStatus, diagnostics: FetchDiagnostics | None = None
            ) -> None:
                record_step_done(step, status, diagnostics)
                live.update(render_scan_steps(current[0], step_status))

            yield ScanProgress(on_step_start=on_step_start, on_step_done=on_step_done, on_budget=record_budget)
            live.update(render_scan_steps(len(SCAN_STEPS), step_status))
        print("\n", file=sys.stderr)
    finally:
        warn_about_degraded_steps(DataCompleteness(by_step=step_status, diagnostics=step_diagnostics))


UNAUTHENTICATED_LIMIT = 60
"""GitHub's unauthenticated REST ceiling. A limit at or below it means no token is in play, which
is the one case where the fix is a setting rather than waiting for the window to roll over."""

# What each failure cause means in a sentence a user can act on. `partial` alone never said
# whether three repositories had been renamed or the quota had run out - the two call for very
# different responses, and one of them is not the user's problem at all.
DEGRADE_REASON_LABELS: dict[DegradeReason, str] = {
    DegradeReason.NOT_FOUND: "not found (renamed, deleted or private)",
    DegradeReason.RATE_LIMITED: "rate limited",
    DegradeReason.UNAVAILABLE: "unreachable after retries",
    DegradeReason.REJECTED: "refused (check the token's access)",
    DegradeReason.EMPTY_RESPONSE: "answered with no data",
    DegradeReason.ABORTED: "skipped after the run was cut short",
    DegradeReason.UNKNOWN: "failed",
}


def format_duration(seconds: float) -> str:
    """A rate-limit reset as a human reads it: `43m`, `2h 05m`, `30s`."""
    if seconds < 60:
        return f"{int(seconds)}s"
    minutes = int(seconds // 60)
    if minutes < 60:
        return f"{minutes}m"
    return f"{minutes // 60}h {minutes % 60:02d}m"


def format_budget(budget: RateLimitBudget, now: float | None = None) -> str:
    """One resource's quota as a line: `graphql 4 987/5 000 left, resets in 43m`."""
    parts = [budget.resource]
    if budget.remaining is not None:
        parts.append(f"{budget.remaining}/{budget.limit} left" if budget.limit else f"{budget.remaining} left")
    if budget.needed:
        parts.append(f"this scan needs ~{budget.needed}")
    until_reset = budget.seconds_until_reset(now if now is not None else time.time())
    if until_reset is not None:
        parts.append(f"resets in {format_duration(until_reset)}")
    return " ".join(parts[:1]) + (": " + ", ".join(parts[1:]) if len(parts) > 1 else "")


def warn_about_budget(budgets: tuple[RateLimitBudget, ...]) -> None:
    """Warn up front when a quota looks too thin for the scan about to spend it.

    Only resources the forecast says are short are worth interrupting for: an ample quota is not
    news, and the scan is about to report everything else anyway.

    Args:
        budgets: Pre-flight readings, each carrying what the scan expects to need.
    """
    short = [budget for budget in budgets if budget.short_by]
    if not short:
        return
    lines = [f"  - {format_budget(budget)}" for budget in short]
    unauthenticated = any(budget.limit is not None and budget.limit <= UNAUTHENTICATED_LIMIT for budget in short)
    hint = (
        "\n  Set OSSIQ_GITHUB_TOKEN (or --github-token) to raise the limit."
        if unauthenticated
        else "\n  Repository and maintenance signals will be thin until the quota resets."
    )
    show_warning("The API quota may not cover this scan:\n" + "\n".join(lines) + hint)


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
    lines = []
    for key, status in degraded.items():
        causes = describe_failures(completeness.diagnostics_for(key))
        lines.append(f"  - {labels.get(key, key)}: {status.value}" + (f" — {causes}" if causes else ""))
    # `needed` was a forecast made before the fetches ran; repeating it next to what is actually
    # left reads as a second prediction rather than a result.
    budgets = [replace(budget, needed=None) for budget in completeness.budgets]
    if budgets:
        lines.append("  API quota at the end of the scan: " + "; ".join(format_budget(b) for b in budgets))
    show_warning(
        "Some data sources did not fully respond, so this report may be based on incomplete data:\n" + "\n".join(lines)
    )


def describe_failures(diagnostics: FetchDiagnostics) -> str:
    """The causes behind one step's degraded status, as `3 not found, 1 rate limited`."""
    return ", ".join(
        f"{count} {DEGRADE_REASON_LABELS.get(reason, reason.value)}" for reason, count in diagnostics.failures
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
