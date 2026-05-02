"""
Console renderer for the package deep-dive command.
"""

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from ossiq.domain.common import Command, ConstraintType, UserInterfaceType
from ossiq.domain.version import (
    VERSION_DIFF_MAJOR,
    VERSION_DIFF_MINOR,
    VERSION_DIFF_PATCH,
    VERSION_LATEST,
    VersionsDifference,
)
from ossiq.service.package import PackageDetailResult, TransitiveCVEGroup
from ossiq.service.project import ScanRecord
from ossiq.settings import Settings
from ossiq.timeutil import format_time_days
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer

# ── Drift status config (mirrors Vue driftConfig) ──────────────────────────────
_DRIFT_CONFIG: dict[int, tuple[str, str]] = {
    VERSION_DIFF_MAJOR: ("MAJOR", "bold red"),
    VERSION_DIFF_MINOR: ("MINOR", "bold yellow"),
    VERSION_DIFF_PATCH: ("PATCH", "bold blue"),
    VERSION_LATEST: ("LATEST", "bold green"),
}

# ── Severity styles (mirrors Vue severityStyles) ───────────────────────────────
_SEVERITY_STYLE: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "default",
}

_LAG_BAR_WIDTH = 30  # characters


def _drift_label_and_style(vdiff: VersionsDifference) -> tuple[str, str]:
    return _DRIFT_CONFIG.get(vdiff.diff_index, ("N/A", "default"))


def _severity_style(severity: str) -> str:
    return _SEVERITY_STYLE.get(severity.upper(), "default")


def _lag_bar(days: int | None) -> str:
    """ASCII progress bar representing time lag (max = 365 days = 100%)."""
    if not days or days <= 0:
        return f"[{'─' * _LAG_BAR_WIDTH}]"
    filled = min(_LAG_BAR_WIDTH, round((days / 365) * _LAG_BAR_WIDTH))
    empty = _LAG_BAR_WIDTH - filled
    return f"[{'█' * filled}{'─' * empty}]"


def _lag_style(days: int | None) -> str:
    if not days:
        return "bold green"
    if days > 730:
        return "bold red"
    if days > 365:
        return "bold yellow"
    if days > 90:
        return "bold red"
    if days > 30:
        return "bold yellow"
    return "bold green"


def _is_direct(record: ScanRecord) -> bool:
    return record.dependency_path is None


def _is_transitive(record: ScanRecord) -> bool:
    return record.dependency_path is not None


def _collect_licenses(records: list[ScanRecord]) -> list[str]:
    """Collect unique licenses across all occurrences, preserving first-seen order."""
    seen: set[str] = set()
    result: list[str] = []
    for record in records:
        for lic in record.license or []:
            if lic not in seen:
                seen.add(lic)
                result.append(lic)
    return result


class ConsolePackageRenderer(AbstractUserInterfaceRenderer):
    """Console renderer for the package deep-dive command."""

    command = Command.PACKAGE
    user_interface_type = UserInterfaceType.CONSOLE

    def __init__(self, settings: Settings):
        super().__init__(settings)
        self.console = Console()

    @staticmethod
    def supports(command: Command, user_interface_type: UserInterfaceType) -> bool:
        return command == Command.PACKAGE and user_interface_type == UserInterfaceType.CONSOLE

    def render(self, data: PackageDetailResult, **kwargs) -> None:
        """Render single-package deep-dive to console."""
        self.console.print()
        self._render_header(data)
        self.console.print()

        for i, record in enumerate(data.records):
            if len(data.records) > 1:
                self.console.print(Rule(f"Occurrence {i + 1} of {len(data.records)}", align="left"))
                self.console.print()

            self._render_drift_status(record)
            self.console.print()
            self._render_dependency_tree_trace(record)
            self.console.print()
            self._render_policy_compliance(record)
            self.console.print()

        self._render_security_advisories(data.records)
        self.console.print()
        self._render_transitive_cves(data.transitive_cve_groups)

        licenses = _collect_licenses(data.records)
        if len(licenses) > 1:
            self.console.print()
            self._render_licenses(licenses)

        self.console.print()

    # ── Header ─────────────────────────────────────────────────────────────────

    def _render_header(self, data: PackageDetailResult) -> None:
        records = data.records
        record = records[0]
        has_direct = any(_is_direct(r) for r in records)
        has_transitive = any(_is_transitive(r) for r in records)
        licenses = _collect_licenses(records)

        title = Text()
        title.append(record.package_name, style="bold cyan")
        title.append(f"  {record.installed_version}", style="bold blue")
        if record.is_installed_package_unpublished:
            title.append("  [UNPUBLISHED]", style="bold red")
        elif record.is_installed_yanked:
            title.append("  [YANKED]", style="bold red")
        elif record.is_installed_deprecated:
            title.append("  [DEPRECATED]", style="bold yellow")
        elif record.is_installed_prerelease:
            title.append("  [pre]", style="yellow")

        meta = Text()

        # Badges
        if has_direct:
            meta.append(" DIRECT ", style="bold green")
            meta.append("  ")
        if has_transitive:
            meta.append(" TRANSITIVE ", style="bold yellow")
            meta.append("  ")

        # First license only in header
        if licenses:
            meta.append(licenses[0], style="bold")
            if len(licenses) > 1:
                meta.append(f" +{len(licenses) - 1} more", style="default")
        else:
            meta.append("License N/A")

        if record.package_url:
            meta.append(f"  {record.package_url}", style="blue")

        self.console.print(Panel(Text.assemble(title, "\n", meta), expand=False, border_style="cyan"))

    # ── [01] Drift Status ──────────────────────────────────────────────────────

    def _render_drift_status(self, record: ScanRecord) -> None:
        self.console.print("[bold][01] DRIFT STATUS[/bold]")

        label, style = _drift_label_and_style(record.versions_diff_index)
        status_text = Text()
        status_text.append("  Status      : ")
        status_text.append(label, style=style)
        self.console.print(status_text)

        installed_text = Text()
        installed_text.append("  Installed   : ")
        installed_text.append(record.installed_version, style="bold")
        if record.is_installed_package_unpublished:
            installed_text.append("  [UNPUBLISHED]", style="bold red")
        elif record.is_installed_yanked:
            installed_text.append("  [YANKED]", style="bold red")
        elif record.is_installed_deprecated:
            installed_text.append("  [DEPRECATED]", style="bold yellow")
        elif record.is_installed_prerelease:
            installed_text.append("  [pre]", style="yellow")
        self.console.print(installed_text)

        latest_text = Text()
        latest_text.append("  Latest      : ")
        latest_text.append(
            record.latest_version or "N/A",
            style="bold green" if record.latest_version else "bold red",
        )
        self.console.print(latest_text)

        days = record.time_lag_days
        lag_style = _lag_style(days)
        lag_str = format_time_days(days) if days else "—"
        bar = _lag_bar(days)

        lag_text = Text()
        lag_text.append("  Time Lag    : ")
        lag_text.append(bar, style=lag_style)
        lag_text.append(f"  {lag_str}", style=lag_style)
        self.console.print(lag_text)

        releases_text = Text()
        releases_text.append("  Release Lag : ")
        if record.releases_lag:
            releases_text.append(f"{record.releases_lag} versions behind", style="bold")
        else:
            releases_text.append("—")
        self.console.print(releases_text)

    # ── [02] Dependency Tree Trace ─────────────────────────────────────────────

    def _render_dependency_tree_trace(self, record: ScanRecord) -> None:
        self.console.print("[bold][02] DEPENDENCY TREE TRACE[/bold]")

        path = record.dependency_path or []
        indent = "  "

        self.console.print(f"{indent}[bold cyan]→[/bold cyan] root")
        for i, ancestor in enumerate(path):
            pad = "  " * (i + 1)
            self.console.print(f"{indent}{pad}└─ {ancestor}")

        final_pad = "  " * (len(path) + 1)
        self.console.print(
            f"{indent}{final_pad}└─ [bold cyan]{record.package_name}[/bold cyan] [bold blue]← you are here[/bold blue]"
        )

    # ── [03] Policy Compliance ─────────────────────────────────────────────────

    def _render_policy_compliance(self, record: ScanRecord) -> None:
        self.console.print("[bold][03] POLICY COMPLIANCE[/bold]")

        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("PARAMETER")
        table.add_column("VALUE")

        table.add_row("Constraint", record.version_constraint or "—")
        table.add_row("Resolved", Text(record.installed_version, style="bold blue"))
        table.add_row("Latest", Text(record.latest_version or "—", style="bold green"))

        if record.constraint_info and record.constraint_info.type != ConstraintType.DECLARED:
            style = "bold red" if record.constraint_info.type == ConstraintType.OVERRIDE else "bold yellow"
            label = record.constraint_info.type.value
            src = record.constraint_info.source_file
            table.add_row("Constraint Type", Text(f"{label}  (from {src})", style=style))

        self.console.print(table)

    # ── [04] Security Advisories ───────────────────────────────────────────────

    def _render_security_advisories(self, records: list[ScanRecord]) -> None:
        seen: set[str] = set()
        all_cves = []
        for record in records:
            for cve in record.cve:
                if cve.id not in seen:
                    seen.add(cve.id)
                    all_cves.append(cve)

        count_str = f" ({len(all_cves)} found)" if all_cves else ""
        self.console.print(f"[bold][04] SECURITY ADVISORIES{count_str}[/bold]")

        if not all_cves:
            self.console.print("  [bold green]✓[/bold green] No known vulnerabilities")
            return

        for cve in all_cves:
            sev_style = _severity_style(cve.severity)
            line = Text()
            line.append(f"  [{cve.severity:<8}]", style=sev_style)
            line.append(f"  {cve.id}", style="bold")
            line.append(f"  (via {cve.source})")
            self.console.print(line)
            if cve.summary:
                self.console.print(f"  {cve.summary}")
            self.console.print()

    # ── [05] Via Transitive Dependencies ──────────────────────────────────────

    def _render_transitive_cves(self, groups: list[TransitiveCVEGroup]) -> None:
        if not groups:
            return

        self.console.print(f"[bold][05] VIA TRANSITIVE DEPENDENCIES ({len(groups)} affected)[/bold]")
        self.console.print()

        for group in groups:
            header = Text()
            header.append(f"  {group.name}", style="bold cyan")
            header.append(f"  v{group.version}")
            header.append(f"  [{len(group.cves)} CVE{'s' if len(group.cves) != 1 else ''}]", style="bold red")
            self.console.print(header)

            for cve in group.cves:
                sev_style = _severity_style(cve.severity)
                line = Text()
                line.append(f"    [{cve.severity:<8}]", style=sev_style)
                line.append(f"  {cve.id}", style="bold")
                line.append(f"  (via {cve.source})")
                self.console.print(line)
                if cve.summary:
                    self.console.print(f"    {cve.summary}")

            self.console.print()

    # ── [06] Licenses ─────────────────────────────────────────────────────────

    def _render_licenses(self, licenses: list[str]) -> None:
        self.console.print("[bold][06] LICENSES[/bold]")
        self.console.print()
        for lic in licenses:
            self.console.print(f"  [bold cyan]{lic}[/bold cyan]")
