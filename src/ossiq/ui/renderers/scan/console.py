"""
Console renderer for scan command.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.domain.version import (
    VERSION_DIFF_BUILD,
    VERSION_DIFF_MAJOR,
    VERSION_DIFF_MINOR,
    VERSION_DIFF_PATCH,
    VERSION_DIFF_PRERELEASE,
    VERSION_LATEST,
    VersionsDifference,
)
from ossiq.service.project import ScanRecord, ScanResult
from ossiq.settings import Settings
from ossiq.timeutil import format_time_days
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer


class ConsoleScanRenderer(AbstractUserInterfaceRenderer):
    """Console renderer for scan command."""

    command = Command.SCAN
    user_interface_type = UserInterfaceType.CONSOLE

    def __init__(self, settings: Settings):
        super().__init__(settings)
        self.console = Console()

    @staticmethod
    def supports(command: Command, user_interface_type: UserInterfaceType) -> bool:
        """Check if this renderer handles scan/console combination."""
        return command == Command.SCAN and user_interface_type == UserInterfaceType.CONSOLE

    def render(self, data: ScanResult, **kwargs) -> None:
        """
        Render project metrics to console.

        Args:
            data: ProjectMetrics from scan service
            **kwargs: Rendering options
                - lag_threshold_days: int - Threshold for highlighting time lag
                - transitive: bool - When True show all transitive update recommendations
        """
        lag_threshold_days = kwargs.get("lag_threshold_days", 180)
        show_full_transitive = kwargs.get("transitive", False)

        table_prod = None
        if data.production_packages:
            table_prod = self._table_factory(
                "Production Dependency Drift Report", "bold green", data.production_packages, lag_threshold_days
            )

        table_dev = None
        if data.optional_packages:
            table_dev = self._table_factory(
                "Optional Dependency Drift Report", "bold cyan", data.optional_packages, lag_threshold_days
            )

        seen: set[tuple[str, str, str]] = set()
        transitive_with_recs: list[ScanRecord] = []
        for r in data.transitive_packages:
            if r.recommended_version is None:
                continue
            key = (r.package_name, r.installed_version, r.recommended_version)
            if key not in seen:
                seen.add(key)
                transitive_with_recs.append(r)

        table_transitive = None
        if transitive_with_recs:
            if show_full_transitive:
                table_transitive = self._transitive_table(
                    transitive_with_recs, "Transitive Recommendations", show_cve_column=True
                )
            else:
                safety_recs = [r for r in transitive_with_recs if r.cve]
                if safety_recs:
                    table_transitive = self._transitive_table(
                        safety_recs, "Transitive Safety Recommendations", show_cve_column=True
                    )

        # Header
        header_text = Text()
        header_text.append("📦 Project: ", style="bold white")
        header_text.append(f"{data.project_name}\n", style="bold cyan")
        header_text.append("🔗 Packages Registry: ", style="bold white")
        header_text.append(f"{data.packages_registry}\n", style="green")
        header_text.append("📍 Project Path: ", style="bold white")
        header_text.append(f"{data.project_path}", style="green")

        # Output
        self.console.print("\n")
        self.console.print(Panel(header_text, expand=False, border_style="cyan"))

        if table_prod:
            self.console.print("\n")
            self.console.print(table_prod)

        if table_dev:
            self.console.print("\n")
            self.console.print(table_dev)

        if table_transitive:
            self.console.print("\n")
            self.console.print(table_transitive)

    def _transitive_table(self, packages: list[ScanRecord], title: str, *, show_cve_column: bool) -> Table:
        """Table showing transitive packages with solver-recommended versions."""
        title_style = "bold yellow" if show_cve_column else "bold cyan"
        table = Table(title=title, title_style=title_style)
        table.add_column("Package", justify="left", style="bold cyan")
        table.add_column("Installed", justify="left")
        if show_cve_column:
            table.add_column("CVEs", justify="center")
        table.add_column("Age", justify="right")
        table.add_column("Recommended", justify="left", style="bold green")

        for pkg in packages:
            row: list[str] = [pkg.package_name, pkg.installed_version]
            if show_cve_column:
                row.append(f"[bold red]{len(pkg.cve)}" if pkg.cve else "")
            row.append(self._format_time_delta(pkg.version_age_days, 365))
            row.append(pkg.recommended_version or "")
            table.add_row(*row)
        return table

    def _table_factory(
        self, title: str, title_style: str, dependencies: list[ScanRecord], lag_threshold_days: int
    ) -> Table:
        """Create Rich table with dependency data."""

        show_recommended = any(pkg.recommended_version is not None for pkg in dependencies)

        table = Table(title=title, title_style=title_style)
        table.add_column("Dependency", justify="left", style="bold cyan")
        table.add_column("CVEs", justify="center")
        table.add_column("Status", justify="center")
        table.add_column("Installed", justify="left")

        if show_recommended:
            table.add_column("Recommended", justify="left")

        table.add_column("Latest", justify="left")
        table.add_column("Distance", justify="right")
        table.add_column("Time Lag", justify="right")
        table.add_column("Version Age", justify="right")

        for pkg in dependencies:
            installed_cell = pkg.installed_version
            if pkg.is_installed_package_unpublished:
                installed_cell += " [bold red][UNPUBLISHED][/]"
            elif pkg.is_installed_yanked:
                installed_cell += " [bold red][YANKED][/]"
            elif pkg.is_installed_deprecated:
                installed_cell += " [bold yellow][DEPRECATED][/]"
            elif pkg.is_installed_prerelease:
                installed_cell += " [yellow][pre][/]"

            row_args = [
                pkg.package_name,
                f"[bold][red]{len(pkg.cve)}" if pkg.cve else "",
                self._format_lag_status(pkg.versions_diff_index),
                installed_cell,
            ]

            if show_recommended:
                recommended_version = pkg.recommended_version if pkg.recommended_version is not None else ""
                if pkg.recommended_version != pkg.latest_version:
                    row_args.append(f"[yellow][bold]{recommended_version}[/]")
                else:
                    row_args.append(recommended_version)

            row_args += [
                pkg.latest_version if pkg.latest_version else "[bold][red]N/A",
                str(pkg.releases_lag),
                self._format_time_delta(pkg.time_lag_days, lag_threshold_days),
                self._format_time_delta(pkg.version_age_days, 365),
            ]

            table.add_row(*row_args)

        return table

    @staticmethod
    def _format_time_delta(days: int | None, lag_threshold_days: int) -> str:
        """Format time delta with color highlighting."""
        if days is None:
            return "N/A"

        formatted_string = format_time_days(days)
        return f"[bold red]{formatted_string}" if days >= lag_threshold_days else formatted_string

    @staticmethod
    def _format_lag_status(vdiff: VersionsDifference) -> str:
        """Format lag status with color coding."""
        if vdiff.diff_index == VERSION_DIFF_MAJOR:
            return "[red][bold]Major"
        elif vdiff.diff_index == VERSION_DIFF_MINOR:
            return "[yellow][bold]Minor"
        elif vdiff.diff_index == VERSION_DIFF_PATCH:
            return "[white]Patch"
        elif vdiff.diff_index == VERSION_DIFF_PRERELEASE:
            return "[yellow][bold]Prerelease"
        elif vdiff.diff_index == VERSION_DIFF_BUILD:
            return "[white]Build"
        elif vdiff.diff_index == VERSION_LATEST:
            return "[green][bold]Latest"
        else:
            return "[white][bold]N/A"
