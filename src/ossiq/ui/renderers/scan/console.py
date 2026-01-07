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
from ossiq.service.project import ProjectMetrics, ProjectMetricsRecord
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

    def render(self, data: ProjectMetrics, **kwargs) -> None:  # type: ignore[override]
        """
        Render project metrics to console.

        Args:
            data: ProjectMetrics from scan service
            **kwargs: Rendering options
                - lag_threshold_days: int - Threshold for highlighting time lag
        """
        lag_threshold_days = kwargs.get("lag_threshold_days", 180)
        table_prod = self._table_factory(
            "Production Packages Version Status", "bold green", data.production_packages, lag_threshold_days
        )

        table_dev = None
        if data.development_packages:
            table_dev = self._table_factory(
                "Optional Packages Version Status", "bold cyan", data.development_packages, lag_threshold_days
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
        self.console.print("\n")
        self.console.print(table_prod)

        if table_dev:
            self.console.print("\n")
            self.console.print(table_dev)

    def _table_factory(
        self, title: str, title_style: str, dependencies: list[ProjectMetricsRecord], lag_threshold_days: int
    ) -> Table:
        """Create Rich table with dependency data."""
        table = Table(title=title, title_style=title_style)
        table.add_column("Dependency", justify="left", style="bold cyan")
        table.add_column("CVEs", justify="center")
        table.add_column("Lag Status", justify="center")
        table.add_column("Installed", justify="left")
        table.add_column("Latest", justify="left")
        table.add_column("Release Lag", justify="right")
        table.add_column("Time Lag", justify="right")

        for pkg in dependencies:
            table.add_row(
                pkg.package_name,
                f"[bold][red]{len(pkg.cve)}" if pkg.cve else "",
                self._format_lag_status(pkg.versions_diff_index),
                pkg.installed_version,
                pkg.latest_version if pkg.latest_version else "[bold][red]N/A",
                str(pkg.releases_lag),
                self._format_time_delta(pkg.time_lag_days, lag_threshold_days),
            )

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
