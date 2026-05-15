"""
Console renderer for scan command.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.service.project import ScanRecord, ScanResult
from ossiq.settings import Settings
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer
from ossiq.ui.renderers.impact_utils import (
    format_lag_status,
    format_time_delta,
    impact_sub_row_texts,
    new_transitive_deps_table,
)


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
                - full: bool - When True show all packages; default shows only packages with updates or CVEs
        """
        lag_threshold_days = kwargs.get("lag_threshold_days", 180)
        full = kwargs.get("full", True)

        table_prod = self._table_factory(
            "Production Dependency Drift Report", "bold green", data.production_packages, lag_threshold_days, full=full
        )

        table_dev = self._table_factory(
            "Optional Dependency Drift Report", "bold cyan", data.optional_packages, lag_threshold_days, full=full
        )

        transitive_with_recs = sorted(
            (r for r in data.transitive_packages if r.recommended_version is not None),
            key=lambda r: r.package_name,
        )

        table_transitive = None
        if transitive_with_recs:
            table_transitive = self._transitive_table(
                transitive_with_recs, "Transitive Recommendations", show_cve_column=True
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

        new_dep_impacts = [
            i
            for records in [data.production_packages, data.optional_packages]
            for r in records
            if r.recommended_version and r.recommended_version != r.installed_version
            for i in r.update_transitive_impacts
            if i.current_version is None
        ]
        table_new_deps = new_transitive_deps_table(new_dep_impacts)

        if table_transitive:
            self.console.print("\n")
            self.console.print(table_transitive)

        if table_new_deps:
            self.console.print("\n")
            self.console.print(table_new_deps)

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
            row.append(format_time_delta(pkg.version_age_days, 365))
            row.append(pkg.recommended_version or "")
            table.add_row(*row)
        return table

    def _table_factory(
        self,
        title: str,
        title_style: str,
        dependencies: list[ScanRecord],
        lag_threshold_days: int,
        *,
        full: bool = True,
    ) -> Table | None:
        """Create Rich table with dependency data."""
        if not full:
            dependencies = [
                pkg
                for pkg in dependencies
                if (pkg.recommended_version is not None and pkg.recommended_version != pkg.installed_version)
                or bool(pkg.cve)
            ]
        if not dependencies:
            return None

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
                format_lag_status(pkg.versions_diff_index),
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
                format_time_delta(pkg.time_lag_days, lag_threshold_days),
                format_time_delta(pkg.version_age_days, 365),
            ]

            table.add_row(*row_args)

            if pkg.update_transitive_impacts and pkg.recommended_version != pkg.installed_version:
                blanks = [""] * (len(table.columns) - 1)
                for text in impact_sub_row_texts(pkg.update_transitive_impacts):
                    table.add_row(text, *blanks)

        return table
