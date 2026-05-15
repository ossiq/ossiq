"""
Console renderer for scan command.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ossiq.domain.common import Command, ConstraintType, UserInterfaceType
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

        table_peer = self._peer_status_table(
            data.production_packages + data.optional_packages + data.transitive_packages,
            full=full,
        )
        if table_peer:
            self.console.print("\n")
            self.console.print(table_peer)

    def _peer_status_table(self, packages: list[ScanRecord], *, full: bool) -> Table | None:
        """Table showing peer constraint status for all packages that have peer requirements."""
        violated_specs_by_pkg: dict[str, set[str]] = {
            record.package_name: {req.spec for req in record.peer_violations}
            for record in packages
            if record.peer_violations
        }

        rows: list[tuple[str, str, str, str, str]] = []
        for record in sorted(packages, key=lambda r: r.package_name):
            if not record.peer_requirements:
                continue
            violated = violated_specs_by_pkg.get(record.package_name, set())
            via_override = record.constraint_info.type == ConstraintType.OVERRIDE
            for req in record.peer_requirements:
                if req.spec in violated:
                    status = "violation"
                elif via_override:
                    status = "override"
                else:
                    status = "ok"
                if full or status == "violation":
                    rows.append((record.package_name, record.installed_version, req.spec, req.requirer_name, status))

        if not rows:
            return None

        has_violations = any(status == "violation" for *_, status in rows)
        title_style = "bold red" if has_violations else "bold yellow"
        table = Table(title="Peer Constraint Status", title_style=title_style)
        table.add_column("Package", justify="left", style="bold cyan")
        table.add_column("Installed", justify="left")
        table.add_column("Peer Constraint", justify="left")
        table.add_column("Required By", justify="left")
        table.add_column("Status", justify="center")

        for pkg_name, installed, spec, requirer, status in rows:
            if status == "violation":
                status_cell = "[bold red]✗ violation[/]"
            elif status == "override":
                status_cell = "[bold yellow]✓ via override[/]"
            else:
                status_cell = "[bold green]✓ satisfied[/]"
            table.add_row(pkg_name, installed, spec, requirer, status_cell)

        return table

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

        show_recommended = any(pkg.recommended_version is not None or pkg.constraint_conflict for pkg in dependencies)

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
                if pkg.constraint_conflict:
                    row_args.append("[bold red][NO RESOLUTION][/]")
                elif pkg.recommended_version is not None:
                    if pkg.recommended_version != pkg.latest_version:
                        row_args.append(f"[yellow][bold]{pkg.recommended_version}[/]")
                    else:
                        row_args.append(pkg.recommended_version)
                else:
                    row_args.append("")

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

            if pkg.constraint_conflict:
                blanks = [""] * (len(table.columns) - 1)
                specs = " + ".join(pkg.constraint_conflict)
                table.add_row(f"  [bold red]↳ no version satisfies: {specs}[/]", *blanks)

        return table
