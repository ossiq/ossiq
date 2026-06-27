"""Console renderer for status command."""

from rich.console import Console
from rich.rule import Rule
from rich.table import Table

from ossiq.domain.common import Command, ConstraintType, UserInterfaceType
from ossiq.service.library_scan import UpgradePath
from ossiq.service.project import ScanRecord, ScanResult
from ossiq.settings import Settings
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer
from ossiq.ui.renderers.impact_utils import (
    format_lag_status,
    format_time_delta,
    impact_sub_row_texts,
    new_transitive_deps_table,
)


class ConsoleStatusRenderer(AbstractUserInterfaceRenderer):
    """Console renderer for status command."""

    command = Command.STATUS
    user_interface_type = UserInterfaceType.CONSOLE

    def __init__(self, settings: Settings):
        super().__init__(settings)
        self.console = Console()

    @staticmethod
    def supports(command: Command, user_interface_type: UserInterfaceType) -> bool:
        """Check if this renderer handles status/console combination."""
        return command == Command.STATUS and user_interface_type == UserInterfaceType.CONSOLE

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

        transitive_with_recs = sorted(
            (r for r in data.transitive_packages if r.recommended_version is not None),
            key=lambda r: r.package_name,
        )

        self.console.print()
        self.console.print(Rule(f"OSS IQ — Status: {data.project_name}", style="bold"))
        self.console.print(
            f"  Registry: [bold]{data.packages_registry}[/bold]  |  Path: [dim]{data.project_path}[/dim]"
        )
        self.console.print(
            f"  Production: [bold]{len(data.production_packages)}[/bold]  |  "
            f"Dev: [bold]{len(data.optional_packages)}[/bold]  |  "
            f"Transitive recs: [bold]{len(transitive_with_recs)}[/bold]"
        )
        self.console.print()

        main_table = self.build_main_table(
            data.production_packages,
            data.optional_packages,
            lag_threshold_days,
            full=full,
        )
        if main_table:
            self.console.print(main_table)
            self.console.print()

        if transitive_with_recs:
            self.console.print(Rule("Transitive Recommendations", style="dim"))
            self.console.print()
            self.console.print(self.transitive_table(transitive_with_recs))
            self.console.print()

        new_dep_impacts = [
            i
            for records in [data.production_packages, data.optional_packages]
            for r in records
            if r.recommended_version and r.recommended_version != r.installed_version
            for i in r.update_transitive_impacts
            if i.current_version is None
        ]
        table_new_deps = new_transitive_deps_table(new_dep_impacts, cooldown_period=self.settings.cooldown_period)
        if table_new_deps:
            self.console.print(table_new_deps)
            self.console.print()

        table_peer = self.peer_status_table(
            data.production_packages + data.optional_packages + data.transitive_packages,
            full=full,
        )
        if table_peer:
            self.console.print(Rule("Peer Constraint Status", style="dim"))
            self.console.print()
            self.console.print(table_peer)
            self.console.print()

        table_upgrade = self.upgrade_paths_table(data.upgrade_paths)
        if table_upgrade:
            self.console.print(Rule("Constraint Widening Opportunities", style="dim"))
            self.console.print()
            self.console.print(table_upgrade)
            self.console.print()

    def build_main_table(
        self,
        prod: list[ScanRecord],
        dev: list[ScanRecord],
        lag_threshold_days: int,
        *,
        full: bool = True,
    ) -> Table | None:
        """Single borderless table merging prod and dev sections."""

        def filter_deps(deps: list[ScanRecord]) -> list[ScanRecord]:
            if full:
                return deps
            return [
                pkg
                for pkg in deps
                if (pkg.recommended_version is not None and pkg.recommended_version != pkg.installed_version)
                or bool(pkg.cve)
            ]

        filtered_prod = filter_deps(prod)
        filtered_dev = filter_deps(dev)

        if not filtered_prod and not filtered_dev:
            return None

        show_recommended = any(
            pkg.recommended_version is not None or pkg.constraint_conflict for pkg in filtered_prod + filtered_dev
        )

        table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
        table.add_column("Package", style="bold")
        table.add_column("CVEs", justify="center")
        table.add_column("Status", justify="center")
        table.add_column("Installed", justify="left")
        if show_recommended:
            table.add_column("Recommended", justify="left", style="bold green")
        table.add_column("Latest", justify="left")
        table.add_column("Lag", justify="right")

        empty = [""] * (len(table.columns) - 1)
        first_section = True

        def add_section_label(label: str) -> None:
            nonlocal first_section
            if not first_section:
                table.add_section()
                table.add_row(*[""] * len(table.columns))
                table.add_section()
            first_section = False
            table.add_row(f"[dim]{label}[/dim]", *empty)
            table.add_section()

        def add_pkg_rows(packages: list[ScanRecord]) -> None:
            for pkg in packages:
                installed_cell = pkg.installed_version
                if pkg.is_installed_package_unpublished:
                    installed_cell += " [bold red][UNPUBLISHED][/]"
                elif pkg.is_installed_yanked:
                    installed_cell += " [bold red][YANKED][/]"
                elif pkg.is_installed_deprecated:
                    installed_cell += " [bold yellow][DEPRECATED][/]"
                elif pkg.is_installed_prerelease:
                    installed_cell += " [yellow][pre][/]"

                row: list[str] = [
                    pkg.package_name,
                    f"[bold red]{len(pkg.cve)}" if pkg.cve else "",
                    format_lag_status(pkg.versions_diff_index),
                    installed_cell,
                ]

                if show_recommended:
                    if pkg.constraint_conflict:
                        row.append("[bold red][NO RESOLUTION][/]")
                    elif pkg.recommended_version is not None:
                        if pkg.recommended_version != pkg.latest_version:
                            row.append(f"[bold yellow]{pkg.recommended_version}[/]")
                        else:
                            row.append(pkg.recommended_version)
                    else:
                        row.append("")

                row += [
                    pkg.latest_version if pkg.latest_version else "[bold red]N/A",
                    format_time_delta(pkg.time_lag_days, lag_threshold_days),
                ]

                table.add_row(*row)

                if pkg.update_transitive_impacts and pkg.recommended_version != pkg.installed_version:
                    blanks = [""] * (len(table.columns) - 1)
                    for text in impact_sub_row_texts(pkg.update_transitive_impacts):
                        table.add_row(text, *blanks)

                if pkg.constraint_conflict:
                    blanks = [""] * (len(table.columns) - 1)
                    specs = " + ".join(pkg.constraint_conflict)
                    table.add_row(f"  [bold red]↳ no version satisfies: {specs}[/]", *blanks)

        if filtered_prod:
            add_section_label("Production")
            add_pkg_rows(filtered_prod)

        if filtered_dev:
            add_section_label("Development")
            add_pkg_rows(filtered_dev)

        return table

    def transitive_table(self, packages: list[ScanRecord]) -> Table:
        """Borderless table for transitive packages with solver-recommended versions."""
        table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
        table.add_column("Package", justify="left", style="bold")
        table.add_column("Installed", justify="left")
        table.add_column("CVEs", justify="center")
        table.add_column("Age", justify="right")
        table.add_column("Recommended", justify="left", style="bold green")

        for pkg in packages:
            table.add_row(
                pkg.package_name,
                pkg.installed_version,
                f"[bold red]{len(pkg.cve)}" if pkg.cve else "",
                format_time_delta(pkg.version_age_days, 365),
                pkg.recommended_version or "",
            )
        return table

    def upgrade_paths_table(self, paths: list[UpgradePath]) -> Table | None:
        """Borderless table for constraint widening opportunities."""
        if not paths:
            return None

        table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
        table.add_column("Package", style="bold")
        table.add_column("Current Range")
        table.add_column("Latest In-Range", style="bold green")
        table.add_column("Latest Available")
        table.add_column("Suggested Range", style="bold yellow")

        for path in sorted(paths, key=lambda p: p.package_name):
            table.add_row(
                path.package_name,
                path.current_constraint,
                path.latest_in_range,
                path.latest_available,
                path.suggested_constraint,
            )

        return table

    def peer_status_table(self, packages: list[ScanRecord], *, full: bool) -> Table | None:
        """Borderless table for peer constraint status."""
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

        table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
        table.add_column("Package", justify="left", style="bold")
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
