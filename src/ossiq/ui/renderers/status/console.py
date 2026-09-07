"""Console renderer for status command."""

from rich.console import Console
from rich.rule import Rule
from rich.table import Table

from ossiq.domain.common import Command, ConstraintType, UserInterfaceType
from ossiq.domain.version import VERSION_DIFF_MAJOR, VERSION_DIFF_MINOR, VERSION_DIFF_PATCH
from ossiq.risk.maintenance import NOT_MAINTAINED
from ossiq.service.library_scan import UpgradePath
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.service.project.next_action import CONSTRAINED_CHECK_NEWER, next_action_label
from ossiq.settings import Settings
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer
from ossiq.ui.renderers.impact_utils import (
    format_lag_status,
    format_probability,
    format_state,
    format_status_badge,
    format_time_delta,
    impact_sub_row_texts,
    new_transitive_deps_table,
    whats_next,
)

BEHIND_DIFFS: frozenset[int] = frozenset({VERSION_DIFF_MAJOR, VERSION_DIFF_MINOR, VERSION_DIFF_PATCH})

MAIN_COLUMNS_DEFAULT: tuple[str, ...] = (
    "Package",
    "CVEs",
    "Installed",
    "Latest",
    "Recommended",
    "What's Next",
)
MAIN_COLUMNS_FULL: tuple[str, ...] = (
    "Package",
    "CVEs",
    "EPSS",
    "Update Mode",
    "Installed",
    "Latest",
    "Recommended",
    "Lag",
    "State",
    "What's Next",
)


def add_status_column(table: Table, name: str) -> None:
    """Add one main-table column with the justification / style it uses in every mode."""
    if name == "Package":
        table.add_column(name, style="bold")
    elif name == "Recommended":
        table.add_column(name, justify="left", style="bold green")
    elif name in ("CVEs", "Update Mode", "State"):
        table.add_column(name, justify="center")
    elif name in ("EPSS", "Lag"):
        table.add_column(name, justify="right")
    else:  # Installed, Latest, What's Next
        table.add_column(name, justify="left")


def recommended_cell(pkg: ScanRecord) -> str:
    """Recommended-column cell: a conflict marker, a highlighted off-latest version, or plain text."""
    if pkg.constraint_conflict:
        return "[bold red][NO RESOLUTION][/]"
    if pkg.recommended_version is None:
        return ""
    if pkg.recommended_version != pkg.latest_version:
        return f"[bold yellow]{pkg.recommended_version}[/]"
    return pkg.recommended_version


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
                - full: bool - When True show every package and the detail columns; default keeps
                  only packages that need action and a minimal column set
        """
        lag_threshold_days = kwargs.get("lag_threshold_days", 180)
        full = kwargs.get("full", False)

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
        if data.project_epss is not None:
            unscored = data.project_epss.unscored_cve_packages
            unscored_part = f"  |  Unscored: [bold]{unscored}[/bold]" if unscored else ""
            self.console.print(
                f"  Project EPSS: [bold]{format_probability(data.project_epss.score)}[/bold]  |  "
                f"Scored: [bold]{data.project_epss.scored_packages}[/bold]{unscored_part}"
            )
        if data.project_stability is not None and data.project_stability.scored_packages:
            stability = data.project_stability
            deprecated_part = f" ({stability.deprecated_packages} deprecated)" if stability.deprecated_packages else ""
            self.console.print(
                f"  Unmaintained deps: [bold]{stability.unmaintained_packages}[/bold]{deprecated_part} of "
                f"[bold]{stability.scored_packages}[/bold] assessed  |  "
                f"Unassessed: [bold]{stability.unknown_packages}[/bold]"
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
            self.console.print(self.transitive_table(transitive_with_recs, full=full))
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

        if data.ignored_packages:
            self.console.print(Rule("Ignored Dependencies", style="dim"))
            self.console.print()
            for dep in data.ignored_packages:
                spec = f"  [dim]{dep.spec}[/dim]" if dep.spec else ""
                self.console.print(f"  [yellow]•[/yellow] {dep.name}{spec}  [dim]({dep.reason})[/dim]")
            self.console.print()

    def build_main_table(
        self,
        prod: list[ScanRecord],
        dev: list[ScanRecord],
        lag_threshold_days: int,
        *,
        full: bool = False,
    ) -> Table | None:
        """Single borderless table merging prod and dev sections.

        `full` picks the wide column set and keeps every package; the default keeps a minimal
        column set and only the packages that need action (drift, a CVE, an unmaintained
        upstream, or an unsolvable constraint).
        """

        def needs_action(pkg: ScanRecord) -> bool:
            state = pkg.maintenance.state if pkg.maintenance is not None else None
            return (
                pkg.versions_diff_index.diff_index in BEHIND_DIFFS
                or bool(pkg.cve)
                or state in NOT_MAINTAINED
                or bool(pkg.constraint_conflict)
                or pkg.recommended_version not in (None, pkg.installed_version)
            )

        filtered_prod = prod if full else [pkg for pkg in prod if needs_action(pkg)]
        filtered_dev = dev if full else [pkg for pkg in dev if needs_action(pkg)]

        if not filtered_prod and not filtered_dev:
            return None

        columns = MAIN_COLUMNS_FULL if full else MAIN_COLUMNS_DEFAULT

        table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
        for name in columns:
            add_status_column(table, name)

        blanks = [""] * (len(columns) - 1)
        first_section = True

        def add_section_label(label: str) -> None:
            nonlocal first_section
            if not first_section:
                table.add_section()
                table.add_row(*[""] * len(columns))
                table.add_section()
            first_section = False
            table.add_row(f"[dim]{label}[/dim]", *blanks)
            table.add_section()

        def add_pkg_rows(packages: list[ScanRecord]) -> None:
            for pkg in packages:
                cells = {
                    "Package": pkg.package_name,
                    "CVEs": f"[bold red]{len(pkg.cve)}" if pkg.cve else "",
                    "EPSS": format_probability(pkg.epss),
                    "Update Mode": format_lag_status(pkg.versions_diff_index),
                    "Installed": pkg.installed_version + format_status_badge(pkg),
                    "Latest": pkg.latest_version or "[dim]—[/dim]",
                    "Recommended": recommended_cell(pkg),
                    "Lag": format_time_delta(pkg.time_lag_days, lag_threshold_days),
                    "State": format_state(pkg),
                    "What's Next": whats_next(pkg),
                }
                table.add_row(*(cells[name] for name in columns))

                if full and pkg.update_transitive_impacts and pkg.recommended_version != pkg.installed_version:
                    for text in impact_sub_row_texts(pkg.update_transitive_impacts):
                        table.add_row(text, *blanks)

                # Name the range that is holding the package back — the "what to do" half of the
                # Constrained label. Other blockers (e.g. an override pin) may apply on top.
                if full and pkg.version_constraint and next_action_label(pkg) == CONSTRAINED_CHECK_NEWER:
                    table.add_row(
                        f"  [yellow]↳ {pkg.version_constraint} caps this below {pkg.latest_version}[/]",
                        *blanks,
                    )

                if pkg.constraint_conflict:
                    specs = " + ".join(pkg.constraint_conflict)
                    table.add_row(f"  [bold red]↳ no version satisfies: {specs}[/]", *blanks)

        if filtered_prod:
            add_section_label("Production")
            add_pkg_rows(filtered_prod)

        if filtered_dev:
            add_section_label("Development")
            add_pkg_rows(filtered_dev)

        return table

    def transitive_table(self, packages: list[ScanRecord], *, full: bool = False) -> Table:
        """Borderless table for transitive packages with solver-recommended versions."""
        table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
        table.add_column("Package", justify="left", style="bold")
        table.add_column("CVEs", justify="center")
        if full:
            table.add_column("EPSS", justify="right")
        table.add_column("Installed", justify="left")
        table.add_column("Recommended", justify="left", style="bold green")
        table.add_column("What's Next", justify="left")

        for pkg in packages:
            row = [pkg.package_name, f"[bold red]{len(pkg.cve)}" if pkg.cve else ""]
            if full:
                row.append(format_probability(pkg.epss))
            row += [pkg.installed_version, pkg.recommended_version or "", whats_next(pkg)]
            table.add_row(*row)
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
