"""Console renderer for the plan command."""

from rich.console import Console
from rich.rule import Rule
from rich.table import Table

from ossiq.domain.common import Command, UserInterfaceType, rung_scope_label
from ossiq.messages import (
    HELP_PLAN_CONVERGENCE_NOTICE,
    HELP_PLAN_CVE_BYPASS_NOTE,
    HELP_PLAN_FORCED_WARNING,
    HELP_PLAN_HELD_BY_PACKAGE_MANAGER_HEADER,
    HELP_PLAN_HELD_BY_PEERS_HEADER,
    HELP_PLAN_HELD_BY_USER_OVERRIDES_HEADER,
    HELP_PLAN_HELD_FOR_COOLDOWN_HEADER,
    HELP_PLAN_HELD_FOR_WIDENING_HEADER,
    HELP_PLAN_KNOWN_BREAK_NOTE,
    HELP_PLAN_NEW_DEP_FRESH_WARNING,
    HELP_PLAN_PEER_REPAIRS_HEADER,
)
from ossiq.service.update import UpdateEntry, UpdatePlan
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer
from ossiq.ui.renderers.impact_utils import (
    format_cutoff,
    impact_sub_row_texts,
    is_fresh_new_dep,
    new_transitive_deps_table,
)

console = Console()


def age_cell(entry: UpdateEntry) -> str:
    """Age of the entry's target in days, or a dash when the registry gave no publish date."""
    return f"{entry.reason.age_days}d" if entry.reason and entry.reason.age_days is not None else "—"


def package_cell_text(entry: UpdateEntry) -> str:
    """Package cell with non-actionable (✗) and CVE markers applied."""
    name = entry.display_name
    text = name if entry.is_actionable else f"[red]✗ {name}[/red]"
    if entry.is_security:
        text = f"{text} [red]CVE[/red]"
    return text


def is_cooldown_bypassed(entry: UpdateEntry, cooldown_period: int) -> bool:
    """True when an escalated recommendation is younger than the cooldown it bypassed.

    `cooldown_bypassed` covers the end-of-life escalation that `is_security` alone misses — the
    selector took a fresh release because nothing aged resolved the motive, so the note has to be
    drawn for that case too.
    """
    if not (entry.is_security or entry.cooldown_bypassed):
        return False
    if entry.reason is None or entry.reason.age_days is None:
        return False
    return entry.reason.age_days < cooldown_period


class ConsolePlanRenderer(AbstractUserInterfaceRenderer):
    """Renders the plan as a summary table followed by an optional bash script block."""

    command = Command.PLAN
    user_interface_type = UserInterfaceType.CONSOLE

    @staticmethod
    def supports(command: Command, user_interface_type: UserInterfaceType) -> bool:
        return command == Command.PLAN and user_interface_type == UserInterfaceType.CONSOLE

    def render(self, data: UpdatePlan, script: str = "", **kwargs) -> None:
        console.print()
        console.print(Rule(f"OSS IQ — Plan: {data.project_name}", style="bold"))
        console.print(
            f"  Package Manager: [bold]{data.package_manager_name}[/bold]  |  "
            f"Direct: [bold green]{len(data.direct_entries)}[/bold green]  |  "
            f"Transitive: [bold yellow]{len(data.transitive_entries)}[/bold yellow]"
        )
        console.print()

        if data.all_entries:
            table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
            table.add_column("Package", style="bold")
            table.add_column("Current", style="red")
            table.add_column("Recommended", style="green")
            table.add_column("Age", style="dim")
            table.add_column("Type", style="dim")

            for entry in data.direct_entries:
                age = f"{entry.reason.age_days}d" if entry.reason and entry.reason.age_days is not None else "—"
                dep_type = "[yellow]forced[/yellow]" if entry.is_forced else "direct"
                table.add_row(package_cell_text(entry), entry.current_version, entry.recommended_version, age, dep_type)
                if entry.carries_known_break:
                    table.add_row(f"[yellow]  {HELP_PLAN_KNOWN_BREAK_NOTE}[/yellow]", "", "", "", "")
                if is_cooldown_bypassed(entry, data.cooldown_period):
                    table.add_row(f"[dim]  {HELP_PLAN_CVE_BYPASS_NOTE}[/dim]", "", "", "", "")
                for text in impact_sub_row_texts(entry.transitive_impacts):
                    table.add_row(text, "", "", "", "")
            for entry in data.transitive_entries:
                age = f"{entry.reason.age_days}d" if entry.reason and entry.reason.age_days is not None else "—"
                dep_type = "[yellow]forced[/yellow]" if entry.is_forced else "transitive"
                table.add_row(package_cell_text(entry), entry.current_version, entry.recommended_version, age, dep_type)
                if entry.carries_known_break:
                    table.add_row(f"[yellow]  {HELP_PLAN_KNOWN_BREAK_NOTE}[/yellow]", "", "", "", "")
                if is_cooldown_bypassed(entry, data.cooldown_period):
                    table.add_row(f"[dim]  {HELP_PLAN_CVE_BYPASS_NOTE}[/dim]", "", "", "", "")

            console.print(table)
            console.print()

            if any(entry.is_forced for entry in data.all_entries):
                console.print(f"[yellow]{HELP_PLAN_FORCED_WARNING}[/yellow]")
                console.print()

            new_dep_impacts = [
                i for entry in data.direct_entries for i in entry.transitive_impacts if i.current_version is None
            ]
            table_new_deps = new_transitive_deps_table(new_dep_impacts, cooldown_period=data.cooldown_period)
            if table_new_deps:
                console.print(table_new_deps)
                console.print()
                if any(is_fresh_new_dep(i, data.cooldown_period) for i in new_dep_impacts):
                    console.print(
                        f"[yellow]{HELP_PLAN_NEW_DEP_FRESH_WARNING.format(days=data.cooldown_period)}[/yellow]"
                    )
                    console.print()

            if data.transitive_entries or new_dep_impacts:
                console.print(f"[dim]{HELP_PLAN_CONVERGENCE_NOTICE}[/dim]")
                console.print()

        self.render_held_for_cooldown(data)
        self.render_held_for_widening(data)
        self.render_held_by_user_overrides(data)
        self.render_held_by_peers(data)
        self.render_peer_repairs(data)

        if script:
            console.print(Rule("Plan Script — review before running", style="dim"))
            console.print()
            console.print(script)
            console.print()
            console.print(Rule("End of Plan Script", style="dim"))

    def render_held_for_cooldown(self, data: UpdatePlan) -> None:
        """List recommendations withheld because their target version is too young to move to.

        OSS IQ's cooldown and the package manager's release cutoff get separate tables: only the
        first is OSS IQ's call, and naming the wrong one sends the user to the wrong setting.
        """
        by_cooldown = [e for e in data.held_for_cooldown if e.held_by is None]
        by_package_manager = [e for e in data.held_for_cooldown if e.held_by is not None]

        if by_cooldown:
            console.print(f"[yellow]{HELP_PLAN_HELD_FOR_COOLDOWN_HEADER.format(days=data.cooldown_period)}[/yellow]")
            table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
            table.add_column("Package", style="bold")
            table.add_column("Current", style="red")
            table.add_column("Recommended", style="green")
            table.add_column("Age", style="dim")
            table.add_column("Type", style="dim")
            for entry in by_cooldown:
                dep_type = "direct" if entry.is_direct else "transitive"
                versions = (entry.current_version, entry.recommended_version)
                table.add_row(entry.display_name, *versions, age_cell(entry), dep_type)
            console.print(table)
            console.print()

        if by_package_manager:
            header = HELP_PLAN_HELD_BY_PACKAGE_MANAGER_HEADER.format(setting=by_package_manager[0].held_by)
            console.print(f"[yellow]{header}[/yellow]")
            table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
            table.add_column("Package", style="bold")
            table.add_column("Current", style="red")
            table.add_column("Waiting on", style="green")
            table.add_column("Age", style="dim")
            table.add_column("Cutoff", style="dim")
            for entry in by_package_manager:
                cutoff = format_cutoff(entry.held_cutoff) if entry.held_cutoff is not None else "—"
                versions = (entry.current_version, entry.recommended_version)
                table.add_row(entry.display_name, *versions, age_cell(entry), cutoff)
            console.print(table)
            console.print()

    def render_held_for_widening(self, data: UpdatePlan) -> None:
        """List recommendations withheld because reaching them requires widening the declared range."""
        if not data.held_for_widening:
            return

        console.print(f"[yellow]{HELP_PLAN_HELD_FOR_WIDENING_HEADER}[/yellow]")
        table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
        table.add_column("Package", style="bold")
        table.add_column("Current", style="red")
        table.add_column("Declared", style="dim")
        table.add_column("Reachable", style="green")
        table.add_column("Scope", style="dim")
        table.add_column("Type", style="dim")
        for entry in data.held_for_widening:
            dep_type = "direct" if entry.is_direct else "transitive"
            scope = rung_scope_label(entry.from_rung)
            table.add_row(
                entry.display_name,
                entry.current_version,
                entry.version_defined or "—",
                entry.recommended_version,
                scope,
                dep_type,
            )
        console.print(table)
        console.print()

    def render_held_by_user_overrides(self, data: UpdatePlan) -> None:
        """List the overrides the user wrote that kept an update out of the plan."""
        if not data.held_by_user_overrides:
            return

        console.print(f"[yellow]{HELP_PLAN_HELD_BY_USER_OVERRIDES_HEADER}[/yellow]")
        table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
        table.add_column("Override", style="bold")
        table.add_column("Forces", style="green")
        table.add_column("Declared in", style="dim")
        table.add_column("Keeps back", style="dim")
        for hold in data.held_by_user_overrides:
            name = f"{hold.package}@{hold.key}" if hold.key else hold.package
            table.add_row(name, hold.value, hold.source_file or "—", ", ".join(hold.blocked))
        console.print(table)
        console.print()

    def render_held_by_peers(self, data: UpdatePlan) -> None:
        """List the packages whose newer release an installed package's peer range rules out."""
        if not data.held_by_peers:
            return

        console.print(f"[yellow]{HELP_PLAN_HELD_BY_PEERS_HEADER}[/yellow]")
        table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
        table.add_column("Package", style="bold")
        table.add_column("Refused", style="green")
        table.add_column("Peer-required by", style="dim")
        table.add_column("Range", style="dim")
        for hold in data.held_by_peers:
            requirer = f"{hold.requirer} (+{hold.others} more)" if hold.others else hold.requirer
            table.add_row(hold.package, hold.blocked_version, requirer, hold.spec)
        console.print(table)
        console.print()

    def render_peer_repairs(self, data: UpdatePlan) -> None:
        """List the peers the plan puts back in reach, and the family copies that move with them."""
        if not data.peer_repairs:
            return

        console.print(f"[yellow]{HELP_PLAN_PEER_REPAIRS_HEADER}[/yellow]")
        table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
        table.add_column("Adds", style="bold")
        table.add_column("As", style="green")
        table.add_column("For", style="dim")
        table.add_column("Family moved", style="dim")
        for repair in data.peer_repairs:
            section = "devDependency" if repair.is_dev else "dependency"
            count = len(repair.family_moves)
            moved = f"{count} stale cop{'y' if count == 1 else 'ies'}" if count else "—"
            table.add_row(f"{repair.package} {repair.spec}", section, ", ".join(repair.requirers), moved)
        console.print(table)
        console.print()
