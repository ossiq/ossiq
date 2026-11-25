"""Console renderer for the plan command."""

from rich.console import Console
from rich.rule import Rule
from rich.table import Table

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.domain.update_plan import UpdateEntry, UpdatePlan
from ossiq.messages import (
    HELP_PLAN_CONVERGENCE_NOTICE,
    HELP_PLAN_CVE_BYPASS_NOTE,
    HELP_PLAN_KNOWN_BREAK_NOTE,
    HELP_PLAN_PASS_HEADER,
    HELP_PLAN_PASS_ORDER,
    HELP_PLAN_PASS_UNRESOLVED,
    HELP_PLAN_PASSES_NOTICE,
    HELP_PLAN_PEER_REPAIRS_HEADER,
)
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer
from ossiq.ui.renderers.impact_utils import impact_sub_row_texts
from ossiq.ui.renderers.upgrade.plan_notes import (
    age_cell,
    new_dependency_impacts,
    render_forced_warning,
    render_higher_tier_footer,
    render_holds,
    render_new_dependencies,
)

console = Console()


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
            + (f"  |  Install passes: [bold]{data.pass_count}[/bold]" if data.pass_count > 1 else "")
        )
        console.print()

        if data.all_entries:
            table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
            table.add_column("Package", style="bold")
            table.add_column("Current", style="red")
            table.add_column("Recommended", style="green")
            table.add_column("Age", style="dim")
            table.add_column("Type", style="dim")

            for number in range(1, data.pass_count + 1):
                if data.pass_count > 1:
                    header = HELP_PLAN_PASS_HEADER.format(number=number, total=data.pass_count)
                    table.add_row(f"[bold]{header}[/bold]", "", "", "", "")
                for entry in data.all_entries:
                    if entry.install_pass == number:
                        self.add_entry_rows(table, entry, data)

            console.print(table)
            console.print()

            render_forced_warning(console, data)
            render_new_dependencies(console, data)

            if data.pass_count > 1:
                console.print(f"[dim]{HELP_PLAN_PASSES_NOTICE.format(total=data.pass_count)}[/dim]")
                console.print()

            if data.transitive_entries or new_dependency_impacts(data):
                console.print(f"[dim]{HELP_PLAN_CONVERGENCE_NOTICE}[/dim]")
                console.print()

        render_holds(console, data)
        self.render_peer_repairs(data)

        if script:
            console.print(Rule("Plan Script — review before running", style="dim"))
            console.print()
            console.print(script)
            console.print()
            console.print(Rule("End of Plan Script", style="dim"))

        render_higher_tier_footer(console, data)

    @staticmethod
    def add_entry_rows(table: Table, entry: UpdateEntry, data: UpdatePlan) -> None:
        """One entry's row, then its notes: known break, cooldown bypass, install order, transitive impacts."""
        dep_type = "[yellow]forced[/yellow]" if entry.is_forced else "direct" if entry.is_direct else "transitive"
        table.add_row(
            package_cell_text(entry), entry.current_version, entry.recommended_version, age_cell(entry), dep_type
        )
        if entry.carries_known_break:
            table.add_row(f"[yellow]  {HELP_PLAN_KNOWN_BREAK_NOTE}[/yellow]", "", "", "", "")
        if is_cooldown_bypassed(entry, data.cooldown_period):
            table.add_row(f"[dim]  {HELP_PLAN_CVE_BYPASS_NOTE}[/dim]", "", "", "", "")
        for ordering in data.pass_orderings:
            if ordering.requirer_key != entry.move_key:
                continue
            if ordering.honoured:
                note = HELP_PLAN_PASS_ORDER.format(
                    peer=ordering.peer,
                    peer_version=ordering.peer_version,
                    requirer=ordering.requirer,
                    requirer_version=ordering.requirer_version,
                    spec=ordering.spec,
                )
                table.add_row(f"[dim]  ↳ {note}[/dim]", "", "", "", "")
            else:
                warning = HELP_PLAN_PASS_UNRESOLVED.format(requirer=ordering.requirer, peer=ordering.peer)
                table.add_row(f"[yellow]  {warning}[/yellow]", "", "", "", "")
        # Transitive entries carry the family moves of their own pick, which the table never listed.
        if entry.is_direct:
            for text in impact_sub_row_texts(entry.transitive_impacts):
                table.add_row(text, "", "", "", "")

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
