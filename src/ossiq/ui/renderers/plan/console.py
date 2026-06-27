"""Console renderer for the plan command."""

from rich.console import Console
from rich.rule import Rule
from rich.table import Table

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.messages import (
    HELP_PLAN_CONVERGENCE_NOTICE,
    HELP_PLAN_CVE_BYPASS_NOTE,
    HELP_PLAN_FORCED_WARNING,
    HELP_PLAN_HELD_FOR_COOLDOWN_HEADER,
    HELP_PLAN_NEW_DEP_FRESH_WARNING,
)
from ossiq.service.update import UpdateEntry, UpdatePlan
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer
from ossiq.ui.renderers.impact_utils import impact_sub_row_texts, is_fresh_new_dep, new_transitive_deps_table

console = Console()


def package_cell_text(entry: UpdateEntry) -> str:
    """Package cell with non-actionable (✗) and CVE markers applied."""
    text = entry.package_name if entry.is_actionable else f"[red]✗ {entry.package_name}[/red]"
    if entry.is_security:
        text = f"{text} [red]CVE[/red]"
    return text


def is_cooldown_bypassed(entry: UpdateEntry, cooldown_period: int) -> bool:
    """True when a CVE-driven recommendation is younger than the cooldown it bypassed."""
    if not entry.is_security or entry.reason is None or entry.reason.age_days is None:
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
                if is_cooldown_bypassed(entry, data.cooldown_period):
                    table.add_row(f"[dim]  {HELP_PLAN_CVE_BYPASS_NOTE}[/dim]", "", "", "", "")
                for text in impact_sub_row_texts(entry.transitive_impacts):
                    table.add_row(text, "", "", "", "")
            for entry in data.transitive_entries:
                age = f"{entry.reason.age_days}d" if entry.reason and entry.reason.age_days is not None else "—"
                dep_type = "[yellow]forced[/yellow]" if entry.is_forced else "transitive"
                table.add_row(package_cell_text(entry), entry.current_version, entry.recommended_version, age, dep_type)
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

        if script:
            console.print(Rule("Plan Script — review before running", style="dim"))
            console.print()
            console.print(script)
            console.print()
            console.print(Rule("End of Plan Script", style="dim"))

    def render_held_for_cooldown(self, data: UpdatePlan) -> None:
        """List recommendations withheld because their target version is younger than the cooldown."""
        if not data.held_for_cooldown:
            return

        console.print(f"[yellow]{HELP_PLAN_HELD_FOR_COOLDOWN_HEADER.format(days=data.cooldown_period)}[/yellow]")
        table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
        table.add_column("Package", style="bold")
        table.add_column("Current", style="red")
        table.add_column("Recommended", style="green")
        table.add_column("Age", style="dim")
        table.add_column("Type", style="dim")
        for entry in data.held_for_cooldown:
            age = f"{entry.reason.age_days}d" if entry.reason and entry.reason.age_days is not None else "—"
            dep_type = "direct" if entry.is_direct else "transitive"
            table.add_row(entry.package_name, entry.current_version, entry.recommended_version, age, dep_type)
        console.print(table)
        console.print()
