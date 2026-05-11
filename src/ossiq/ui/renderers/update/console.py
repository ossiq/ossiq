"""Console renderer for the update command."""

from rich.console import Console
from rich.rule import Rule
from rich.table import Table

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.service.update import UpdatePlan
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer

console = Console()


class ConsoleUpdateRenderer(AbstractUserInterfaceRenderer):
    """Renders the update plan as a summary table followed by a bash script block."""

    command = Command.UPDATE
    user_interface_type = UserInterfaceType.CONSOLE

    @staticmethod
    def supports(command: Command, user_interface_type: UserInterfaceType) -> bool:
        return command == Command.UPDATE and user_interface_type == UserInterfaceType.CONSOLE

    def render(self, data: UpdatePlan, script: str = "", **kwargs) -> None:
        console.print()
        console.print(Rule(f"OSS IQ — Update Plan: {data.project_name}", style="bold cyan"))
        console.print(
            f"  Package Manager: [bold]{data.package_manager_name}[/bold]  |  "
            f"Direct: [bold green]{len(data.direct_entries)}[/bold green]  |  "
            f"Transitive: [bold yellow]{len(data.transitive_entries)}[/bold yellow]"
        )
        console.print()

        if data.all_entries:
            table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
            table.add_column("Package")
            table.add_column("Current", style="red")
            table.add_column("Recommended", style="green")
            table.add_column("Age", style="dim")
            table.add_column("Type", style="dim")

            for entry in data.direct_entries:
                age = f"{entry.reason.age_days}d" if entry.reason and entry.reason.age_days is not None else "—"
                table.add_row(entry.package_name, entry.current_version, entry.recommended_version, age, "direct")
            for entry in data.transitive_entries:
                age = f"{entry.reason.age_days}d" if entry.reason and entry.reason.age_days is not None else "—"
                table.add_row(entry.package_name, entry.current_version, entry.recommended_version, age, "transitive")

            console.print(table)
            console.print()

        if script:
            console.print(Rule("Update Script — review before running", style="bold yellow"))
            console.print()
            console.print(script)
            console.print()
            console.print(Rule("End of Update Script", style="dim"))
