"""
View for overview command/Console output type
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from update_burden.service.project import ProjectOverviewSummary

console = Console()


def _format_time_delta(days: int | None, lag_threshold_days: int) -> str:
    """
    Formats a number of days into a human-readable string (e.g., "2y", "1y", "8m", "3w", "5d").
    """

    if days is None:
        return "N/A"

    if days == 0:
        return "[bold][green]LATEST"

    # Determine the formatted string and apply highlighting if needed
    formatted_string = ""
    if days >= 365:
        years = round(days / 365)
        formatted_string = f"{years}y"
    elif days >= 30:
        months = round(days / 30)
        formatted_string = f"{months}m"
    elif days >= 7:
        weeks = round(days / 7)
        formatted_string = f"{weeks}w"
    else:
        formatted_string = f"{days}d"

    return f"[bold red]{formatted_string}" if days >= lag_threshold_days else formatted_string


def display_view(project_overview: ProjectOverviewSummary, lag_threshold_days: int):
    """
    Representation of the project overview for Console.
    """
    table = Table(title="Python Package Version Status",
                  title_style="bold cyan")

    table.add_column("Dependency", justify="left", style="bold cyan")
    table.add_column("Prod?", justify="center")
    table.add_column("Time Lag", justify="right")
    table.add_column("Installed", justify="center")
    table.add_column("Latest", justify="center")

    def sort_function(pkg):
        return (pkg.lag_days, pkg.package_name,)

    production_dependencies = sorted([
        pkg for pkg in project_overview.installed_packages_overview
        if not pkg.is_dev_dependency
    ], key=sort_function, reverse=True)

    dev_dependencies = sorted([
        pkg for pkg in project_overview.installed_packages_overview
        if pkg.is_dev_dependency
    ], key=sort_function, reverse=True)

    for pkg in production_dependencies:
        table.add_row(
            pkg.package_name,
            "Y",
            _format_time_delta(pkg.lag_days, lag_threshold_days),
            pkg.installed_version,
            pkg.latest_version,
        )

    if dev_dependencies:
        table.add_section()

    for pkg in dev_dependencies:
        table.add_row(
            pkg.package_name,
            "N",
            _format_time_delta(pkg.lag_days, lag_threshold_days),
            pkg.installed_version,
            pkg.latest_version
        )

    header_text = Text()
    header_text.append("📦 Project: ", style="bold white")
    header_text.append(f"{project_overview.project_name}\n", style="bold cyan")
    header_text.append("🔗 Packages Registry: ", style="bold white")
    header_text.append(
        f"{project_overview.packages_registry}\n", style="green")
    header_text.append("📍 Project Path: ", style="bold white")
    header_text.append(f"{project_overview.project_path}", style="green")

    console.print("\n")
    console.print(Panel(header_text, expand=False, border_style="cyan"))
    console.print("\n")
    console.print(table)
