"""
View for overview command/Console output type
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ossiq.domain.version import (
    VERSION_DIFF_BUILD,
    VERSION_DIFF_MAJOR,
    VERSION_DIFF_MINOR,
    VERSION_DIFF_PATCH,
    VERSION_DIFF_PRERELEASE,
    VERSION_LATEST,
    VersionsDifference,
    difference_versions,
)
from ossiq.service.project import ProjectOverviewRecord, ProjectOverviewSummary
from ossiq.timeutil import format_time_days

console = Console()


def _format_time_delta(days: int | None, lag_threshold_days: int) -> str:
    """
    Formats a number of days into a human-readable string (e.g., "2y", "1y", "8m", "3w", "5d").
    """
    if days is None:
        return "N/A"

    # Determine the formatted string and apply highlighting if needed
    formatted_string = format_time_days(days)

    return f"[bold red]{formatted_string}" if days >= lag_threshold_days else formatted_string


def _format_lag_status(vdiff: VersionsDifference) -> str:
    """
    Format lag status into human readable string with color coding
    """
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


def table_factory(
    title: str, title_style: str, dependencies: list[ProjectOverviewRecord], lag_threshold_days: int
) -> Table:
    """
    Product records for the table
    """
    table = Table(title=title, title_style=title_style)
    table.add_column("Dependency", justify="left", style="bold cyan")
    table.add_column("CVEs", justify="center")
    table.add_column("Lag Status", justify="center")
    table.add_column("Installed", justify="left")
    table.add_column("Latest", justify="left")
    table.add_column("Release Lag", justify="right")
    table.add_column("Time Lag", justify="right")

    for pkg in dependencies:
        vdiff = difference_versions(pkg.installed_version, pkg.latest_version)
        table.add_row(
            pkg.package_name,
            f"[bold][red]{len(pkg.cve)}" if pkg.cve else "",
            _format_lag_status(vdiff),
            pkg.installed_version,
            pkg.latest_version if pkg.latest_version else "[bold][red]N/A",
            str(pkg.releases_lag),
            _format_time_delta(pkg.time_lag_days, lag_threshold_days),
        )

    return table


def display_view(project_overview: ProjectOverviewSummary, lag_threshold_days: int, **_):
    """
    Representation of the project overview for Console.
    """

    table_dev = None

    table_prod = table_factory(
        "Production Packages Version Status", "bold green", project_overview.production_packages, lag_threshold_days
    )

    if project_overview.development_packages:
        table_dev = table_factory(
            "Development Packages Version Status",
            "bold cyan",
            project_overview.development_packages,
            lag_threshold_days,
        )

    header_text = Text()
    header_text.append("📦 Project: ", style="bold white")
    header_text.append(f"{project_overview.project_name}\n", style="bold cyan")
    header_text.append("🔗 Packages Registry: ", style="bold white")
    header_text.append(f"{project_overview.packages_registry}\n", style="green")
    header_text.append("📍 Project Path: ", style="bold white")
    header_text.append(f"{project_overview.project_path}", style="green")

    console.print("\n")
    console.print(Panel(header_text, expand=False, border_style="cyan"))
    console.print("\n")
    console.print(table_prod)

    if table_dev:
        console.print("\n")
        console.print(table_dev)
