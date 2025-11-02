"""
View for overview command/Console output type
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from update_burden.service.project import ProjectOverviewSummary

console = Console()


def display_view(project_overview: ProjectOverviewSummary):
    table = Table(title="Python Package Version Status",
                  title_style="bold cyan")

    table.add_column("Dependency", justify="left", style="bold cyan")
    table.add_column("Installed", justify="center")
    table.add_column("Latest", justify="center")
    table.add_column("Days Behind", justify="right")
    table.add_column("Production?", justify="center")

    production_dependencies = sorted([
        pkg for pkg in project_overview.installed_packages_overview
        if not pkg.is_dev_dependency
    ], key=lambda pkg: pkg.package_name)

    dev_dependencies = sorted([
        pkg for pkg in project_overview.installed_packages_overview
        if pkg.is_dev_dependency
    ], key=lambda pkg: pkg.package_name)

    for pkg in production_dependencies:
        table.add_row(
            pkg.package_name,
            pkg.installed_version,
            pkg.latest_version,
            str(pkg.lag_days),
            "✅ yes"
        )

    if dev_dependencies:
        table.add_section()

    for pkg in dev_dependencies:
        table.add_row(
            pkg.package_name,
            pkg.installed_version,
            pkg.latest_version,
            str(pkg.lag_days),
            "❌ no"
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
