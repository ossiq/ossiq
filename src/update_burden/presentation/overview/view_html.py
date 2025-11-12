"""
View for overview command for HTML view
"""

from jinja2 import ChoiceLoader, Environment, FileSystemLoader, PackageLoader, select_autoescape
from rich.console import Console
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

    return f"<strong class=\"text-red-100 dark:text-red-500\">{formatted_string}</strong>" if days >= lag_threshold_days else formatted_string


def display_view(project_overview: ProjectOverviewSummary,
                 lag_threshold_days: int,
                 output_destination="."):
    """
    Representation of the project overview for HTML renderer.
    """

    env = Environment(
        loader=ChoiceLoader([
            PackageLoader("update_burden",
                          package_path="./presentation/html_templates"),
            PackageLoader(
                "update_burden", package_path="./presentation/overview/html_templates")
        ]),
        autoescape=select_autoescape()
    )

    template = env.get_template("main.html")

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

    rendered_html = template.render(
        project_overview=project_overview,
        lag_threshold_days=lag_threshold_days,
        production_dependencies=production_dependencies,
        dev_dependencies=dev_dependencies,
        format_time_delta=_format_time_delta
    )

    env.filters['format_time_delta'] = _format_time_delta

    # Save the rendered HTML to a file
    with open("overview_report.html", "w", encoding="utf-8") as fh:
        fh.write(rendered_html)
