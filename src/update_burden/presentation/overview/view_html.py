"""
View for overview command for HTML view
"""

import os
from update_burden.domain.exceptions import DestinationDoesntExist
from update_burden.presentation.html.template_environment import (
    configure_template_environment,
)
from update_burden.service.project import ProjectOverviewSummary


def display_view(project_overview: ProjectOverviewSummary,
                 lag_threshold_days: int,
                 output_destination="."):
    """
    Representation of the project overview for HTML renderer.
    """

    # Make sure we can write to the destination
    if not os.path.exists(output_destination):
        raise DestinationDoesntExist(
            f"Destination `{output_destination}` doesn't exist.")

    _, template = configure_template_environment(
        "./presentation/overview/html_templates/main.html"
    )

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
        dev_dependencies=dev_dependencies
    )

    target_path = os.path.join(output_destination, "overview_report.html")

    # Save the rendered HTML to a file
    with open(target_path, "w", encoding="utf-8") as fh:
        fh.write(rendered_html)
