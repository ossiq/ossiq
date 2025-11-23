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
                 destination: str = "."):
    """
    Representation of the project overview for HTML renderer.
    """

    # Make sure we can write to the destination
    if not os.path.exists(destination):
        raise DestinationDoesntExist(
            f"Destination `{destination}` doesn't exist.")

    _, template = configure_template_environment(
        "./presentation/overview/html_templates/main.html"
    )

    rendered_html = template.render(
        project_overview=project_overview,
        lag_threshold_days=lag_threshold_days,
        dependencies=project_overview.production_packages +
        project_overview.development_packages,
    )

    target_path = os.path.join(destination, "overview_report.html")

    # Save the rendered HTML to a file
    with open(target_path, "w", encoding="utf-8") as fh:
        fh.write(rendered_html)
