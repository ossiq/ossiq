"""
View for scan command for HTML view
"""

import os

from ossiq.domain.exceptions import DestinationDoesntExist
from ossiq.domain.project import normalize_filename
from ossiq.presentation.html.template_environment import (
    configure_template_environment,
)
from ossiq.service.project import ProjectMetrics


def display_view(project_scan: ProjectMetrics, lag_threshold_days: int, destination: str = "."):
    """
    Representation of the project scan for HTML renderer.
    """

    # Make sure we can write to the destination
    if not os.path.exists(os.path.dirname(destination)):
        raise DestinationDoesntExist(f"Destination `{destination}` doesn't exist.")

    _, template = configure_template_environment("./presentation/scan/html_templates/main.html")

    rendered_html = template.render(
        project_scan=project_scan,
        lag_threshold_days=lag_threshold_days,
        dependencies=project_scan.production_packages + project_scan.development_packages,
    )

    target_path = destination.format(
        project_name=normalize_filename(project_scan.project_name),
    )

    # Save the rendered HTML to a file
    with open(target_path, "w", encoding="utf-8") as fh:
        fh.write(rendered_html)
