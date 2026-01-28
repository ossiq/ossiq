"""
HTML renderer for scan command.
Migrated from presentation/scan/view_html.py
"""

import datetime
import os

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.domain.exceptions import DestinationDoesntExist
from ossiq.domain.project import normalize_filename
from ossiq.service.project import ProjectMetrics
from ossiq.ui.html.template_environment import configure_template_environment
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer


class HtmlScanRenderer(AbstractUserInterfaceRenderer):
    """HTML renderer for scan command."""

    command = Command.SCAN
    user_interface_type = UserInterfaceType.HTML

    @staticmethod
    def supports(command: Command, user_interface_type: UserInterfaceType) -> bool:
        """Check if this renderer handles scan/html combination."""
        return command == Command.SCAN and user_interface_type == UserInterfaceType.HTML

    def render(self, data: ProjectMetrics, **kwargs) -> None:
        """
        Render project metrics to HTML file.

        Args:
            data: ProjectMetrics from scan service
            **kwargs: Rendering options
                - lag_threshold_days: int - Threshold for highlighting time lag
                - destination: str - Output file path (supports {project_name} placeholder)

        Raises:
            DestinationDoesntExist: If destination directory doesn't exist
        """
        lag_threshold_days = kwargs.get("lag_threshold_days", 180)
        destination = kwargs.get("destination", ".")
        # Validate destination directory (fixed edge case: empty dirname)
        dest_dir = os.path.dirname(destination)
        if dest_dir and not os.path.exists(dest_dir):
            raise DestinationDoesntExist(f"Destination `{destination}` doesn't exist.")

        # Configure Jinja2 environment and load template
        _, template = configure_template_environment("ui/renderers/scan/html_templates/main.html")

        # Render template
        rendered_html = template.render(
            project_scan=data,
            lag_threshold_days=lag_threshold_days,
            dependencies=data.production_packages + data.optional_packages,
            now=datetime.datetime.now(datetime.UTC),
        )

        # Resolve output path with project name placeholder
        target_path = destination.format(
            project_name=normalize_filename(data.project_name),
        )

        # Write HTML to file
        with open(target_path, "w", encoding="utf-8") as fh:
            fh.write(rendered_html)
