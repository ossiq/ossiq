"""
HTML renderer for scan command.
Migrated from presentation/scan/view_html.py
"""

import os

from ossiq.domain.common import Command, PresentationType
from ossiq.domain.exceptions import DestinationDoesntExist
from ossiq.domain.project import normalize_filename
from ossiq.presentation.html.template_environment import configure_template_environment
from ossiq.presentation.interfaces import AbstractPresentationRenderer
from ossiq.service.project import ProjectMetrics


class HtmlScanRenderer(AbstractPresentationRenderer):
    """HTML renderer for scan command."""

    command = Command.SCAN
    presentation_type = PresentationType.HTML

    @staticmethod
    def supports(command: Command, presentation_type: PresentationType) -> bool:
        """Check if this renderer handles scan/html combination."""
        return command == Command.SCAN and presentation_type == PresentationType.HTML

    def render(self, data: ProjectMetrics, **kwargs) -> None:  # type: ignore[override]
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
        # Use module_file parameter for robust path resolution
        _, template = configure_template_environment(
            "html_templates/main.html",
            module_file=__file__
        )

        # Render template
        rendered_html = template.render(
            project_scan=data,
            lag_threshold_days=lag_threshold_days,
            dependencies=data.production_packages + data.development_packages,
        )

        # Resolve output path with project name placeholder
        target_path = destination.format(
            project_name=normalize_filename(data.project_name),
        )

        # Write HTML to file
        with open(target_path, "w", encoding="utf-8") as fh:
            fh.write(rendered_html)
