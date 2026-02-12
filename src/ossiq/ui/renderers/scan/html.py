"""
HTML renderer for scan command.
Migrated from presentation/scan/view_html.py
"""

import os
from pathlib import Path

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.domain.exceptions import DestinationDoesntExist
from ossiq.domain.project import normalize_filename
from ossiq.service.project import ProjectMetrics
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer
from ossiq.ui.renderers.export.json_schema_registry import json_schema_registry
from ossiq.ui.renderers.export.models import ExportData


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
        Render project metrics to HTML file using Vue.js SPA.

        Args:
            data: ProjectMetrics from scan service
            **kwargs: Rendering options
                - destination: str - Output file path (supports {project_name} placeholder)

        Raises:
            DestinationDoesntExist: If destination directory doesn't exist
        """
        destination = kwargs.get("destination", ".")
        # Validate destination directory (fixed edge case: empty dirname)
        dest_dir = os.path.dirname(destination)
        if dest_dir and not os.path.exists(dest_dir):
            raise DestinationDoesntExist(f"Destination `{destination}` doesn't exist.")

        # Load pre-built SPA template
        spa_template_path = Path(__file__).parent.parent.parent / "html_templates" / "spa_app.html"
        spa_template = spa_template_path.read_text(encoding="utf-8")

        # Convert ProjectMetrics to ExportData (reuses JSON export logic)
        export_data = ExportData.from_project_metrics(
            data,
            schema_version=json_schema_registry.get_latest_version(),
        )

        # Serialize to JSON and inject into SPA template
        json_data = export_data.model_dump_json()
        rendered_html = spa_template.replace("__OSSIQ_REPORT_DATA__", json_data)

        # Resolve output path with project name placeholder
        target_path = destination.format(
            project_name=normalize_filename(data.project_name),
        )

        # Write HTML to file
        with open(target_path, "w", encoding="utf-8") as fh:
            fh.write(rendered_html)
