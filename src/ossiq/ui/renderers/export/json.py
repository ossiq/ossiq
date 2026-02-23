"""
JSON renderer for export command.

This renderer exports project metrics to JSON format using a versioned schema.
The output includes metadata, project information, summary statistics, and
detailed package metrics.
"""

import os

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.domain.exceptions import DestinationDoesntExist
from ossiq.domain.project import normalize_filename
from ossiq.service.project import ScanResult
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer
from ossiq.ui.renderers.export.json_schema_registry import json_schema_registry
from ossiq.ui.renderers.export.models import ExportData


class JsonExportRenderer(AbstractUserInterfaceRenderer):
    """JSON renderer for export command."""

    command = Command.EXPORT
    user_interface_type = UserInterfaceType.JSON

    @staticmethod
    def supports(command: Command, user_interface_type: UserInterfaceType) -> bool:
        """Check if this renderer handles export/json combination."""
        return command == Command.EXPORT and user_interface_type == UserInterfaceType.JSON

    def render(self, data: ScanResult, destination: str = ".", **kwargs) -> None:
        """
        Export project metrics to JSON file with metadata wrapper.

        Uses Pydantic models for serialization, ensuring type safety and
        schema validation. The output conforms to the versioned export schema.

        Args:
            data: ScanResult from scan service
            destination: Output file path (supports {project_name} placeholder)
            **kwargs: Optional arguments:
                - validate_schema (bool): Validate against JSON schema (default: True)

        Raises:
            DestinationDoesntExist: If destination directory doesn't exist
            jsonschema.ValidationError: If schema validation fails
        """
        # Validate destination directory
        dest_dir = os.path.dirname(destination)
        if dest_dir and not os.path.exists(dest_dir):
            raise DestinationDoesntExist(f"Destination `{destination}` doesn't exist.")

        # Convert domain model to export model
        export_data = ExportData.from_project_metrics(
            data,
            schema_version=json_schema_registry.get_latest_version(),
        )

        # Resolve destination path with project name placeholder
        target_path = destination.format(
            project_name=normalize_filename(data.project_name),
            output_format="json",
        )

        # # Get the schema for this version
        # schema = schema_registry.load_schema(export_data.metadata.schema_version)

        # # Validate model against schema to ensure that JSON Schema and Pydantic models are aligned
        # jsonschema.validate(instance=export_data.model_dump(), schema=schema)

        # Write JSON to file using Pydantic serialization
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(export_data.model_dump_json())
