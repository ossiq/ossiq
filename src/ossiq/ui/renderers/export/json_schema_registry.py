"""
Schema registry for export formats.

Maps schema versions to their corresponding JSON schema files.
This allows for version-specific validation and evolution of the export format.
"""

import json
from pathlib import Path
from typing import ClassVar

from ossiq.domain.common import ExportJsonSchemaVersion


class SchemaRegistry:
    """Registry mapping schema versions to JSON schema files."""

    # Map schema version to schema file name
    _SCHEMA_FILES: ClassVar[dict[ExportJsonSchemaVersion, str]] = {
        ExportJsonSchemaVersion.V1_0: "export_schema_v1.0.json",
        ExportJsonSchemaVersion.V1_1: "export_schema_v1.1.json",
        ExportJsonSchemaVersion.V1_2: "export_schema_v1.2.json",
        ExportJsonSchemaVersion.V1_3: "export_schema_v1.3.json",
        ExportJsonSchemaVersion.V1_4: "export_schema_v1.4.json",
    }

    _schemas_dir: Path

    def __init__(self):
        """Initialize schema registry with path to schemas directory."""
        self._schemas_dir = Path(__file__).parent / "schemas"

    def get_schema_path(self, version: ExportJsonSchemaVersion) -> Path:
        """
        Get the path to the JSON schema file for a given version.
        """
        if version not in self._SCHEMA_FILES:
            raise ValueError(f"No schema file registered for version {version.value}")

        return self._schemas_dir / self._SCHEMA_FILES[version]

    def load_schema(self, version: ExportJsonSchemaVersion) -> dict:
        """
        Load and parse the JSON schema for a given version.
        """
        schema_path = self.get_schema_path(version)

        if not schema_path.exists():
            raise FileNotFoundError(f"Schema file not found: {schema_path}")

        with open(schema_path, encoding="utf-8") as f:
            return json.load(f)

    def get_latest_version(self) -> ExportJsonSchemaVersion:
        """
        Get the latest supported schema version.
        """
        return ExportJsonSchemaVersion.V1_4

    def list_versions(self) -> list[ExportJsonSchemaVersion]:
        """
        List all registered schema versions.

        Returns:
            List of supported schema versions
        """
        return list(self._SCHEMA_FILES.keys())


# Global registry instance
json_schema_registry = SchemaRegistry()
