"""
Schema registry for export formats.

Maps each (schema version, profile) pair to its JSON schema file.
This allows for version-specific validation and evolution of the export format.
"""

import json
from pathlib import Path
from typing import ClassVar

from ossiq.domain.common import ExportJsonSchemaVersion, ExportProfile


class SchemaRegistry:
    """Registry mapping schema versions and export profiles to JSON schema files."""

    # One file per (version, profile): the standard profile is a projection of the full one, with a
    # schema of its own so a leaked full-only field fails validation instead of passing unnoticed.
    SCHEMA_FILES: ClassVar[dict[tuple[ExportJsonSchemaVersion, ExportProfile], str]] = {
        (ExportJsonSchemaVersion.V1_5, ExportProfile.FULL): "export_schema_v1.5.json",
        (ExportJsonSchemaVersion.V1_5, ExportProfile.STANDARD): "export_schema_v1.5_standard.json",
    }

    schemas_dir: Path

    def __init__(self):
        """Initialize schema registry with path to schemas directory."""
        self.schemas_dir = Path(__file__).parent / "schemas"

    def get_schema_path(self, version: ExportJsonSchemaVersion, profile: ExportProfile = ExportProfile.FULL) -> Path:
        """
        Get the path to the JSON schema file for a given version and profile.
        """
        if (version, profile) not in self.SCHEMA_FILES:
            raise ValueError(f"No schema file registered for version {version.value}, profile {profile.value}")

        return self.schemas_dir / self.SCHEMA_FILES[(version, profile)]

    def load_schema(self, version: ExportJsonSchemaVersion, profile: ExportProfile = ExportProfile.FULL) -> dict:
        """
        Load and parse the JSON schema for a given version and profile.
        """
        schema_path = self.get_schema_path(version, profile)

        if not schema_path.exists():
            raise FileNotFoundError(f"Schema file not found: {schema_path}")

        with open(schema_path, encoding="utf-8") as f:
            return json.load(f)

    def get_latest_version(self) -> ExportJsonSchemaVersion:
        """
        Get the latest supported schema version.
        """
        return ExportJsonSchemaVersion.V1_5

    def list_versions(self) -> list[ExportJsonSchemaVersion]:
        """
        List all registered schema versions.

        Returns:
            List of supported schema versions, each once whatever its profiles
        """
        return list(dict.fromkeys(version for version, _ in self.SCHEMA_FILES))


# Global registry instance
json_schema_registry = SchemaRegistry()
