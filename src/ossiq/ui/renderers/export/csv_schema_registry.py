"""
CSV schema registry for Frictionless Table Schema validation.

Maps schema versions to their corresponding Table Schema files.
Uses frictionless-py for validation against Frictionless Data Package standards.
This allows for version-specific validation and evolution of the CSV export format.
"""

import json
from pathlib import Path
from typing import Any, ClassVar, Literal

from frictionless import Resource, Schema, extract

from ossiq.domain.common import ExportCsvSchemaVersion

SchemaType = Literal["summary", "packages", "cves"]


class CsvSchemaRegistry:
    """Registry mapping schema versions to Table Schema files with frictionless validation."""

    # Map schema version to schema file base names (JSON files)
    _SCHEMA_FILES: ClassVar[dict[ExportCsvSchemaVersion, dict[SchemaType, str]]] = {
        ExportCsvSchemaVersion.V1_0: {
            "summary": "summary-schema-v1.0.json",
            "packages": "packages-schema-v1.0.json",
            "cves": "cves-schema-v1.0.json",
        },
    }

    _schemas_dir: Path

    def __init__(self):
        """Initialize CSV schema registry with path to schemas directory."""
        self._schemas_dir = Path(__file__).parent / "schemas" / "csv"

    def get_schema_path(self, version: ExportCsvSchemaVersion, schema_type: SchemaType) -> Path:
        """
        Get the path to the Table Schema file for a given version and type.
        """
        if version not in self._SCHEMA_FILES:
            raise ValueError(f"No schema files registered for version {version.value}")

        if schema_type not in self._SCHEMA_FILES[version]:
            raise ValueError(
                f"Schema type '{schema_type}' not found for version {version.value}. "
                f"Available types: {list(self._SCHEMA_FILES[version].keys())}"
            )

        return self._schemas_dir / self._SCHEMA_FILES[version][schema_type]

    def load_schema(self, version: ExportCsvSchemaVersion, schema_type: SchemaType) -> dict[str, Any]:
        """
        Load the Table Schema content for a given version and type.
        """
        schema_path = self.get_schema_path(version, schema_type)

        if not schema_path.exists():
            raise FileNotFoundError(f"Schema file not found: {schema_path}")

        with open(schema_path, encoding="utf-8") as f:
            return json.load(f)

    def validate_schema(self, version: ExportCsvSchemaVersion, schema_type: SchemaType) -> tuple[bool, list[str]]:
        """
        Validate that the schema file itself conforms to Frictionless Table Schema spec.

        Args:
            version: Schema version to validate
            schema_type: Type of schema ('summary', 'packages', or 'cves')

        Returns:
            Tuple of (is_valid: bool, errors: list[str])
        """
        errors = []

        schema_dict = self.load_schema(version, schema_type)

        # Validate required fields exist and have proper structure
        if "fields" not in schema_dict:
            errors.append("Schema missing required 'fields' property")
            return False, errors

        for i, field in enumerate(schema_dict["fields"]):
            if "name" not in field:
                errors.append(f"Field {i} missing required 'name' property")
            if "type" not in field:
                errors.append(f"Field {field.get('name', i)} missing required 'type' property")

        # Try to create a Schema object - this validates the descriptor
        try:
            Schema.from_descriptor(schema_dict)
        except Exception as e:
            errors.append(f"Invalid schema descriptor: {e}")

        return len(errors) == 0, errors

    def validate_csv(
        self, csv_path: Path, version: ExportCsvSchemaVersion, schema_type: SchemaType
    ) -> tuple[bool, list[str]]:
        """
        Validate a CSV file against its Table Schema using frictionless-py.

        This method validates:
        1. Column headers match schema fields
        2. Data types conform to schema
        3. Constraints are satisfied (required, enum, min/max, etc.)

        Args:
            csv_path: Path to CSV file to validate
            version: Schema version to validate against
            schema_type: Type of schema ('summary', 'packages', or 'cves')

        Returns:
            Tuple of (is_valid: bool, errors: list[str])

        Example:
            >>> registry = CsvSchemaRegistry()
            >>> is_valid, errors = registry.validate_csv(
            ...     Path("export-summary.csv"),
            ...     ExportCsvSchemaVersion.V1_0,
            ...     "summary"
            ... )
            >>> if not is_valid:
            ...     print(f"Validation errors: {errors}")
        """
        errors = []

        schema_dict = self.load_schema(version, schema_type)
        schema = Schema.from_descriptor(schema_dict)

        # First, validate column headers match schema
        expected_fields = [field["name"] for field in schema_dict.get("fields", [])]
        with open(csv_path, encoding="utf-8-sig") as f:
            import csv as csv_module

            reader = csv_module.reader(f)
            try:
                actual_headers = next(reader)
            except StopIteration:
                actual_headers = []

        if actual_headers != expected_fields:
            errors.append(f"Column mismatch: expected {expected_fields}, got {actual_headers}")
            return False, errors

        # Read CSV file content and create an in-memory resource
        with open(csv_path, "rb") as f:
            csv_bytes = f.read()

        # Create resource from bytes to avoid path safety issues
        resource = Resource(data=csv_bytes, schema=schema, format="csv", encoding="utf-8-sig")

        # Validate the resource
        report = resource.validate()

        # Extract errors from validation report
        if not report.valid:
            # Helper to extract error info (handles both dict and object access)
            def extract_error_msg(error) -> str:
                try:
                    # Try dict access first (for some error types)
                    err_type = error["type"] if isinstance(error, dict) else getattr(error, "type", "unknown")
                    err_message = error["message"] if isinstance(error, dict) else getattr(error, "message", str(error))
                    row_num = error.get("rowNumber") if isinstance(error, dict) else getattr(error, "row_number", None)
                except (KeyError, TypeError):
                    return str(error)

                msg = f"{err_type}: {err_message}"
                if row_num is not None:
                    msg += f" (row {row_num})"
                return msg

            # Check top-level errors
            for error in report.errors:
                errors.append(extract_error_msg(error))

            # Check task-level errors (for resource validation)
            for task in report.tasks:
                for error in task.errors:
                    errors.append(extract_error_msg(error))

            # If still no errors but report is invalid, add a generic error
            if not errors:
                errors.append("CSV validation failed: Schema constraints not met")

        # Special validation: summary CSV should have exactly 1 row
        # Do this check even if report is not valid to catch all issues
        if schema_type == "summary":
            rows = extract(str(csv_path), encoding="utf-8-sig")
            if len(rows) != 1:
                errors.append(f"Summary CSV should have exactly 1 data row, found {len(rows)}")

        return len(errors) == 0, errors

    def get_latest_version(self) -> ExportCsvSchemaVersion:
        """
        Get the latest supported schema version.
        """
        return ExportCsvSchemaVersion.V1_0

    def list_versions(self) -> list[ExportCsvSchemaVersion]:
        """
        List all registered schema versions.
        """
        return list(self._SCHEMA_FILES.keys())

    def list_schema_types(self, version: ExportCsvSchemaVersion) -> list[str]:
        """
        List all schema types for a given version.
        """
        if version not in self._SCHEMA_FILES:
            raise ValueError(f"No schema files registered for version {version.value}")

        return list(self._SCHEMA_FILES[version].keys())


# Global registry instance
csv_schema_registry = CsvSchemaRegistry()
