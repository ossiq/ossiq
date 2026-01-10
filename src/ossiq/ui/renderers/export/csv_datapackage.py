"""
Frictionless Data Package generation utilities.

This module provides functions to generate Tabular Data Package descriptors
conforming to the Frictionless Data Package specification.

These utilities are primarily used in tests to validate that exported CSV files
conform to the Frictionless Data Package standard.
"""

import json
from pathlib import Path
from typing import Any

from frictionless import validate

from ossiq.domain.common import ExportCsvSchemaVersion
from ossiq.ui.renderers.export.csv_schema_registry import csv_schema_registry
from ossiq.ui.renderers.export.models import ExportData


def generate_datapackage_descriptor(
    export_data: ExportData,
    schema_version: ExportCsvSchemaVersion = ExportCsvSchemaVersion.V1_0,
) -> dict[str, Any]:
    """
    Generate a Tabular Data Package descriptor (datapackage.json).

    Args:
        export_data: Export data model with project metadata
        schema_version: Schema version to use

    Returns:
        Dictionary representing datapackage.json structure

    Example:
        >>> descriptor = generate_datapackage_descriptor(
        ...     export_data,
        ...     ExportCsvSchemaVersion.V1_0
        ... )
        >>> with open("/output/datapackage.json", "w") as f:
        ...     json.dump(descriptor, f, indent=2)
    """
    project_name = export_data.project.name

    # Load schemas
    summary_schema = csv_schema_registry.load_schema(schema_version, "summary")
    packages_schema = csv_schema_registry.load_schema(schema_version, "packages")
    cves_schema = csv_schema_registry.load_schema(schema_version, "cves")

    return {
        "profile": "tabular-data-package",
        "name": f"ossiq-export-{project_name}",
        "title": f"OSS IQ Export: {project_name}",
        "description": (
            f"Dependency risk analysis export for {project_name} ({export_data.project.registry} ecosystem)"
        ),
        "version": schema_version.value,
        "created": export_data.metadata.export_timestamp.isoformat(),
        "keywords": ["ossiq", "dependency-analysis", "security", "cve", export_data.project.registry],
        "licenses": [
            {
                "name": "AGPL-3.0-only",
                "path": "https://www.gnu.org/licenses/agpl-3.0.html",
                "title": "GNU Affero General Public License v3.0",
            }
        ],
        "resources": [
            {
                "profile": "tabular-data-resource",
                "name": "summary",
                "path": "summary.csv",
                "title": "Project Summary",
                "description": "Project metadata and aggregate statistics",
                "schema": summary_schema,
                "encoding": "utf-8-sig",
                "format": "csv",
            },
            {
                "profile": "tabular-data-resource",
                "name": "packages",
                "path": "packages.csv",
                "title": "Package Metrics",
                "description": "Dependency metrics with version lag and CVE counts",
                "schema": packages_schema,
                "encoding": "utf-8-sig",
                "format": "csv",
            },
            {
                "profile": "tabular-data-resource",
                "name": "cves",
                "path": "cves.csv",
                "title": "CVE Details",
                "description": "Detailed vulnerability information for all affected packages",
                "schema": cves_schema,
                "encoding": "utf-8-sig",
                "format": "csv",
            },
        ],
    }


def write_datapackage(
    output_dir: Path,
    export_data: ExportData,
    schema_version: ExportCsvSchemaVersion = ExportCsvSchemaVersion.V1_0,
) -> Path:
    """
    Write datapackage.json descriptor to disk.

    Args:
        output_dir: Directory where datapackage.json will be written
        export_data: Export data model with project metadata
        schema_version: Schema version to use

    Returns:
        Path to written datapackage.json file

    Example:
        >>> datapackage_path = write_datapackage(
        ...     Path("/output"),
        ...     export_data
        ... )
    """
    # Generate descriptor
    descriptor = generate_datapackage_descriptor(export_data, schema_version)

    # Write to file
    datapackage_path = output_dir / "datapackage.json"
    with open(datapackage_path, "w", encoding="utf-8") as f:
        json.dump(descriptor, f, indent=2, ensure_ascii=False)

    return datapackage_path


def validate_datapackage(datapackage_path: Path) -> tuple[bool, list[str]]:
    """
    Validate a complete Tabular Data Package.

    Validates:
    1. datapackage.json structure
    2. All referenced CSV files exist
    3. CSV data conforms to schemas
    4. Foreign key relationships are satisfied

    Args:
        datapackage_path: Path to datapackage.json

    Returns:
        Tuple of (is_valid: bool, errors: list[str])

    Example:
        >>> is_valid, errors = validate_datapackage(Path("/output/datapackage.json"))
        >>> if not is_valid:
        ...     print(f"Package validation errors: {errors}")
    """
    errors = []

    try:
        # Validate using frictionless
        report = validate(str(datapackage_path), type="package")

        # Extract errors
        if not report.valid:
            for task in report.tasks:
                for error in task.errors:
                    errors.append(f"{error.type}: {error.message}")

    except FileNotFoundError:
        errors.append(f"Data package file not found: {datapackage_path}")

    return len(errors) == 0, errors
