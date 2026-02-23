"""
CSV renderer for export command.

This renderer exports project metrics to three separate CSV files:
- {base}-summary.csv: Metadata and aggregate statistics (1 row)
- {base}-packages.csv: Package metrics with CVE counts (1 row per package)
- {base}-cves.csv: Detailed CVE information (1 row per CVE)

The CSV structure follows Frictionless Table Schema specification for validation.
Schema files are located in src/ossiq/ui/renderers/export/schemas/csv/
"""

import csv
import json
import os
from pathlib import Path
from typing import Any, NamedTuple

from ossiq.domain.common import Command, ExportCsvSchemaVersion, UserInterfaceType
from ossiq.domain.exceptions import DestinationDoesntExist
from ossiq.domain.project import normalize_filename
from ossiq.service.project import ScanResult
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer
from ossiq.ui.renderers.export.csv_datapackage import generate_datapackage_descriptor
from ossiq.ui.renderers.export.csv_schema_registry import csv_schema_registry
from ossiq.ui.renderers.export.models import ExportData


class ExportPaths(NamedTuple):
    """Paths for CSV export output files."""

    target_directory: Path  # The output folder: export_{project_name}/
    summary_csv: Path  # target_directory / "summary.csv"
    packages_csv: Path  # target_directory / "packages.csv"
    cves_csv: Path  # target_directory / "cves.csv"
    datapackage_json: Path  # target_directory / "datapackage.json"


class CsvExportRenderer(AbstractUserInterfaceRenderer):
    """CSV renderer for export command."""

    command = Command.EXPORT
    user_interface_type = UserInterfaceType.CSV

    @staticmethod
    def supports(command: Command, user_interface_type: UserInterfaceType) -> bool:
        """Check if this renderer handles export/csv combination."""
        return command == Command.EXPORT and user_interface_type == UserInterfaceType.CSV

    def render(self, data: ScanResult, destination: str = ".", **kwargs) -> None:
        """
        Export project metrics to a folder containing CSV files and datapackage.json.

        Creates a folder with the following structure:
        - {base}/summary.csv: Project metadata and summary statistics
        - {base}/packages.csv: Package metrics (one row per package)
        - {base}/cves.csv: CVE details (one row per CVE)
        - {base}/datapackage.json: Frictionless Data Package descriptor

        Args:
            data: ScanResult from scan service
            destination: Output file path (supports {project_name} placeholder)

        Raises:
            DestinationDoesntExist: If destination parent directory doesn't exist

        Example:
            >>> renderer = CsvExportRenderer(settings)
            >>> renderer.render(
            ...     data=project_metrics,
            ...     destination="./reports/export_{project_name}.{output_format}"
            ... )
            # Creates folder: ./reports/export_my-project/
            # Containing: summary.csv, packages.csv, cves.csv, datapackage.json
        """
        # Validate destination directory
        dest_dir = os.path.dirname(destination)
        if dest_dir and not os.path.exists(dest_dir):
            raise DestinationDoesntExist(f"Destination `{destination}` doesn't exist.")

        # Convert domain model to export model
        export_data = ExportData.from_project_metrics(
            data,
            schema_version=csv_schema_registry.get_latest_version(),
        )

        # Resolve destination path with project name placeholder
        target_path = destination.format(
            project_name=normalize_filename(data.project_name),
            output_format="csv",
        )

        # Generate export paths
        export_paths = self._resolve_file_paths(target_path)

        # Create target directory
        export_paths.target_directory.mkdir(parents=True, exist_ok=True)

        # Write all three CSV files
        self._write_summary_csv(export_paths.summary_csv, export_data)
        self._write_packages_csv(export_paths.packages_csv, export_data)
        self._write_cves_csv(export_paths.cves_csv, export_data)

        # Generate and write datapackage.json
        self._write_datapackage(export_paths, export_data)

    def _resolve_file_paths(self, base_destination: str) -> ExportPaths:
        """
        Generate output directory and file paths from base destination.

        Args:
            base_destination: Resolved destination path (placeholders already replaced)

        Returns:
            ExportPaths with target_directory and all file paths within it

        Example:
            >>> paths = self._resolve_file_paths("./export_my-project.csv")
            >>> paths.target_directory
            Path('./export_my-project')
            >>> paths.summary_csv
            Path('./export_my-project/summary.csv')
        """
        base_path = Path(base_destination)
        parent_dir = base_path.parent
        stem = base_path.stem  # e.g., "export_my-project"

        # Create target directory path: ./export_my-project/
        target_directory = parent_dir / stem

        return ExportPaths(
            target_directory=target_directory,
            summary_csv=target_directory / "summary.csv",
            packages_csv=target_directory / "packages.csv",
            cves_csv=target_directory / "cves.csv",
            datapackage_json=target_directory / "datapackage.json",
        )

    def _write_summary_csv(self, file_path: Path, export_data: ExportData) -> None:
        """
        Write summary CSV with metadata and aggregate statistics.

        Creates a single-row CSV containing project metadata and summary stats.

        Args:
            file_path: Output file path for summary CSV
            export_data: Export data model with metadata, project, and summary
        """
        fieldnames = [
            "schema_version",
            "export_timestamp",
            "project_name",
            "project_path",
            "project_registry",
            "total_packages",
            "production_packages",
            "development_packages",
            "packages_with_cves",
            "total_cves",
            "packages_outdated",
        ]

        # Create single row with all summary data
        # Get schema version value (enums have .value, literal "N/A" is already a string)
        schema_version = export_data.metadata.schema_version
        schema_version_str = schema_version.value
        row = {
            "schema_version": schema_version_str,
            # Format timestamp to match schema: %Y-%m-%dT%H:%M:%S (no microseconds/timezone)
            "export_timestamp": export_data.metadata.export_timestamp.strftime("%Y-%m-%dT%H:%M:%S"),
            "project_name": export_data.project.name,
            "project_path": export_data.project.path,
            "project_registry": export_data.project.registry.lower(),
            "total_packages": export_data.summary.total_packages,
            "production_packages": export_data.summary.production_packages,
            "development_packages": export_data.summary.development_packages,
            "packages_with_cves": export_data.summary.packages_with_cves,
            "total_cves": export_data.summary.total_cves,
            "packages_outdated": export_data.summary.packages_outdated,
        }

        # Write CSV with UTF-8 BOM for Excel compatibility
        with open(file_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=fieldnames,
                quoting=csv.QUOTE_ALL,
                lineterminator="\r\n",
            )
            writer.writeheader()
            writer.writerow(row)

    def _write_packages_csv(self, file_path: Path, export_data: ExportData) -> None:
        """
        Write packages CSV with package metrics and CVE counts.

        Creates one row per package (production + development) with aggregated CVE count.

        Args:
            file_path: Output file path for packages CSV
            export_data: Export data model with production and development packages
        """
        fieldnames = [
            "package_name",
            "dependency_type",
            "is_optional_dependency",
            "installed_version",
            "latest_version",
            "time_lag_days",
            "releases_lag",
            "cve_count",
        ]

        # Generate rows for all packages
        rows = []

        # Production packages
        for pkg in export_data.production_packages:
            rows.append(
                {
                    "package_name": pkg.package_name,
                    "dependency_type": "development" if pkg.is_optional_dependency else "production",
                    "is_optional_dependency": self._serialize_bool(pkg.is_optional_dependency),
                    "installed_version": pkg.installed_version,
                    "latest_version": self._serialize_optional(pkg.latest_version),
                    "time_lag_days": self._serialize_optional(pkg.time_lag_days),
                    "releases_lag": self._serialize_optional(pkg.releases_lag),
                    "cve_count": len(pkg.cve),
                }
            )

        # Development packages
        for pkg in export_data.development_packages:
            rows.append(
                {
                    "package_name": pkg.package_name,
                    "dependency_type": "development" if pkg.is_optional_dependency else "production",
                    "is_optional_dependency": self._serialize_bool(pkg.is_optional_dependency),
                    "installed_version": pkg.installed_version,
                    "latest_version": self._serialize_optional(pkg.latest_version),
                    "time_lag_days": self._serialize_optional(pkg.time_lag_days),
                    "releases_lag": self._serialize_optional(pkg.releases_lag),
                    "cve_count": len(pkg.cve),
                }
            )

        # Write CSV with UTF-8 BOM for Excel compatibility
        with open(file_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

    def _write_cves_csv(self, file_path: Path, export_data: ExportData) -> None:
        """
        Write CVEs CSV with detailed vulnerability information.

        Creates one row per CVE with package_name as foreign key to link back to packages.

        Args:
            file_path: Output file path for CVEs CSV
            export_data: Export data model with production and development packages
        """
        fieldnames = [
            "cve_id",
            "package_name",
            "package_registry",
            "source",
            "severity",
            "summary",
            "affected_versions",
            "all_cve_ids",
            "published",
            "link",
        ]

        # Generate rows for all CVEs from all packages
        rows = []

        # Process production packages
        for pkg in export_data.production_packages:
            for cve in pkg.cve:
                rows.append(
                    {
                        "cve_id": cve.id,
                        "package_name": cve.package_name,
                        "package_registry": cve.package_registry.lower(),
                        "source": cve.source,
                        "severity": cve.severity.value,
                        "summary": cve.summary,
                        "affected_versions": self._serialize_list(cve.affected_versions),
                        "all_cve_ids": self._serialize_list(cve.cve_ids),
                        "published": self._serialize_datetime(cve.published),
                        "link": cve.link,
                    }
                )

        # Process development packages
        for pkg in export_data.development_packages:
            for cve in pkg.cve:
                rows.append(
                    {
                        "cve_id": cve.id,
                        "package_name": cve.package_name,
                        "package_registry": cve.package_registry.lower(),
                        "source": cve.source,
                        "severity": cve.severity.value,
                        "summary": cve.summary,
                        "affected_versions": self._serialize_list(cve.affected_versions),
                        "all_cve_ids": self._serialize_list(cve.cve_ids),
                        "published": self._serialize_datetime(cve.published),
                        "link": cve.link,
                    }
                )

        # Write CSV with UTF-8 BOM for Excel compatibility
        with open(file_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

    def _write_datapackage(self, export_paths: ExportPaths, export_data: ExportData) -> None:
        """
        Generate and write Frictionless Data Package descriptor.

        Args:
            export_paths: ExportPaths with target directory and file paths
            export_data: Export data model with metadata for descriptor
        """

        schema_version = export_data.metadata.schema_version

        if not isinstance(schema_version, ExportCsvSchemaVersion):
            raise TypeError(f"CSV export requires ExportCsvSchemaVersion, got {schema_version}")

        descriptor = generate_datapackage_descriptor(export_data, schema_version)

        with open(export_paths.datapackage_json, "w", encoding="utf-8") as f:
            json.dump(descriptor, f, indent=2, ensure_ascii=False)

    def _serialize_list(self, items: list) -> str:
        """
        Convert list to pipe-delimited string.

        Pipe delimiter is chosen because it's rare in version strings and CVE IDs.

        Args:
            items: List of values to serialize

        Returns:
            Pipe-delimited string (e.g., "item1|item2|item3")

        Example:
            >>> self._serialize_list([">=1.0.0", "<2.0.0"])
            '>=1.0.0|<2.0.0'
        """
        return "|".join(str(item) for item in items)

    def _serialize_bool(self, value: bool) -> str:
        """
        Convert boolean to lowercase string.

        Args:
            value: Boolean value to serialize

        Returns:
            "true" or "false" (lowercase)

        Example:
            >>> self._serialize_bool(True)
            'true'
        """
        return "true" if value else "false"

    def _serialize_optional(self, value: Any) -> str:
        """
        Convert None to empty string, otherwise convert to string.

        Args:
            value: Optional value to serialize (may be None)

        Returns:
            Empty string if None, otherwise str(value)

        Example:
            >>> self._serialize_optional(None)
            ''
            >>> self._serialize_optional(245)
            '245'
        """
        return "" if value is None else str(value)

    def _serialize_datetime(self, value: str | None) -> str:
        """
        Format datetime string to match schema format: %Y-%m-%dT%H:%M:%S.

        Strips timezone suffix (Z or +00:00) and microseconds if present.

        Args:
            value: ISO datetime string or None

        Returns:
            Formatted datetime string or empty string if None

        Example:
            >>> self._serialize_datetime("2023-03-15T00:00:00Z")
            '2023-03-15T00:00:00'
            >>> self._serialize_datetime("2023-03-15T12:30:45.123456+00:00")
            '2023-03-15T12:30:45'
        """
        if value is None:
            return ""

        # Remove timezone suffix (Z or +HH:MM)
        if value.endswith("Z"):
            value = value[:-1]
        elif "+" in value:
            value = value.split("+")[0]
        elif value.count("-") > 2:  # Has negative timezone like -05:00
            # Find the last occurrence of - that's part of timezone
            parts = value.rsplit("-", 1)
            if ":" in parts[-1]:  # It's a timezone
                value = parts[0]

        # Remove microseconds if present (after the seconds)
        if "." in value:
            value = value.split(".")[0]

        return value

    def _validate_csv_files(
        self, summary_path: Path, packages_path: Path, cves_path: Path, export_data: ExportData
    ) -> None:
        """
        Validate all three CSV files against their schemas.

        Args:
            summary_path: Path to summary CSV file
            packages_path: Path to packages CSV file
            cves_path: Path to CVEs CSV file
            export_data: Export data model for additional validation context

        Raises:
            ValueError: If any CSV file fails schema validation
        """
        schema_version = export_data.metadata.schema_version
        all_errors = []

        # Ensure schema_version is ExportCsvSchemaVersion for CSV validation
        if not isinstance(schema_version, ExportCsvSchemaVersion):
            raise ValueError(f"CSV validation requires ExportCsvSchemaVersion, got {type(schema_version)}")

        # Validate summary CSV
        is_valid, errors = csv_schema_registry.validate_csv(summary_path, schema_version, "summary")
        if not is_valid:
            all_errors.append(f"Summary CSV validation failed: {'; '.join(errors)}")

        # Validate packages CSV
        is_valid, errors = csv_schema_registry.validate_csv(packages_path, schema_version, "packages")
        if not is_valid:
            all_errors.append(f"Packages CSV validation failed: {'; '.join(errors)}")

        # Validate CVEs CSV
        is_valid, errors = csv_schema_registry.validate_csv(cves_path, schema_version, "cves")
        if not is_valid:
            all_errors.append(f"CVEs CSV validation failed: {'; '.join(errors)}")

        # Raise if any validation failed
        if all_errors:
            raise ValueError("CSV schema validation failed:\n" + "\n".join(all_errors))
