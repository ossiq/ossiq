"""
Tests for CSV export renderer.

This test suite follows pytest best practices:
- AAA pattern (Arrange-Act-Assert) for clear test structure
- Parametrization to reduce test duplication
- Fixtures for reusable setup/teardown
- Single responsibility per test
- Mocking external dependencies where appropriate
"""

import csv

import pytest

from ossiq.domain.common import Command, ProjectPackagesRegistry, UserInterfaceType
from ossiq.domain.cve import CVE, CveDatabase, Severity
from ossiq.domain.exceptions import DestinationDoesntExist
from ossiq.domain.version import VersionsDifference
from ossiq.service.project import ProjectMetrics, ProjectMetricsRecord
from ossiq.settings import Settings
from ossiq.ui.renderers.export.csv import CsvExportRenderer
from ossiq.ui.renderers.export.csv_schema_registry import csv_schema_registry


@pytest.fixture
def settings():
    """Create Settings instance for tests."""
    return Settings()


@pytest.fixture
def sample_cve():
    """Create a sample CVE for testing."""
    return CVE(
        id="GHSA-test-1234",
        cve_ids=("CVE-2023-12345", "GHSA-test-1234"),
        source=CveDatabase.GHSA,
        package_name="react",
        package_registry=ProjectPackagesRegistry.NPM,
        summary="XSS vulnerability in component",
        severity=Severity.HIGH,
        affected_versions=("<18.0.0", ">=17.0.0"),
        published="2023-03-15T00:00:00Z",
        link="https://example.com/advisory",
    )


@pytest.fixture
def sample_project_metrics_record(sample_cve):
    """Create a sample ProjectMetricsRecord for testing."""
    return ProjectMetricsRecord(
        package_name="react",
        is_dev_dependency=False,
        installed_version="17.0.2",
        latest_version="18.2.0",
        versions_diff_index=VersionsDifference(
            version1="17.0.2", version2="18.2.0", diff_index=5, diff_name="DIFF_MAJOR"
        ),
        time_lag_days=245,
        releases_lag=12,
        cve=[sample_cve],
    )


@pytest.fixture
def sample_dev_dependency_record():
    """Create a sample development dependency record."""
    return ProjectMetricsRecord(
        package_name="pytest",
        is_dev_dependency=True,
        installed_version="7.0.0",
        latest_version="7.2.0",
        versions_diff_index=VersionsDifference(
            version1="7.0.0", version2="7.2.0", diff_index=2, diff_name="DIFF_MINOR"
        ),
        time_lag_days=90,
        releases_lag=5,
        cve=[],
    )


@pytest.fixture
def sample_project_metrics(sample_project_metrics_record, sample_dev_dependency_record):
    """Create realistic ProjectMetrics for testing."""
    return ProjectMetrics(
        project_name="test-project",
        project_path="/path/to/test-project",
        packages_registry=ProjectPackagesRegistry.NPM.value,
        production_packages=[sample_project_metrics_record],
        optional_packages=[sample_dev_dependency_record],
    )


@pytest.fixture
def csv_output_path(tmp_path):
    """Create output file path fixture with automatic cleanup."""
    output_path = tmp_path / "export.csv"
    yield output_path
    # Cleanup happens automatically via tmp_path


class TestCsvExportRenderer:
    """Test suite for CSV export renderer."""

    @pytest.mark.parametrize(
        "command,user_interface_type,expected",
        [
            (Command.EXPORT, UserInterfaceType.CSV, True),
            (Command.SCAN, UserInterfaceType.CSV, False),
            (Command.EXPORT, UserInterfaceType.JSON, False),
            (Command.EXPORT, UserInterfaceType.HTML, False),
            (Command.EXPORT, UserInterfaceType.CONSOLE, False),
        ],
    )
    def test_supports_command_presentation_combinations(self, command, user_interface_type, expected):
        """Verify renderer correctly identifies supported command/presentation type combinations.

        AAA Pattern:
        - Arrange: Parametrized test inputs
        - Act: Call supports() method
        - Assert: Verify expected support result
        """
        # Act
        result = CsvExportRenderer.supports(command, user_interface_type)

        # Assert
        assert result == expected

    def test_basic_export_creates_folder_with_csv_files(self, csv_output_path, sample_project_metrics, settings):
        """Test basic CSV export creates folder with CSV files and datapackage.json.

        AAA Pattern:
        - Arrange: Set up renderer and output path
        - Act: Render the export
        - Assert: Verify folder exists with all required files
        """
        # Arrange
        renderer = CsvExportRenderer(settings)

        # Act
        renderer.render(sample_project_metrics, destination=str(csv_output_path))

        # Assert
        export_folder = csv_output_path.parent / "export"
        assert export_folder.is_dir()
        assert (export_folder / "summary.csv").exists()
        assert (export_folder / "packages.csv").exists()
        assert (export_folder / "cves.csv").exists()
        assert (export_folder / "datapackage.json").exists()

    def test_file_naming_creates_folder_with_files(self, tmp_path, sample_project_metrics, settings):
        """Test export creates folder with standard file names inside.

        AAA Pattern:
        - Arrange: Set up renderer with specific base name
        - Act: Render export
        - Assert: Verify folder created with files inside
        """
        # Arrange
        renderer = CsvExportRenderer(settings)
        base_path = tmp_path / "my_export_file.csv"

        # Act
        renderer.render(sample_project_metrics, destination=str(base_path))

        # Assert
        export_folder = tmp_path / "my_export_file"
        assert export_folder.is_dir()
        assert (export_folder / "summary.csv").exists()
        assert (export_folder / "packages.csv").exists()
        assert (export_folder / "cves.csv").exists()
        assert (export_folder / "datapackage.json").exists()

    def test_summary_csv_has_correct_headers(self, csv_output_path, sample_project_metrics, settings):
        """Test summary CSV has correct column headers.

        AAA Pattern:
        - Arrange: Set up renderer and render export
        - Act: Read summary CSV headers
        - Assert: Verify expected headers
        """
        # Arrange
        renderer = CsvExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(csv_output_path))
        summary_file = csv_output_path.parent / "export" / "summary.csv"

        # Act
        with open(summary_file, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames

        # Assert
        expected_headers = [
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
        assert headers == expected_headers

    def test_packages_csv_has_correct_headers(self, csv_output_path, sample_project_metrics, settings):
        """Test packages CSV has correct column headers.

        AAA Pattern:
        - Arrange: Set up renderer and render export
        - Act: Read packages CSV headers
        - Assert: Verify expected headers
        """
        # Arrange
        renderer = CsvExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(csv_output_path))
        packages_file = csv_output_path.parent / "export" / "packages.csv"

        # Act
        with open(packages_file, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames

        # Assert
        expected_headers = [
            "package_name",
            "dependency_type",
            "is_optional_dependency",
            "installed_version",
            "latest_version",
            "time_lag_days",
            "releases_lag",
            "cve_count",
        ]
        assert headers == expected_headers

    def test_cves_csv_has_correct_headers(self, csv_output_path, sample_project_metrics, settings):
        """Test CVEs CSV has correct column headers.

        AAA Pattern:
        - Arrange: Set up renderer and render export
        - Act: Read CVEs CSV headers
        - Assert: Verify expected headers
        """
        # Arrange
        renderer = CsvExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(csv_output_path))
        cves_file = csv_output_path.parent / "export" / "cves.csv"

        # Act
        with open(cves_file, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames

        # Assert
        expected_headers = [
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
        assert headers == expected_headers

    def test_summary_row_values_match_project_metrics(self, csv_output_path, sample_project_metrics, settings):
        """Test summary row contains correct calculated values.

        AAA Pattern:
        - Arrange: Set up renderer with known data
        - Act: Render and read summary CSV
        - Assert: Verify summary statistics match expected values
        """
        # Arrange
        renderer = CsvExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(csv_output_path))
        summary_file = csv_output_path.parent / "export" / "summary.csv"

        # Act
        with open(summary_file, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            row = next(reader)

        # Assert
        assert row["schema_version"] == "1.0"
        assert row["project_name"] == "test-project"
        assert row["project_path"] == "/path/to/test-project"
        assert row["project_registry"] == "npm"
        assert row["total_packages"] == "2"
        assert row["production_packages"] == "1"
        assert row["development_packages"] == "1"
        assert row["packages_with_cves"] == "1"
        assert row["total_cves"] == "1"
        assert row["packages_outdated"] == "2"

    def test_packages_csv_row_count_matches_dependencies(self, csv_output_path, sample_project_metrics, settings):
        """Test packages CSV has one row per package.

        AAA Pattern:
        - Arrange: Set up renderer with known package count
        - Act: Render and read packages CSV
        - Assert: Verify row count matches package count
        """
        # Arrange
        renderer = CsvExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(csv_output_path))
        packages_file = csv_output_path.parent / "export" / "packages.csv"

        # Act
        with open(packages_file, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        # Assert
        assert len(rows) == 2  # 1 production + 1 development
        assert rows[0]["package_name"] == "react"
        assert rows[0]["dependency_type"] == "production"
        assert rows[0]["cve_count"] == "1"
        assert rows[1]["package_name"] == "pytest"
        assert rows[1]["dependency_type"] == "development"
        assert rows[1]["cve_count"] == "0"

    def test_cves_csv_foreign_key_links_to_packages(self, csv_output_path, sample_project_metrics, settings):
        """Test CVEs CSV foreign key references valid packages.

        AAA Pattern:
        - Arrange: Set up renderer with known CVEs
        - Act: Render and read CVEs CSV
        - Assert: Verify package_name references exist in packages CSV
        """
        # Arrange
        renderer = CsvExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(csv_output_path))
        cves_file = csv_output_path.parent / "export" / "cves.csv"
        packages_file = csv_output_path.parent / "export" / "packages.csv"

        # Act - read package names
        with open(packages_file, encoding="utf-8-sig", newline="") as f:
            packages = list(csv.DictReader(f))
            package_names = {pkg["package_name"] for pkg in packages}

        # Act - read CVE package references
        with open(cves_file, encoding="utf-8-sig", newline="") as f:
            cves = list(csv.DictReader(f))

        # Assert
        assert len(cves) == 1  # One CVE for react
        assert cves[0]["package_name"] in package_names
        assert cves[0]["cve_id"] == "GHSA-test-1234"

    def test_boolean_fields_serialized_as_lowercase_strings(self, csv_output_path, sample_project_metrics, settings):
        """Test boolean fields are serialized as 'true'/'false' lowercase strings.

        AAA Pattern:
        - Arrange: Set up renderer with boolean fields
        - Act: Render and read packages CSV
        - Assert: Verify boolean values are lowercase strings
        """
        # Arrange
        renderer = CsvExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(csv_output_path))
        packages_file = csv_output_path.parent / "export" / "packages.csv"

        # Act
        with open(packages_file, encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))

        # Assert
        assert rows[0]["is_optional_dependency"] == "false"
        assert rows[1]["is_optional_dependency"] == "true"

    def test_none_fields_serialized_as_empty_strings(self, tmp_path, settings):
        """Test None fields are serialized as empty strings.

        AAA Pattern:
        - Arrange: Create metrics with None values
        - Act: Render and read CSV
        - Assert: Verify None values are empty strings
        """
        # Arrange
        metrics_with_none = ProjectMetrics(
            project_name="test",
            project_path="/test",
            packages_registry="NPM",
            production_packages=[
                ProjectMetricsRecord(
                    package_name="package1",
                    is_dev_dependency=False,
                    installed_version="1.0.0",
                    latest_version=None,  # None value
                    versions_diff_index=VersionsDifference("1.0.0", "1.0.0", 0, "SAME"),
                    time_lag_days=None,  # None value
                    releases_lag=None,  # None value
                    cve=[],
                )
            ],
            optional_packages=[],
        )
        renderer = CsvExportRenderer(settings)
        output_path = tmp_path / "export.csv"

        # Act
        renderer.render(metrics_with_none, destination=str(output_path))
        packages_file = tmp_path / "export" / "packages.csv"

        with open(packages_file, encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))

        # Assert
        assert rows[0]["latest_version"] == ""
        assert rows[0]["time_lag_days"] == ""
        assert rows[0]["releases_lag"] == ""

    def test_list_fields_serialized_as_pipe_delimited(self, csv_output_path, sample_project_metrics, settings):
        """Test list fields are serialized as pipe-delimited strings.

        AAA Pattern:
        - Arrange: Set up renderer with list fields
        - Act: Render and read CVEs CSV
        - Assert: Verify lists are pipe-delimited
        """
        # Arrange
        renderer = CsvExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(csv_output_path))
        cves_file = csv_output_path.parent / "export" / "cves.csv"

        # Act
        with open(cves_file, encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))

        # Assert
        assert rows[0]["affected_versions"] == "<18.0.0|>=17.0.0"
        assert rows[0]["all_cve_ids"] == "CVE-2023-12345|GHSA-test-1234"

    def test_enum_fields_serialized_as_strings(self, csv_output_path, sample_project_metrics, settings):
        """Test enum fields are serialized as string values.

        AAA Pattern:
        - Arrange: Set up renderer with enum fields
        - Act: Render and read CVEs CSV
        - Assert: Verify enums are string values
        """
        # Arrange
        renderer = CsvExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(csv_output_path))
        cves_file = csv_output_path.parent / "export" / "cves.csv"

        # Act
        with open(cves_file, encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))

        # Assert
        assert rows[0]["severity"] == "HIGH"
        assert rows[0]["source"] == "GHSA"
        assert rows[0]["package_registry"] == "npm"

    def test_summary_field_with_commas_properly_quoted(self, tmp_path, settings):
        """Test CVE summary fields containing commas are properly quoted.

        AAA Pattern:
        - Arrange: Create CVE with comma in summary
        - Act: Render and read CSV
        - Assert: Verify field is readable and contains comma
        """
        # Arrange
        cve_with_comma = CVE(
            id="TEST-001",
            cve_ids=("TEST-001",),
            source=CveDatabase.OSV,
            package_name="test-pkg",
            package_registry=ProjectPackagesRegistry.NPM,
            summary="This summary contains, multiple, commas",
            severity=Severity.LOW,
            affected_versions=("*",),
            published=None,
            link="https://test.com",
        )
        metrics = ProjectMetrics(
            project_name="test",
            project_path="/test",
            packages_registry="NPM",
            production_packages=[
                ProjectMetricsRecord(
                    package_name="test-pkg",
                    is_dev_dependency=False,
                    installed_version="1.0.0",
                    latest_version="2.0.0",
                    versions_diff_index=VersionsDifference("1.0.0", "2.0.0", 1, "DIFF"),
                    time_lag_days=10,
                    releases_lag=1,
                    cve=[cve_with_comma],
                )
            ],
            optional_packages=[],
        )
        renderer = CsvExportRenderer(settings)
        output_path = tmp_path / "export.csv"

        # Act
        renderer.render(metrics, destination=str(output_path))
        cves_file = tmp_path / "export" / "cves.csv"

        with open(cves_file, encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))

        # Assert
        assert rows[0]["summary"] == "This summary contains, multiple, commas"

    def test_unicode_characters_handled_correctly(self, tmp_path, settings):
        """Test CSV export handles Unicode characters correctly.

        AAA Pattern:
        - Arrange: Create metrics with Unicode project name
        - Act: Render export and parse CSV
        - Assert: Verify Unicode preserved correctly
        """
        # Arrange
        metrics = ProjectMetrics(
            project_name="tëst-ünïcødé",
            project_path="/path/to/project",
            packages_registry="NPM",
            production_packages=[],
            optional_packages=[],
        )
        renderer = CsvExportRenderer(settings)
        output_path = tmp_path / "export.csv"

        # Act
        renderer.render(metrics, destination=str(output_path))
        summary_file = tmp_path / "export" / "summary.csv"

        with open(summary_file, encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))

        # Assert
        assert rows[0]["project_name"] == "tëst-ünïcødé"

    def test_project_name_placeholder_replaced_in_folder_name(self, tmp_path, sample_project_metrics, settings):
        """Test {project_name} placeholder is replaced with actual project name in folder.

        AAA Pattern:
        - Arrange: Set up renderer with placeholder in destination path
        - Act: Render export
        - Assert: Verify folder created with actual project name containing files
        """
        # Arrange
        renderer = CsvExportRenderer(settings)
        output_template = tmp_path / "export_{project_name}.csv"

        # Act
        renderer.render(sample_project_metrics, destination=str(output_template))

        # Assert
        export_folder = tmp_path / "export_test-project"
        assert export_folder.is_dir()
        assert (export_folder / "summary.csv").exists()
        assert (export_folder / "packages.csv").exists()
        assert (export_folder / "cves.csv").exists()
        assert (export_folder / "datapackage.json").exists()

    def test_all_files_in_named_folder(self, tmp_path, sample_project_metrics, settings):
        """Test all output files are created in a folder with the base name.

        AAA Pattern:
        - Arrange: Set up renderer with specific base name
        - Act: Render export
        - Assert: Verify folder created with all files inside
        """
        # Arrange
        renderer = CsvExportRenderer(settings)
        base_name = "my_custom_export"
        output_path = tmp_path / f"{base_name}.csv"

        # Act
        renderer.render(sample_project_metrics, destination=str(output_path))

        # Assert
        export_folder = tmp_path / base_name
        assert export_folder.is_dir()
        files = list(export_folder.glob("*.csv"))
        assert len(files) == 3
        assert (export_folder / "summary.csv").exists()
        assert (export_folder / "packages.csv").exists()
        assert (export_folder / "cves.csv").exists()
        assert (export_folder / "datapackage.json").exists()

    def test_raises_exception_when_destination_directory_not_exists(self, sample_project_metrics, settings):
        """Test raises DestinationDoesntExist for invalid directory.

        AAA Pattern:
        - Arrange: Set up renderer with nonexistent destination
        - Act & Assert: Verify exception is raised
        """
        # Arrange
        renderer = CsvExportRenderer(settings)

        # Act & Assert
        with pytest.raises(DestinationDoesntExist):
            renderer.render(sample_project_metrics, destination="/nonexistent/dir/export.csv")

    def test_exported_csv_can_be_read_back_with_dictreader(self, csv_output_path, sample_project_metrics, settings):
        """Test exported CSV files can be read back correctly with DictReader.

        AAA Pattern:
        - Arrange: Render export
        - Act: Read all three CSV files with DictReader
        - Assert: Verify all files can be parsed without errors
        """
        # Arrange
        renderer = CsvExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(csv_output_path))

        # Act & Assert - summary CSV
        summary_file = csv_output_path.parent / "export" / "summary.csv"
        with open(summary_file, encoding="utf-8-sig", newline="") as f:
            summary_rows = list(csv.DictReader(f))
        assert len(summary_rows) == 1

        # Act & Assert - packages CSV
        packages_file = csv_output_path.parent / "export" / "packages.csv"
        with open(packages_file, encoding="utf-8-sig", newline="") as f:
            package_rows = list(csv.DictReader(f))
        assert len(package_rows) == 2

        # Act & Assert - CVEs CSV
        cves_file = csv_output_path.parent / "export" / "cves.csv"
        with open(cves_file, encoding="utf-8-sig", newline="") as f:
            cve_rows = list(csv.DictReader(f))
        assert len(cve_rows) == 1

    def test_empty_dependencies_creates_empty_packages_csv(self, tmp_path, settings):
        """Test project with no dependencies creates empty packages CSV (header only).

        AAA Pattern:
        - Arrange: Create metrics with no packages
        - Act: Render export
        - Assert: Verify packages CSV has headers but no rows
        """
        # Arrange
        metrics = ProjectMetrics(
            project_name="empty-project",
            project_path="/test",
            packages_registry="NPM",
            production_packages=[],
            optional_packages=[],
        )
        renderer = CsvExportRenderer(settings)
        output_path = tmp_path / "export.csv"

        # Act
        renderer.render(metrics, destination=str(output_path))
        packages_file = tmp_path / "export" / "packages.csv"

        with open(packages_file, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        # Assert
        assert len(rows) == 0  # No package rows
        assert reader.fieldnames is not None  # Headers exist

    def test_packages_without_cves_create_empty_cves_csv(self, tmp_path, settings):
        """Test packages without CVEs create empty CVEs CSV (header only).

        AAA Pattern:
        - Arrange: Create metrics with packages but no CVEs
        - Act: Render export
        - Assert: Verify CVEs CSV has headers but no rows
        """
        # Arrange
        metrics = ProjectMetrics(
            project_name="no-cves",
            project_path="/test",
            packages_registry="NPM",
            production_packages=[
                ProjectMetricsRecord(
                    package_name="safe-pkg",
                    is_dev_dependency=False,
                    installed_version="1.0.0",
                    latest_version="1.0.0",
                    versions_diff_index=VersionsDifference("1.0.0", "1.0.0", 0, "SAME"),
                    time_lag_days=0,
                    releases_lag=0,
                    cve=[],  # No CVEs
                )
            ],
            optional_packages=[],
        )
        renderer = CsvExportRenderer(settings)
        output_path = tmp_path / "export.csv"

        # Act
        renderer.render(metrics, destination=str(output_path))
        cves_file = tmp_path / "export" / "cves.csv"

        with open(cves_file, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        # Assert
        assert len(rows) == 0  # No CVE rows
        assert reader.fieldnames is not None  # Headers exist


class TestCsvSchemaValidation:
    """Test suite for CSV schema validation via Frictionless Data Package."""

    def test_exported_csv_creates_valid_datapackage(self, csv_output_path, sample_project_metrics, settings):
        """Test exported CSV files create a valid Frictionless Data Package.

        AAA Pattern:
        - Arrange: Set up renderer and render export
        - Act: Validate datapackage.json using frictionless
        - Assert: Data package passes validation
        """
        # Arrange
        renderer = CsvExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(csv_output_path))

        # Act
        from ossiq.ui.renderers.export.csv_datapackage import validate_datapackage

        datapackage_path = csv_output_path.parent / "export" / "datapackage.json"
        is_valid, errors = validate_datapackage(datapackage_path)

        # Assert
        assert is_valid is True, f"Data package validation failed: {errors}"
        assert len(errors) == 0

    def test_exported_folder_contains_all_required_files(self, csv_output_path, sample_project_metrics, settings):
        """Test export creates folder with all required files.

        AAA Pattern:
        - Arrange: Set up renderer
        - Act: Render export
        - Assert: Verify folder contains summary.csv, packages.csv, cves.csv, datapackage.json
        """
        # Arrange
        renderer = CsvExportRenderer(settings)

        # Act
        renderer.render(sample_project_metrics, destination=str(csv_output_path))

        # Assert
        export_folder = csv_output_path.parent / "export"
        assert export_folder.is_dir()
        assert (export_folder / "summary.csv").exists()
        assert (export_folder / "packages.csv").exists()
        assert (export_folder / "cves.csv").exists()
        assert (export_folder / "datapackage.json").exists()

    def test_datapackage_json_has_correct_structure(self, csv_output_path, sample_project_metrics, settings):
        """Test datapackage.json conforms to Frictionless Data Package spec.

        AAA Pattern:
        - Arrange: Render export
        - Act: Load and parse datapackage.json
        - Assert: Verify required fields and resource paths
        """
        # Arrange
        import json

        renderer = CsvExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(csv_output_path))

        # Act
        datapackage_path = csv_output_path.parent / "export" / "datapackage.json"
        with open(datapackage_path, encoding="utf-8") as f:
            descriptor = json.load(f)

        # Assert
        assert descriptor["profile"] == "tabular-data-package"
        assert "resources" in descriptor
        assert len(descriptor["resources"]) == 3

        resource_names = {r["name"] for r in descriptor["resources"]}
        assert resource_names == {"summary", "packages", "cves"}

        # Verify resource paths are simple filenames (within folder)
        for resource in descriptor["resources"]:
            assert "/" not in resource["path"]  # No subdirs
            assert resource["path"].endswith(".csv")

    def test_schema_validation_detects_invalid_summary_csv(self, tmp_path):
        """Test schema validation detects invalid summary CSV structure.

        AAA Pattern:
        - Arrange: Create corrupted summary CSV
        - Act: Validate CSV against schema
        - Assert: Validation raises appropriate error
        """
        # Arrange - create corrupted summary file
        summary_file = tmp_path / "test-summary.csv"
        summary_file.write_text("wrong,headers\nvalue1,value2\n", encoding="utf-8-sig")

        # Act & Assert - validation should fail
        from ossiq.domain.common import ExportCsvSchemaVersion

        is_valid, errors = csv_schema_registry.validate_csv(summary_file, ExportCsvSchemaVersion.V1_0, "summary")

        # Assert
        assert is_valid is False
        assert len(errors) > 0
        assert "Column mismatch" in errors[0]

    def test_datapackage_validates_foreign_key_relationships(self, csv_output_path, sample_project_metrics, settings):
        """Test Frictionless validates foreign key between cves and packages.

        AAA Pattern:
        - Arrange: Render export
        - Act: Check that package_name in cves.csv references packages.csv
        - Assert: Foreign key relationship is satisfied
        """
        # Arrange
        renderer = CsvExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(csv_output_path))

        # Act - Read both files and check FK relationship
        export_folder = csv_output_path.parent / "export"

        with open(export_folder / "packages.csv", encoding="utf-8-sig", newline="") as f:
            packages = list(csv.DictReader(f))
            package_names = {pkg["package_name"] for pkg in packages}

        with open(export_folder / "cves.csv", encoding="utf-8-sig", newline="") as f:
            cves = list(csv.DictReader(f))

        # Assert - All CVE package_names reference valid packages
        for cve in cves:
            assert cve["package_name"] in package_names, (
                f"CVE {cve['cve_id']} references unknown package: {cve['package_name']}"
            )
