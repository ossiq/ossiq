"""
Tests for JSON export renderer.

This test suite follows pytest best practices:
- AAA pattern (Arrange-Act-Assert) for clear test structure
- Parametrization to reduce test duplication
- Fixtures for reusable setup/teardown
- Single responsibility per test
- Mocking external dependencies where appropriate
"""

import json

import pytest
from jsonschema import validate

from ossiq.domain.common import Command, ProjectPackagesRegistry, UserInterfaceType
from ossiq.domain.cve import CVE, CveDatabase, Severity
from ossiq.domain.exceptions import DestinationDoesntExist
from ossiq.domain.version import VersionsDifference
from ossiq.service.project import ScanResult, ScanRecord
from ossiq.settings import Settings
from ossiq.ui.renderers.export.json import JsonExportRenderer
from ossiq.ui.renderers.export.json_schema_registry import json_schema_registry


@pytest.fixture
def settings():
    """Create Settings instance for tests."""
    return Settings()


@pytest.fixture
def sample_cve():
    """Create a sample CVE for testing."""
    return CVE(
        id="GHSA-test-1234",
        cve_ids=("CVE-2023-12345",),
        source=CveDatabase.GHSA,
        package_name="react",
        package_registry=ProjectPackagesRegistry.NPM,
        summary="Test vulnerability",
        severity=Severity.HIGH,
        affected_versions=("<18.0.0",),
        published="2023-03-15T00:00:00Z",
        link="https://example.com/advisory",
    )


@pytest.fixture
def sample_project_metrics_record(sample_cve):
    """Create a sample ScanRecord for testing."""
    return ScanRecord(
        package_name="react",
        is_optional_dependency=False,
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
def sample_project_metrics(sample_project_metrics_record):
    """Create realistic ScanResult for testing."""
    return ScanResult(
        project_name="test-project",
        project_path="/path/to/test-project",
        packages_registry=ProjectPackagesRegistry.NPM.value,
        production_packages=[sample_project_metrics_record],
        optional_packages=[],
    )


@pytest.fixture
def output_file(tmp_path):
    """Create output file path fixture with automatic cleanup."""
    output_path = tmp_path / "export.json"
    yield output_path
    # Cleanup happens automatically via tmp_path


class TestJsonExportRenderer:
    """Test suite for JSON export renderer."""

    @pytest.mark.parametrize(
        "command,user_interface_type,expected",
        [
            (Command.EXPORT, UserInterfaceType.JSON, True),
            (Command.SCAN, UserInterfaceType.JSON, False),
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
        result = JsonExportRenderer.supports(command, user_interface_type)

        # Assert
        assert result == expected

    def test_basic_export_creates_valid_json_file(self, output_file, sample_project_metrics, settings):
        """Test basic JSON export creates a valid file with expected structure.

        AAA Pattern:
        - Arrange: Set up renderer and output path
        - Act: Render the export
        - Assert: Verify file exists and contains expected top-level structure
        """
        # Arrange
        renderer = JsonExportRenderer(settings)

        # Act
        renderer.render(sample_project_metrics, destination=str(output_file))

        # Assert
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        expected_keys = ["metadata", "project", "summary", "production_packages", "development_packages"]
        assert all(key in data for key in expected_keys)

    def test_metadata_contains_schema_version_and_timestamp(self, output_file, sample_project_metrics, settings):
        """Test metadata section contains required fields.

        AAA Pattern:
        - Arrange: Set up renderer and render export
        - Act: Extract metadata from exported JSON
        - Assert: Verify metadata fields
        """
        # Arrange
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(output_file))

        # Act
        data = json.loads(output_file.read_text())
        metadata = data["metadata"]

        # Assert
        assert metadata["schema_version"] == "1.0"
        assert "export_timestamp" in metadata
        assert "ossiq_version" not in metadata

    def test_project_fields_match_input_data(self, output_file, sample_project_metrics, settings):
        """Test project section matches input data.

        AAA Pattern:
        - Arrange: Set up renderer with known project data
        - Act: Render export and extract project section
        - Assert: Verify project fields match input
        """
        # Arrange
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(output_file))

        # Act
        data = json.loads(output_file.read_text())
        project = data["project"]

        # Assert
        assert project["name"] == "test-project"
        assert project["path"] == "/path/to/test-project"
        assert project["registry"] == "npm"

    def test_summary_calculates_correct_statistics(self, output_file, sample_project_metrics, settings):
        """Test summary section calculates correct statistics from package data.

        AAA Pattern:
        - Arrange: Set up renderer with known package data
        - Act: Render export and extract summary
        - Assert: Verify calculated statistics
        """
        # Arrange
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(output_file))

        # Act
        data = json.loads(output_file.read_text())
        summary = data["summary"]

        # Assert
        assert summary["total_packages"] == 1
        assert summary["production_packages"] == 1
        assert summary["development_packages"] == 0
        assert summary["packages_with_cves"] == 1
        assert summary["total_cves"] == 1
        assert summary["packages_outdated"] == 1

    @pytest.mark.parametrize(
        "field_path,expected_type,expected_value",
        [
            ("severity", str, "HIGH"),
            ("source", str, "GHSA"),
        ],
    )
    def test_enum_fields_serialized_as_strings(
        self, output_file, sample_project_metrics, settings, field_path, expected_type, expected_value
    ):
        """Test enum fields are serialized as string values, not objects.

        AAA Pattern:
        - Arrange: Set up renderer and render export
        - Act: Extract CVE data from exported JSON
        - Assert: Verify enum fields are strings with correct values
        """
        # Arrange
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(output_file))

        # Act
        data = json.loads(output_file.read_text())
        cve = data["production_packages"][0]["cve"][0]

        # Assert
        assert isinstance(cve[field_path], expected_type)
        assert cve[field_path] == expected_value

    def test_project_name_placeholder_replaced_in_destination(self, tmp_path, sample_project_metrics, settings):
        """Test {project_name} placeholder is replaced with actual project name.

        AAA Pattern:
        - Arrange: Set up renderer with placeholder in destination path
        - Act: Render export
        - Assert: Verify file created with actual project name
        """
        # Arrange
        renderer = JsonExportRenderer(settings)
        output_template = tmp_path / "export_{project_name}.json"

        # Act
        renderer.render(sample_project_metrics, destination=str(output_template))

        # Assert
        expected_file = tmp_path / "export_test-project.json"
        assert expected_file.exists()

    def test_raises_exception_when_destination_directory_not_exists(self, sample_project_metrics, settings):
        """Test raises DestinationDoesntExist for invalid directory.

        AAA Pattern:
        - Arrange: Set up renderer with nonexistent destination
        - Act & Assert: Verify exception is raised
        """
        # Arrange
        renderer = JsonExportRenderer(settings)

        # Act & Assert
        with pytest.raises(DestinationDoesntExist):
            renderer.render(sample_project_metrics, destination="/nonexistent/dir/export.json")

    def test_unicode_characters_handled_correctly(self, output_file, settings):
        """Test JSON export handles Unicode characters correctly.

        AAA Pattern:
        - Arrange: Create metrics with Unicode project name
        - Act: Render export and parse JSON
        - Assert: Verify Unicode preserved correctly
        """
        # Arrange
        metrics = ScanResult(
            project_name="tëst-ünïcødé",
            project_path="/path/to/project",
            packages_registry="NPM",
            production_packages=[],
            optional_packages=[],
        )
        renderer = JsonExportRenderer(settings)

        # Act
        renderer.render(metrics, destination=str(output_file))
        data = json.loads(output_file.read_text())

        # Assert
        assert data["project"]["name"] == "tëst-ünïcødé"

    def test_exported_json_contains_complete_cve_data(self, output_file, sample_project_metrics, settings):
        """Test complete export includes CVE data in packages.

        AAA Pattern:
        - Arrange: Set up renderer with package containing CVE
        - Act: Render export and extract package data
        - Assert: Verify CVE data is present and complete
        """
        # Arrange
        renderer = JsonExportRenderer(settings)

        # Act
        renderer.render(sample_project_metrics, destination=str(output_file))
        data = json.loads(output_file.read_text())

        # Assert
        pkg = data["production_packages"][0]
        assert len(pkg["cve"]) == 1
        assert pkg["cve"][0]["severity"] == "HIGH"
        assert pkg["cve"][0]["source"] == "GHSA"
        assert pkg["cve"][0]["id"] == "GHSA-test-1234"

    def test_exported_json_conforms_to_schema(self, output_file, sample_project_metrics, settings):
        """Test exported JSON validates against the schema from registry.

        AAA Pattern:
        - Arrange: Set up renderer and render export
        - Act: Load schema and validate exported data
        - Assert: Validation passes without raising exception
        """
        # Arrange
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(output_file))

        # Act
        exported_data = json.loads(output_file.read_text())
        latest_schema = json_schema_registry.load_schema(json_schema_registry.get_latest_version())

        # Assert - validate() raises exception if invalid
        validate(instance=exported_data, schema=latest_schema)
