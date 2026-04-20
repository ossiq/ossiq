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

from ossiq.domain.common import (
    Command,
    ConstraintType,
    ExportJsonSchemaVersion,
    ProjectPackagesRegistry,
    UserInterfaceType,
)
from ossiq.domain.cve import CVE, CveDatabase, Severity
from ossiq.domain.exceptions import DestinationDoesntExist
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VersionsDifference
from ossiq.service.project import ScanRecord, ScanResult
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
        dependency_name="react",
        is_optional_dependency=False,
        installed_version="17.0.2",
        latest_version="18.2.0",
        versions_diff_index=VersionsDifference(
            version1="17.0.2", version2="18.2.0", diff_index=5, diff_name="DIFF_MAJOR"
        ),
        time_lag_days=245,
        releases_lag=12,
        cve=[sample_cve],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
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
        assert metadata["schema_version"] == "1.3"
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

    def test_explicit_schema_version_1_0_produces_v1_0_output(self, output_file, sample_project_metrics, settings):
        """Test that requesting schema v1.0 produces output with schema_version 1.0.

        AAA Pattern:
        - Arrange: Set up renderer
        - Act: Render with schema_version="1.0"
        - Assert: Metadata reflects v1.0 and output conforms to v1.0 schema
        """
        # Arrange
        renderer = JsonExportRenderer(settings)

        # Act
        renderer.render(sample_project_metrics, destination=str(output_file), schema_version="1.0")

        # Assert
        data = json.loads(output_file.read_text())
        assert data["metadata"]["schema_version"] == "1.0"
        v1_0_schema = json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_0)
        validate(instance=data, schema=v1_0_schema)

    def test_explicit_schema_version_1_1_produces_v1_1_output(self, output_file, sample_project_metrics, settings):
        """Test that requesting schema v1.1 produces output with schema_version 1.1.

        AAA Pattern:
        - Arrange: Set up renderer
        - Act: Render with schema_version="1.1"
        - Assert: Metadata reflects v1.1 and transitive_packages key is present
        """
        # Arrange
        renderer = JsonExportRenderer(settings)

        # Act
        renderer.render(sample_project_metrics, destination=str(output_file), schema_version="1.1")

        # Assert
        data = json.loads(output_file.read_text())
        assert data["metadata"]["schema_version"] == "1.1"
        assert "transitive_packages" in data

    def test_no_schema_version_defaults_to_latest(self, output_file, sample_project_metrics, settings):
        """Test that omitting schema_version uses the latest version.

        AAA Pattern:
        - Arrange: Set up renderer
        - Act: Render without schema_version argument
        - Assert: Output uses the latest schema version
        """
        # Arrange
        renderer = JsonExportRenderer(settings)

        # Act
        renderer.render(sample_project_metrics, destination=str(output_file))

        # Assert
        data = json.loads(output_file.read_text())
        assert data["metadata"]["schema_version"] == json_schema_registry.get_latest_version().value


@pytest.fixture
def transitive_record_a(sample_cve):
    """Transitive ScanRecord for scheduler reached via react-dom."""
    return ScanRecord(
        package_name="scheduler",
        dependency_name=None,
        is_optional_dependency=False,
        installed_version="0.23.0",
        latest_version="0.23.0",
        versions_diff_index=VersionsDifference(version1="0.23.0", version2="0.23.0", diff_index=0, diff_name="LATEST"),
        time_lag_days=0,
        releases_lag=0,
        cve=[sample_cve],
        dependency_path=["react-dom"],
        version_constraint="^0.23.0",
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
    )


@pytest.fixture
def transitive_record_b():
    """Same package/version as record_a but reached via react."""
    return ScanRecord(
        package_name="scheduler",
        dependency_name=None,
        is_optional_dependency=False,
        installed_version="0.23.0",
        latest_version="0.23.0",
        versions_diff_index=VersionsDifference(version1="0.23.0", version2="0.23.0", diff_index=0, diff_name="LATEST"),
        time_lag_days=0,
        releases_lag=0,
        cve=[],
        dependency_path=["react"],
        version_constraint="~0.23.0",
        constraint_info=ConstraintSource(type=ConstraintType.NARROWED, source_file="package.json"),
    )


@pytest.fixture
def sample_project_with_transitives(sample_project_metrics_record, transitive_record_a, transitive_record_b):
    """ScanResult with two transitive records for the same (package_name, installed_version)."""
    return ScanResult(
        project_name="test-project",
        project_path="/path/to/test-project",
        packages_registry=ProjectPackagesRegistry.NPM.value,
        production_packages=[sample_project_metrics_record],
        optional_packages=[],
        transitive_packages=[transitive_record_a, transitive_record_b],
    )


class TestJsonExportRendererV13:
    """Test suite for v1.3 JSON export: deduplicated transitive packages."""

    def test_v1_3_transitive_packages_are_deduplicated(self, output_file, sample_project_with_transitives, settings):
        """Two ScanRecords with same (package_name, installed_version) produce one transitive entry."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.3")

        data = json.loads(output_file.read_text())
        assert len(data["transitive_packages"]) == 1

    def test_v1_3_transitive_entry_has_dependency_paths(self, output_file, sample_project_with_transitives, settings):
        """The single deduplicated entry must have two dependency_paths entries."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.3")

        data = json.loads(output_file.read_text())
        entry = data["transitive_packages"][0]
        assert "dependency_paths" in entry
        assert len(entry["dependency_paths"]) == 2

    def test_v1_3_dependency_paths_contain_path_specific_fields(
        self, output_file, sample_project_with_transitives, settings
    ):
        """Each DependencyPath must carry path, version_constraint, constraint_type."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.3")

        data = json.loads(output_file.read_text())
        paths = data["transitive_packages"][0]["dependency_paths"]
        for dp in paths:
            assert "path" in dp
            assert "version_constraint" in dp
            assert "constraint_type" in dp

    def test_v1_3_dependency_paths_preserve_correct_path_values(
        self, output_file, sample_project_with_transitives, settings
    ):
        """dependency_paths entries carry the correct ancestor chains from both records."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.3")

        data = json.loads(output_file.read_text())
        paths = [tuple(dp["path"]) for dp in data["transitive_packages"][0]["dependency_paths"]]
        assert ("react-dom",) in paths
        assert ("react",) in paths

    def test_v1_3_invariant_fields_not_duplicated_inside_dependency_paths(
        self, output_file, sample_project_with_transitives, settings
    ):
        """Invariant fields (package_name, installed_version, cve) must be at top level only."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.3")

        data = json.loads(output_file.read_text())
        entry = data["transitive_packages"][0]
        assert "package_name" in entry
        assert "installed_version" in entry
        assert "cve" in entry
        for dp in entry["dependency_paths"]:
            assert "package_name" not in dp
            assert "installed_version" not in dp
            assert "cve" not in dp

    def test_v1_3_no_dependency_path_field_at_top_level(self, output_file, sample_project_with_transitives, settings):
        """The old flat dependency_path key must be absent from v1.3 transitive entries."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.3")

        data = json.loads(output_file.read_text())
        entry = data["transitive_packages"][0]
        assert "dependency_path" not in entry

    def test_v1_3_cve_taken_from_first_record(self, output_file, sample_project_with_transitives, settings):
        """CVE data is read from the first record in the group (invariant field)."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.3")

        data = json.loads(output_file.read_text())
        # transitive_record_a (first) has 1 CVE; transitive_record_b has 0
        assert len(data["transitive_packages"][0]["cve"]) == 1

    def test_v1_3_output_validates_against_v1_3_schema(self, output_file, sample_project_with_transitives, settings):
        """v1.3 output must pass jsonschema validation against the v1.3 schema."""
        from jsonschema import validate

        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.3")

        data = json.loads(output_file.read_text())
        schema = json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_3)
        validate(instance=data, schema=schema)

    def test_v1_2_still_produces_flat_transitive_list(self, output_file, sample_project_with_transitives, settings):
        """v1.2 export must retain the old flat structure with dependency_path at top level."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.2")

        data = json.loads(output_file.read_text())
        assert data["metadata"]["schema_version"] == "1.2"
        assert len(data["transitive_packages"]) == 2
        for entry in data["transitive_packages"]:
            assert "dependency_path" in entry
            assert "dependency_paths" not in entry

    def test_v1_3_grouping_key_is_package_name_and_version(self, output_file, settings, sample_project_metrics_record):
        """Two records with different package names produce two separate transitive entries."""
        other_record = ScanRecord(
            package_name="loose-envify",
            dependency_name=None,
            is_optional_dependency=False,
            installed_version="1.4.0",
            latest_version="1.4.0",
            versions_diff_index=VersionsDifference(
                version1="1.4.0", version2="1.4.0", diff_index=0, diff_name="LATEST"
            ),
            time_lag_days=0,
            releases_lag=0,
            cve=[],
            dependency_path=["react"],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
        )
        scheduler_record = ScanRecord(
            package_name="scheduler",
            dependency_name=None,
            is_optional_dependency=False,
            installed_version="0.23.0",
            latest_version="0.23.0",
            versions_diff_index=VersionsDifference(
                version1="0.23.0", version2="0.23.0", diff_index=0, diff_name="LATEST"
            ),
            time_lag_days=0,
            releases_lag=0,
            cve=[],
            dependency_path=["react"],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
        )
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[sample_project_metrics_record],
            optional_packages=[],
            transitive_packages=[other_record, scheduler_record],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.3")

        data = json.loads(output_file.read_text())
        assert len(data["transitive_packages"]) == 2
