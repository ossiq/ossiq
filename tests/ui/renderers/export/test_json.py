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
    DataCompleteness,
    DataSourceStatus,
    EngineContext,
    EngineContextSource,
    ExportJsonSchemaVersion,
    ModuleSystem,
    ProjectPackagesRegistry,
    RecommendationRung,
    ScanStep,
    UserInterfaceType,
)
from ossiq.domain.compatibility import CompatibilityFacts
from ossiq.domain.cve import CVE, CveDatabase, Severity
from ossiq.domain.exceptions import DestinationDoesntExist
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VersionsDifference
from ossiq.risk.stability import EngagementBucket, EngagementSeries
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.service.project.stability import RepositoryStability
from ossiq.settings import Settings
from ossiq.strategy.motive import UpdateMotive
from ossiq.strategy.pyramid import UpdateStrategy
from ossiq.strategy.targeting import StrategySelection
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
            (Command.STATUS, UserInterfaceType.JSON, False),
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

    def test_dash_destination_writes_valid_json_to_stdout(self, sample_project_metrics, settings, capsys):
        """B8's related minor issue: '-' should stream to stdout instead of being written to (or
        rejected as) a file literally named '-'.
        """
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_metrics, destination="-")

        captured = capsys.readouterr()
        assert captured.err == ""
        data = json.loads(captured.out)
        assert data["project"]["name"] == "test-project"

    def test_dash_destination_does_not_create_a_file_named_dash(
        self, sample_project_metrics, settings, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_metrics, destination="-")

        assert not (tmp_path / "-").exists()

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
        data = json.loads(output_file.read_text(encoding="utf-8"))
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
        data = json.loads(output_file.read_text(encoding="utf-8"))
        metadata = data["metadata"]

        # Assert
        assert metadata["schema_version"] == "1.5"
        assert "export_timestamp" in metadata
        assert "ossiq_version" not in metadata

    def test_metadata_data_completeness_defaults_to_ok_with_no_sources(
        self, output_file, sample_project_metrics, settings
    ):
        """A ScanResult built without any tracked completeness (the common test-fixture case)
        must not be mistaken for a scan with degraded sources.
        """
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(output_file))

        data = json.loads(output_file.read_text(encoding="utf-8"))
        completeness = data["metadata"]["data_completeness"]

        assert completeness["overall"] == "ok"
        assert completeness["sources"] == []

    def test_metadata_data_completeness_surfaces_degraded_sources(
        self, output_file, sample_project_metrics_record, settings
    ):
        """B4 point 3: a firewalled OSV host or exhausted GitHub quota must be visible in the
        export, not just the CLI's own progress display - any consumer of the JSON needs to be
        able to tell a genuinely clean report apart from one built on missing data.
        """
        scan = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[sample_project_metrics_record],
            optional_packages=[],
            data_completeness=DataCompleteness(
                by_step={
                    ScanStep.VULNERABILITIES: DataSourceStatus.UNREACHABLE,
                    ScanStep.REPOSITORIES: DataSourceStatus.OK,
                }
            ),
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(scan, destination=str(output_file))

        data = json.loads(output_file.read_text(encoding="utf-8"))
        completeness = data["metadata"]["data_completeness"]

        assert completeness["overall"] == "unreachable"
        assert {"step": "vulnerabilities", "status": "unreachable"} in completeness["sources"]
        assert {"step": "repositories", "status": "ok"} in completeness["sources"]

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
        data = json.loads(output_file.read_text(encoding="utf-8"))
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
        data = json.loads(output_file.read_text(encoding="utf-8"))
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
        data = json.loads(output_file.read_text(encoding="utf-8"))
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
        data = json.loads(output_file.read_text(encoding="utf-8"))

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
        data = json.loads(output_file.read_text(encoding="utf-8"))

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
        exported_data = json.loads(output_file.read_text(encoding="utf-8"))
        latest_schema = json_schema_registry.load_schema(json_schema_registry.get_latest_version())

        # Assert - validate() raises exception if invalid
        validate(instance=exported_data, schema=latest_schema)

    def test_explicit_schema_version_1_5_produces_v1_5_output(self, output_file, sample_project_metrics, settings):
        """Test that requesting schema v1.5 produces output with schema_version 1.5.

        AAA Pattern:
        - Arrange: Set up renderer
        - Act: Render with schema_version="1.5"
        - Assert: Metadata reflects v1.5 and output conforms to v1.5 schema
        """
        # Arrange
        renderer = JsonExportRenderer(settings)

        # Act
        renderer.render(sample_project_metrics, destination=str(output_file), schema_version="1.5")

        # Assert
        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert data["metadata"]["schema_version"] == "1.5"
        assert "transitive_packages" in data
        v1_5_schema = json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5)
        validate(instance=data, schema=v1_5_schema)

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
        data = json.loads(output_file.read_text(encoding="utf-8"))
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
    """Test suite for v1.3 JSON export: deduplicated transitive packages with dependency_tree."""

    def test_v1_3_transitive_packages_are_deduplicated(self, output_file, sample_project_with_transitives, settings):
        """Two ScanRecords with same (package_name, installed_version) produce one transitive entry."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert len(data["transitive_packages"]) == 1

    def test_v1_3_output_has_dependency_tree(self, output_file, sample_project_with_transitives, settings):
        """v1.3 output must contain a top-level dependency_tree array."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert "dependency_tree" in data
        assert isinstance(data["dependency_tree"], list)

    def test_v1_3_dependency_tree_has_roots_for_both_paths(
        self, output_file, sample_project_with_transitives, settings
    ):
        """Tree must have roots for react-dom and react (the two direct parents from the test fixtures)."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        root_names = {r["package_name"] for r in data["dependency_tree"]}
        assert "react-dom" in root_names
        assert "react" in root_names

    def test_v1_3_tree_nodes_carry_constraint_fields(self, output_file, sample_project_with_transitives, settings):
        """Each tree node must carry ref, ct, and version_constraint."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        for root in data["dependency_tree"]:
            for node in root["children"]:
                assert "ref" in node
                assert "ct" in node
                assert "version_constraint" in node

    def test_v1_3_same_package_different_constraints_in_tree(
        self, output_file, sample_project_with_transitives, settings
    ):
        """The same package (scheduler ref=0) appears under two roots with different ct values."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        # Both roots point to scheduler (ref=0) but with different constraints
        node_by_root = {r["package_name"]: r["children"][0] for r in data["dependency_tree"]}
        assert node_by_root["react-dom"]["ref"] == node_by_root["react"]["ref"] == 0
        ct_map = data["constraint_type_map"]
        ct_by_root = {r["package_name"]: ct_map[node_by_root[r["package_name"]]["ct"]] for r in data["dependency_tree"]}
        assert ct_by_root["react-dom"] == "DECLARED"
        assert ct_by_root["react"] == "NARROWED"

    def test_v1_3_tree_node_ref_indexes_into_transitive_packages(
        self, output_file, sample_project_with_transitives, settings
    ):
        """Every ref value in the tree must be a valid index into transitive_packages."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        n = len(data["transitive_packages"])

        def check_refs(nodes):
            for node in nodes:
                assert 0 <= node["ref"] < n
                check_refs(node.get("children", []))

        for root in data["dependency_tree"]:
            check_refs(root["children"])

    def test_v1_3_transitive_entry_has_no_path_fields(self, output_file, sample_project_with_transitives, settings):
        """transitive_packages entries must not contain dependency_paths or dependency_path."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        entry = data["transitive_packages"][0]
        assert "dependency_path" not in entry
        assert "dependency_paths" not in entry

    def test_v1_3_invariant_fields_on_transitive_entry(self, output_file, sample_project_with_transitives, settings):
        """Invariant fields (id, package_name, installed_version, cve) must be on transitive entries."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        entry = data["transitive_packages"][0]
        assert "id" in entry
        assert entry["id"] == 0
        assert "package_name" in entry
        assert "installed_version" in entry
        assert "cve" in entry

    def test_v1_3_output_has_constraint_type_map(self, output_file, sample_project_with_transitives, settings):
        """v1.3 output must contain a top-level constraint_type_map with 5 entries."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert "constraint_type_map" in data
        assert data["constraint_type_map"] == ["DECLARED", "NARROWED", "PINNED", "ADDITIVE", "OVERRIDE"]

    def test_v1_3_tree_node_has_no_null_fields(self, output_file, sample_project_with_transitives, settings):
        """Tree nodes must not contain null or empty-list fields."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        for root in data["dependency_tree"]:
            for node in root.get("children", []):
                assert "constraint_source_file" not in node
                assert "dependency_name" not in node
                for key, val in node.items():
                    assert val is not None, f"Node field {key!r} should be absent, not null"
                    assert val != [], f"Node field {key!r} should be absent, not empty list"

    def test_v1_3_constraint_source_file_on_transitive_package(
        self, output_file, sample_project_with_transitives, settings
    ):
        """constraint_source_file from NARROWED record must appear on the transitive package entry."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        # transitive_record_b has NARROWED constraint with source_file="package.json"
        entry = data["transitive_packages"][0]
        assert entry.get("constraint_source_file") == "package.json"

    def test_v1_3_cve_taken_from_first_record(self, output_file, sample_project_with_transitives, settings):
        """CVE data is read from the first record in the group (invariant field)."""
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        # transitive_record_a (first) has 1 CVE; transitive_record_b has 0
        assert len(data["transitive_packages"][0]["cve"]) == 1

    def test_v1_3_output_validates_against_v1_3_schema(self, output_file, sample_project_with_transitives, settings):
        """v1.3 output must pass jsonschema validation against the v1.3 schema."""
        from jsonschema import validate

        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        schema = json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5)
        validate(instance=data, schema=schema)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert len(data["transitive_packages"]) == 2

    def test_v1_3_deep_path_produces_nested_tree(self, output_file, settings, sample_project_metrics_record):
        """A package reached via a two-level path produces a nested tree node."""
        # react-dom → scheduler → loose-envify
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
            dependency_path=["react-dom"],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
        )
        loose_envify_record = ScanRecord(
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
            dependency_path=["react-dom", "scheduler"],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
        )
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[sample_project_metrics_record],
            optional_packages=[],
            transitive_packages=[scheduler_record, loose_envify_record],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        # transitive_packages: scheduler=0, loose-envify=1
        assert len(data["transitive_packages"]) == 2
        # tree: react-dom → scheduler → loose-envify
        tree = data["dependency_tree"]
        assert len(tree) == 1
        root = tree[0]
        assert root["package_name"] == "react-dom"
        assert len(root["children"]) == 1
        scheduler_node = root["children"][0]
        assert scheduler_node["ref"] == 0
        assert len(scheduler_node["children"]) == 1
        loose_node = scheduler_node["children"][0]
        assert loose_node["ref"] == 1


@pytest.fixture
def prerelease_record():
    """ScanRecord with is_installed_prerelease=True."""
    return ScanRecord(
        package_name="mylib",
        dependency_name="mylib",
        is_optional_dependency=False,
        installed_version="1.0.0b2",
        latest_version="1.0.0",
        versions_diff_index=VersionsDifference(
            version1="1.0.0b2", version2="1.0.0", diff_index=1, diff_name="DIFF_PATCH"
        ),
        time_lag_days=10,
        releases_lag=1,
        cve=[],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
        is_installed_prerelease=True,
        is_installed_yanked=False,
    )


@pytest.fixture
def yanked_record():
    """ScanRecord with is_installed_yanked=True."""
    return ScanRecord(
        package_name="oldlib",
        dependency_name="oldlib",
        is_optional_dependency=False,
        installed_version="0.9.0",
        latest_version="1.0.0",
        versions_diff_index=VersionsDifference(
            version1="0.9.0", version2="1.0.0", diff_index=2, diff_name="DIFF_MAJOR"
        ),
        time_lag_days=100,
        releases_lag=5,
        cve=[],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
        is_installed_prerelease=False,
        is_installed_yanked=True,
    )


class TestJsonExportRendererV14:
    """Test suite for v1.4 JSON export: is_prerelease and is_yanked fields."""

    def test_v1_4_output_has_is_prerelease_on_packages(self, output_file, settings, prerelease_record):
        """v1.4 production packages must include is_prerelease field."""
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[prerelease_record],
            optional_packages=[],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        pkg = data["production_packages"][0]
        assert "is_prerelease" in pkg
        assert "is_yanked" in pkg

    def test_v1_4_is_prerelease_true_when_installed_prerelease(self, output_file, settings, prerelease_record):
        """is_prerelease field is True when ScanRecord.is_installed_prerelease is True."""
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[prerelease_record],
            optional_packages=[],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        pkg = data["production_packages"][0]
        assert pkg["is_prerelease"] is True
        assert pkg["is_yanked"] is False

    def test_v1_4_is_yanked_true_when_installed_yanked(self, output_file, settings, yanked_record):
        """is_yanked field is True when ScanRecord.is_installed_yanked is True."""
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[yanked_record],
            optional_packages=[],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        pkg = data["production_packages"][0]
        assert pkg["is_prerelease"] is False
        assert pkg["is_yanked"] is True

    def test_v1_4_defaults_both_false_for_normal_package(self, output_file, settings, sample_project_metrics_record):
        """is_prerelease and is_yanked default to False for a normal package."""
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[sample_project_metrics_record],
            optional_packages=[],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        pkg = data["production_packages"][0]
        assert pkg["is_prerelease"] is False
        assert pkg["is_yanked"] is False

    def test_v1_4_transitive_packages_have_is_prerelease_and_is_yanked(
        self, output_file, settings, sample_project_metrics_record, prerelease_record
    ):
        """Transitive packages in v1.4 output must include is_prerelease and is_yanked."""
        transitive = ScanRecord(
            package_name="dep",
            dependency_name=None,
            is_optional_dependency=False,
            installed_version="2.0.0a1",
            latest_version="2.0.0",
            versions_diff_index=VersionsDifference(
                version1="2.0.0a1", version2="2.0.0", diff_index=1, diff_name="DIFF_PATCH"
            ),
            time_lag_days=5,
            releases_lag=1,
            cve=[],
            dependency_path=["mylib"],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
            is_installed_prerelease=True,
            is_installed_yanked=False,
        )
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[sample_project_metrics_record],
            optional_packages=[],
            transitive_packages=[transitive],
            engine_context=EngineContext({"node": ">=18.0.0"}, EngineContextSource.DECLARED),
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        entry = data["transitive_packages"][0]
        assert entry["is_prerelease"] is True
        assert entry["is_yanked"] is False

    def test_v1_4_output_validates_against_v1_4_schema(self, output_file, settings, sample_project_with_transitives):
        """v1.4 output must pass jsonschema validation against the v1.4 schema."""
        from jsonschema import validate

        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_with_transitives, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        schema = json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5)
        validate(instance=data, schema=schema)

    def test_recommended_version_populated_when_solver_recommendation_exists(
        self, output_file, settings, sample_project_metrics_record
    ):
        """recommended_version in v1.5 export matches ScanRecord.recommended_version."""
        import dataclasses

        record_with_rec = dataclasses.replace(sample_project_metrics_record, recommended_version="18.2.0")
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[record_with_rec],
            optional_packages=[],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        pkg = data["production_packages"][0]
        assert pkg["recommended_version"] == "18.2.0"

    def test_recommended_version_is_null_when_no_recommendation(
        self, output_file, settings, sample_project_metrics_record
    ):
        """recommended_version is null in v1.5 export when ScanRecord has no recommendation."""
        import dataclasses

        record_no_rec = dataclasses.replace(sample_project_metrics_record, recommended_version=None)
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[record_no_rec],
            optional_packages=[],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        pkg = data["production_packages"][0]
        assert pkg["recommended_version"] is None


@pytest.fixture
def epss_scored_record():
    """ScanRecord with epss and install-execution fields populated, for v1.5 export tests."""
    return ScanRecord(
        package_name="risky-lib",
        dependency_name="risky-lib",
        is_optional_dependency=False,
        installed_version="0.1.0",
        latest_version="0.2.0",
        versions_diff_index=VersionsDifference(
            version1="0.1.0", version2="0.2.0", diff_index=1, diff_name="DIFF_MINOR"
        ),
        time_lag_days=5,
        releases_lag=1,
        cve=[],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
        epss=0.123456789,
        runs_code_at_install=True,
        install_execution_reason="npm lifecycle: postinstall",
    )


class TestJsonExportRendererV15:
    """Test suite for v1.5 JSON export: epss and install-execution fields."""

    def test_v1_5_output_validates_against_v1_5_schema(self, output_file, settings, epss_scored_record):
        """v1.5 output with EPSS data must pass jsonschema validation against the v1.5 schema."""
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[epss_scored_record],
            optional_packages=[],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        schema = json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5)
        validate(instance=data, schema=schema)

    def test_v1_5_emits_epss_and_install_execution_fields(self, output_file, settings, epss_scored_record):
        """A scored record emits epss rounded to 4 decimals plus the install-execution fields."""
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[epss_scored_record],
            optional_packages=[],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        pkg = data["production_packages"][0]
        assert pkg["epss"] == 0.1235
        assert pkg["runs_code_at_install"] is True
        assert pkg["install_execution_reason"] == "npm lifecycle: postinstall"

    def test_v1_5_null_epss_omits_key_on_transitive_but_null_on_package(
        self, output_file, settings, sample_project_metrics_record
    ):
        """epss=None serializes to null on PackageMetrics but is dropped entirely on TransitivePackageMetrics."""
        transitive = ScanRecord(
            package_name="dep",
            dependency_name=None,
            is_optional_dependency=False,
            installed_version="1.0.0",
            latest_version="1.0.0",
            versions_diff_index=VersionsDifference(
                version1="1.0.0", version2="1.0.0", diff_index=0, diff_name="LATEST"
            ),
            time_lag_days=0,
            releases_lag=0,
            cve=[],
            dependency_path=["react"],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
            epss=None,
        )
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[sample_project_metrics_record],
            optional_packages=[],
            transitive_packages=[transitive],
            engine_context=EngineContext({"node": ">=18.0.0"}, EngineContextSource.DECLARED),
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        pkg = data["production_packages"][0]
        assert "epss" in pkg
        assert pkg["epss"] is None

        entry = data["transitive_packages"][0]
        assert "epss" not in entry

    def test_v1_5_transitive_with_unknown_lag_validates(self, output_file, settings, sample_project_metrics_record):
        """The compact serializer drops null lag fields, so the schema must not require them.

        Regression: a transitive whose latest version is invisible (unpublished, or hidden by
        --cutoff-date) produced an entry that failed validation against its own schema.
        """
        transitive = ScanRecord(
            package_name="stale-dep",
            dependency_name=None,
            is_optional_dependency=False,
            installed_version="15001.1.0-dev-harmony",
            latest_version=None,
            versions_diff_index=VersionsDifference(
                version1="15001.1.0-dev-harmony", version2="15001.1.0-dev-harmony", diff_index=0, diff_name="LATEST"
            ),
            time_lag_days=None,
            releases_lag=None,
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
            transitive_packages=[transitive],
            engine_context=EngineContext({"node": ">=18.0.0"}, EngineContextSource.DECLARED),
        )
        JsonExportRenderer(settings).render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        entry = data["transitive_packages"][0]
        assert "time_lag_days" not in entry
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5))

    def test_v1_5_emits_ladder_fields_and_validates(self, output_file, settings, sample_project_metrics_record):
        """latest_in_range/latest_in_major/recommended_from_rung round-trip and validate."""
        import dataclasses

        from ossiq.domain.common import RecommendationRung

        record = dataclasses.replace(
            sample_project_metrics_record,
            compatibility=CompatibilityFacts(latest_in_range="17.0.2", latest_in_major="17.9.0"),
            recommended_version="17.9.0",
            recommended_from_rung=RecommendationRung.IN_MAJOR,
        )
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[record],
            optional_packages=[],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        pkg = data["production_packages"][0]
        assert pkg["latest_in_range"] == "17.0.2"
        assert pkg["latest_in_major"] == "17.9.0"
        assert pkg["recommended_from_rung"] == "in_major"  # plain string, not an enum repr
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5))

    def test_v1_5_emits_next_action_and_widening_flag(self, output_file, settings, sample_project_metrics_record):
        """next_action and requires_constraint_widening come from the pipeline, not from each
        surface re-deriving them. The HTML report used to compute its own and disagreed."""
        import dataclasses

        from ossiq.domain.common import RecommendationRung
        from ossiq.service.project.next_action import next_action_label

        record = dataclasses.replace(
            sample_project_metrics_record,
            compatibility=CompatibilityFacts(latest_in_range="17.0.2", latest_in_major="17.9.0"),
            recommended_version="17.9.0",
            recommended_from_rung=RecommendationRung.IN_MAJOR,
        )
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[record],
            optional_packages=[],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        pkg = data["production_packages"][0]
        assert pkg["next_action"] == next_action_label(record)
        assert pkg["requires_constraint_widening"] is True
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5))

    def test_v1_5_widening_pick_is_not_reported_as_an_ordinary_update(
        self, output_file, settings, sample_project_metrics_record
    ):
        """The cross-surface regression: a recommendation only reachable by widening must not read
        as "Update Immediately" anywhere. The CLI has always said "Constrained. Check newer
        version" for these; the exported label is now the same one it renders."""
        import dataclasses

        from ossiq.domain.common import RecommendationRung
        from ossiq.domain.version import VersionsDifference

        record = dataclasses.replace(
            sample_project_metrics_record,
            latest_version="17.9.0",
            versions_diff_index=VersionsDifference(
                version1="17.0.2", version2="17.9.0", diff_index=4, diff_name="DIFF_MINOR"
            ),
            compatibility=CompatibilityFacts(latest_in_range="17.0.2", latest_in_major="17.9.0"),
            version_constraint="~17.0.2",
            version_constraint_declared="~17.0.2",
            recommended_version="17.9.0",
            recommended_from_rung=RecommendationRung.IN_MAJOR,
        )
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[record],
            optional_packages=[],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        pkg = json.loads(output_file.read_text(encoding="utf-8"))["production_packages"][0]
        assert pkg["next_action"] == "Constrained. Check newer version"
        assert pkg["requires_constraint_widening"] is True

    def test_v1_5_in_range_pick_does_not_require_widening(self, output_file, settings, sample_project_metrics_record):
        import dataclasses

        from ossiq.domain.common import RecommendationRung

        record = dataclasses.replace(
            sample_project_metrics_record,
            recommended_version="18.2.0",
            recommended_from_rung=RecommendationRung.SOLVER,
        )
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[record],
            optional_packages=[],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        pkg = json.loads(output_file.read_text(encoding="utf-8"))["production_packages"][0]
        assert pkg["requires_constraint_widening"] is False

    def test_v1_5_emits_module_system_fields_and_validates(self, output_file, settings, sample_project_metrics_record):
        """latest_compatible_major/module_system/recommended_module_system/breaking_change
        round-trip on PackageMetrics and validate against the v1.5 schema."""
        import dataclasses

        record = dataclasses.replace(
            sample_project_metrics_record,
            compatibility=CompatibilityFacts(
                latest_compatible_major="4.1.2",
                module_system=ModuleSystem.CJS,
                recommended_module_system=ModuleSystem.ESM_ONLY,
                breaking_change="ESM-only from 5.0.0",
            ),
            recommended_version="5.0.0",
        )
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[record],
            optional_packages=[],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        pkg = data["production_packages"][0]
        assert pkg["latest_compatible_major"] == "4.1.2"
        assert pkg["module_system"] == "cjs"  # plain string, not an enum repr
        assert pkg["recommended_module_system"] == "esm-only"
        assert pkg["breaking_change"] == "ESM-only from 5.0.0"
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5))

    def test_v1_5_emits_module_system_fields_on_transitive_and_validates(
        self, output_file, settings, sample_project_metrics_record
    ):
        """latest_compatible_major/module_system/recommended_module_system round-trip on
        TransitivePackageMetrics too - no breaking_change field there (no recommended_version)."""
        transitive = ScanRecord(
            package_name="chalk",
            dependency_name=None,
            is_optional_dependency=False,
            installed_version="4.1.2",
            latest_version="4.1.2",
            versions_diff_index=VersionsDifference(
                version1="4.1.2", version2="4.1.2", diff_index=0, diff_name="LATEST"
            ),
            time_lag_days=0,
            releases_lag=0,
            cve=[],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
            compatibility=CompatibilityFacts(
                latest_compatible_major="4.1.2",
                module_system=ModuleSystem.CJS,
                recommended_module_system=ModuleSystem.CJS,
            ),
        )
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[sample_project_metrics_record],
            optional_packages=[],
            transitive_packages=[transitive],
            engine_context=EngineContext({"node": ">=18.0.0"}, EngineContextSource.DECLARED),
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        entry = data["transitive_packages"][0]
        assert entry["latest_compatible_major"] == "4.1.2"
        assert entry["module_system"] == "cjs"
        assert entry["recommended_module_system"] == "cjs"
        assert "breaking_change" not in entry
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5))

    def test_v1_5_emits_the_nested_strategy_object_and_validates(
        self, output_file, settings, sample_project_metrics_record
    ):
        """The selector's verdict is one nested object built by StrategySelectionExport.from_domain,
        not four flattened fields each guarding on `if record.strategy_selection` at the call site."""
        import dataclasses

        record = dataclasses.replace(
            sample_project_metrics_record,
            recommended_version="1.2.0",
            strategy_selection=StrategySelection(
                strategy=UpdateStrategy.STANDARD,
                target_version="1.2.0",
                rung=RecommendationRung.IN_MAJOR,
                motives=frozenset({UpdateMotive.DRIFT}),
                requires_widening=True,
                withheld_reason=None,
                available_at=None,
                escalation="nothing in reach",
            ),
        )
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[record],
            optional_packages=[],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert data["production_packages"][0]["strategy"] == {
            "motives": ["drift"],
            "withheld_reason": None,
            "requires_widening": True,
            "escalation": "nothing in reach",
        }
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5))

    def test_v1_5_strategy_is_null_when_the_selector_never_ran(
        self, output_file, settings, sample_project_metrics_record
    ):
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[sample_project_metrics_record],
            optional_packages=[],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert data["production_packages"][0]["strategy"] is None
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5))

    def test_v1_5_emits_engine_fields_and_validates(self, output_file, settings, sample_project_metrics_record):
        """engine_requirement/engine_compatible round-trip on PackageMetrics, and the runtime the
        scan checked them against is stated once at the top rather than on every record."""
        import dataclasses

        record = dataclasses.replace(
            sample_project_metrics_record,
            recommended_version="1.2.0",
            compatibility=CompatibilityFacts(engine_requirement={"node": ">=22.0.0"}, engine_compatible=False),
        )
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[record],
            optional_packages=[],
            engine_context=EngineContext({"node": "20.11.0"}, EngineContextSource.DETECTED),
            npm_cli_version="10.2.4",
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        pkg = data["production_packages"][0]
        assert pkg["engine_requirement"] == {"node": ">=22.0.0"}
        assert pkg["engine_compatible"] is False
        # Provenance is one fact about the scan; it used to be denormalized onto every record and
        # the copies drifted within a single run.
        assert "engine_context_source" not in pkg
        assert data["runtime_context"] == {
            "engine_versions": {"node": "20.11.0"},
            "engine_context_source": "detected",  # plain string, not an enum repr
            "npm_cli_version": "10.2.4",
            "project_declares_esm": False,
        }
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5))

    def test_v1_5_emits_engine_fields_on_transitive_and_validates(
        self, output_file, settings, sample_project_metrics_record
    ):
        """engine_requirement/engine_compatible round-trip on TransitivePackageMetrics too - engine
        compatibility is meaningful for transitives independent of what's recommended for their
        parent."""
        transitive = ScanRecord(
            package_name="chalk",
            dependency_name=None,
            is_optional_dependency=False,
            installed_version="4.1.2",
            latest_version="4.1.2",
            versions_diff_index=VersionsDifference(
                version1="4.1.2", version2="4.1.2", diff_index=0, diff_name="LATEST"
            ),
            time_lag_days=0,
            releases_lag=0,
            cve=[],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
            compatibility=CompatibilityFacts(engine_requirement={"node": ">=22.0.0"}, engine_compatible=True),
        )
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[sample_project_metrics_record],
            optional_packages=[],
            transitive_packages=[transitive],
            engine_context=EngineContext({"node": ">=18.0.0"}, EngineContextSource.DECLARED),
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        entry = data["transitive_packages"][0]
        assert entry["engine_requirement"] == {"node": ">=22.0.0"}
        assert entry["engine_compatible"] is True
        assert "engine_context_source" not in entry
        assert data["runtime_context"]["engine_context_source"] == "declared"
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5))

    def test_v1_5_emits_declared_constraint_distinct_from_effective_and_validates(
        self, output_file, settings, sample_project_metrics_record
    ):
        """version_constraint_declared round-trips and stays distinct from version_constraint,
        the last-writer-wins accumulator a competing transitive/peer parent can clobber."""
        import dataclasses

        record = dataclasses.replace(
            sample_project_metrics_record,
            version_constraint="^1.2.0",
            version_constraint_declared="~1.0.0",
        )
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[record],
            optional_packages=[],
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        pkg = data["production_packages"][0]
        assert pkg["version_constraint"] == "^1.2.0"
        assert pkg["version_constraint_declared"] == "~1.0.0"
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5))

    def test_v1_5_emits_rejected_candidates_and_validates(self, output_file, settings, sample_project_metrics_record):
        """rejected_candidates round-trips on both PackageMetrics and TransitivePackageMetrics."""
        import dataclasses

        from ossiq.domain.common import RejectedCandidate

        record = dataclasses.replace(
            sample_project_metrics_record,
            rejected_candidates=[RejectedCandidate(version="18.2.0", reason="dep-x requires >=2.0.0")],
        )
        transitive = ScanRecord(
            package_name="dep-y",
            dependency_name=None,
            is_optional_dependency=False,
            installed_version="1.0.0",
            latest_version="1.0.0",
            versions_diff_index=VersionsDifference(
                version1="1.0.0", version2="1.0.0", diff_index=0, diff_name="LATEST"
            ),
            time_lag_days=0,
            releases_lag=0,
            cve=[],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
            rejected_candidates=[RejectedCandidate(version="2.0.0", reason="dep-z needs >=3.0.0, held at 1.0.0")],
        )
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[record],
            optional_packages=[],
            transitive_packages=[transitive],
            engine_context=EngineContext({"node": ">=18.0.0"}, EngineContextSource.DECLARED),
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        pkg = data["production_packages"][0]
        assert pkg["rejected_candidates"] == [{"version": "18.2.0", "reason": "dep-x requires >=2.0.0"}]
        trans_entry = data["transitive_packages"][0]
        assert trans_entry["rejected_candidates"] == [
            {"version": "2.0.0", "reason": "dep-z needs >=3.0.0, held at 1.0.0"}
        ]
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5))

    def test_v1_5_transitive_ladder_fields_omitted_when_null(
        self, output_file, settings, sample_project_metrics_record
    ):
        """Undeterminable ladder rungs are dropped on TransitivePackageMetrics by _compact,
        distinguishing "not analysed" from PackageMetrics' explicit null."""
        transitive = ScanRecord(
            package_name="dep",
            dependency_name=None,
            is_optional_dependency=False,
            installed_version="1.0.0",
            latest_version=None,
            versions_diff_index=VersionsDifference(
                version1="1.0.0", version2="1.0.0", diff_index=0, diff_name="LATEST"
            ),
            time_lag_days=None,
            releases_lag=None,
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
            transitive_packages=[transitive],
            engine_context=EngineContext({"node": ">=18.0.0"}, EngineContextSource.DECLARED),
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(metrics, destination=str(output_file), schema_version="1.5")

        data = json.loads(output_file.read_text(encoding="utf-8"))
        entry = data["transitive_packages"][0]
        assert "latest_in_range" not in entry
        assert "latest_in_major" not in entry
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5))


@pytest.fixture
def engagement_record():
    """ScanRecord carrying a two-bucket engagement sample, for the raw-bucket export."""
    buckets = [
        EngagementBucket(index=0, issues_opened=4, issues_closed=3, prs_opened=2, prs_merged=2),
        EngagementBucket(index=1, issues_opened=1, issues_closed=0, prs_opened=1, prs_merged=0),
    ]
    return ScanRecord(
        package_name="flowing-lib",
        dependency_name="flowing-lib",
        is_optional_dependency=False,
        installed_version="1.0.0",
        latest_version="1.0.0",
        versions_diff_index=VersionsDifference(version1="1.0.0", version2="1.0.0", diff_index=0, diff_name="LATEST"),
        time_lag_days=0,
        releases_lag=0,
        cve=[],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
        stability=RepositoryStability(
            flow_trend="declining",
            engagement=EngagementSeries(buckets, "declining"),
        ),
    )


class TestJsonExportRendererEngagementBuckets:
    """The raw engagement buckets the calibration path re-fits offline."""

    def export(self, output_file, settings, record):
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[record],
            optional_packages=[],
        )
        JsonExportRenderer(settings).render(metrics, destination=str(output_file), schema_version="1.5")
        return json.loads(output_file.read_text(encoding="utf-8"))

    def test_buckets_exported_as_fixed_order_rows(self, output_file, settings, engagement_record):
        """Oldest bucket first, one [issues_opened, issues_closed, prs_opened, prs_merged] row each."""
        data = self.export(output_file, settings, engagement_record)

        assert data["production_packages"][0]["engagement_buckets"] == [[4, 3, 2, 2], [1, 0, 1, 0]]

    def test_buckets_validate_against_v1_5_schema(self, output_file, settings, engagement_record):
        data = self.export(output_file, settings, engagement_record)

        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5))

    def test_buckets_null_without_activity_sample(self, output_file, settings, sample_project_metrics_record):
        """Unmeasured is null, never an empty bucket list that would read as zero flow."""
        data = self.export(output_file, settings, sample_project_metrics_record)

        assert data["production_packages"][0]["engagement_buckets"] is None


def test_compatibility_cluster_stays_flat_on_the_wire(output_file, settings, sample_project_metrics_record):
    """The domain nests these eight fields in CompatibilityFacts; the published contract does not.

    Only one of the two shapes has consumers outside this repo, so nesting the record was allowed
    to change the model but must not change the JSON. Guards against a future "tidy-up" quietly
    reshaping the export to match the domain.
    """
    import dataclasses

    record = dataclasses.replace(
        sample_project_metrics_record,
        recommended_version="5.0.0",
        compatibility=CompatibilityFacts(
            latest_in_range="4.1.2",
            latest_in_major="4.9.0",
            latest_compatible_major="4.1.2",
            module_system=ModuleSystem.CJS,
            recommended_module_system=ModuleSystem.ESM_ONLY,
            breaking_change="ESM-only from 5.0.0",
            engine_requirement={"node": ">=22.0.0"},
            engine_compatible=False,
        ),
    )
    metrics = ScanResult(
        project_name="test-project",
        project_path="/path/to/test-project",
        packages_registry=ProjectPackagesRegistry.NPM.value,
        production_packages=[record],
        optional_packages=[],
    )
    JsonExportRenderer(settings).render(metrics, destination=str(output_file), schema_version="1.5")

    pkg = json.loads(output_file.read_text(encoding="utf-8"))["production_packages"][0]

    assert "compatibility" not in pkg
    assert pkg["latest_in_range"] == "4.1.2"
    assert pkg["latest_in_major"] == "4.9.0"
    assert pkg["latest_compatible_major"] == "4.1.2"
    assert pkg["module_system"] == "cjs"
    assert pkg["recommended_module_system"] == "esm-only"
    assert pkg["breaking_change"] == "ESM-only from 5.0.0"
    assert pkg["engine_requirement"] == {"node": ">=22.0.0"}
    assert pkg["engine_compatible"] is False
