"""
Tests for JSON export renderer.

This test suite follows pytest best practices:
- AAA pattern (Arrange-Act-Assert) for clear test structure
- Parametrization to reduce test duplication
- Fixtures for reusable setup/teardown
- Single responsibility per test
- Mocking external dependencies where appropriate
"""

import dataclasses
import json
from typing import Any

import pytest
from jsonschema import ValidationError, validate

from ossiq.domain.common import (
    Command,
    ConstraintType,
    DataCompleteness,
    DataSourceStatus,
    DegradeReason,
    EngineContext,
    EngineContextSource,
    ExportJsonSchemaVersion,
    ExportProfile,
    FetchDiagnostics,
    ModuleSystem,
    ProjectPackagesRegistry,
    RateLimitBudget,
    RecommendationRung,
    RegistryStatus,
    RuntimeMismatch,
    ScanStep,
    UserInterfaceType,
)
from ossiq.domain.compatibility import CompatibilityFacts
from ossiq.domain.cve import CVE, AffectedRange, CveDatabase, Severity
from ossiq.domain.exceptions import DestinationDoesntExist
from ossiq.domain.project import ConstraintSource, UnresolvedPeer
from ossiq.domain.version import VersionsDifference
from ossiq.risk.stability import EngagementBucket, EngagementSeries
from ossiq.risk.triage import ACTION_REFACTOR, TriageResult
from ossiq.service.library_scan import UpgradePath
from ossiq.service.project.models import IgnoredDependency, PeerRepair, ScanRecord, ScanResult
from ossiq.service.project.stability import RepositoryStability
from ossiq.service.update_impact import ImpactKind, TransitiveImpact
from ossiq.settings import Settings
from ossiq.strategy.motive import UpdateMotive
from ossiq.strategy.pyramid import UpdateStrategy
from ossiq.strategy.targeting import StrategySelection
from ossiq.ui.renderers.export import models as export_models
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
        renderer.render(sample_project_metrics, destination="-", profile=ExportProfile.FULL)

        captured = capsys.readouterr()
        assert captured.err == ""
        data = json.loads(captured.out)
        assert data["project"]["name"] == "test-project"

    def test_dash_destination_does_not_create_a_file_named_dash(
        self, sample_project_metrics, settings, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_metrics, destination="-", profile=ExportProfile.FULL)

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
        renderer.render(sample_project_metrics, destination=str(output_file), profile=ExportProfile.FULL)

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
        renderer.render(sample_project_metrics, destination=str(output_file), profile=ExportProfile.FULL)

        # Act
        data = json.loads(output_file.read_text(encoding="utf-8"))
        metadata = data["metadata"]

        # Assert: with no version asked for, the latest is declared
        assert metadata["schema_version"] == "1.6"
        assert "export_timestamp" in metadata
        assert "ossiq_version" not in metadata

    def test_metadata_data_completeness_defaults_to_ok_with_no_sources(
        self, output_file, sample_project_metrics, settings
    ):
        """A ScanResult built without any tracked completeness (the common test-fixture case)
        must not be mistaken for a scan with degraded sources.
        """
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(output_file), profile=ExportProfile.FULL)

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
        renderer.render(scan, destination=str(output_file), profile=ExportProfile.FULL)

        data = json.loads(output_file.read_text(encoding="utf-8"))
        completeness = data["metadata"]["data_completeness"]

        assert completeness["overall"] == "unreachable"
        assert {"step": "vulnerabilities", "status": "unreachable", "failures": []} in completeness["sources"]
        assert {"step": "repositories", "status": "ok", "failures": []} in completeness["sources"]

    def test_metadata_data_completeness_carries_causes_and_quota(
        self, output_file, sample_project_metrics_record, settings
    ):
        """Why a source degraded, and the quota behind it: a consumer that can see "3 not found"
        knows a retry changes nothing, where a bare `partial` invites one into a spent quota."""
        scan = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[sample_project_metrics_record],
            optional_packages=[],
            data_completeness=DataCompleteness(
                by_step={ScanStep.REPOSITORIES: DataSourceStatus.PARTIAL},
                diagnostics={
                    ScanStep.REPOSITORIES: FetchDiagnostics(
                        failures=((DegradeReason.NOT_FOUND, 3),),
                        budgets=(RateLimitBudget(resource="core", limit=5000, remaining=120, reset_at=1700000000.0),),
                    )
                },
            ),
        )
        renderer = JsonExportRenderer(settings)
        renderer.render(scan, destination=str(output_file), profile=ExportProfile.FULL)

        completeness = json.loads(output_file.read_text(encoding="utf-8"))["metadata"]["data_completeness"]

        assert completeness["sources"] == [
            {"step": "repositories", "status": "partial", "failures": [{"reason": "not_found", "count": 3}]}
        ]
        assert completeness["api_budgets"] == [
            {"resource": "core", "limit": 5000, "remaining": 120, "reset_at": 1700000000.0, "needed": None}
        ]

    def test_project_fields_match_input_data(self, output_file, sample_project_metrics, settings):
        """Test project section matches input data.

        AAA Pattern:
        - Arrange: Set up renderer with known project data
        - Act: Render export and extract project section
        - Assert: Verify project fields match input
        """
        # Arrange
        renderer = JsonExportRenderer(settings)
        renderer.render(sample_project_metrics, destination=str(output_file), profile=ExportProfile.FULL)

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
        renderer.render(sample_project_metrics, destination=str(output_file), profile=ExportProfile.FULL)

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
        renderer.render(sample_project_metrics, destination=str(output_file), profile=ExportProfile.FULL)

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
        renderer.render(sample_project_metrics, destination=str(output_template), profile=ExportProfile.FULL)

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
            renderer.render(
                sample_project_metrics, destination="/nonexistent/dir/export.json", profile=ExportProfile.FULL
            )

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
        renderer.render(metrics, destination=str(output_file), profile=ExportProfile.FULL)
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
        renderer.render(sample_project_metrics, destination=str(output_file), profile=ExportProfile.FULL)
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
        renderer.render(sample_project_metrics, destination=str(output_file), profile=ExportProfile.FULL)

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
        renderer.render(
            sample_project_metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL
        )

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
        renderer.render(sample_project_metrics, destination=str(output_file), profile=ExportProfile.FULL)

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
        renderer.render(
            sample_project_with_transitives,
            destination=str(output_file),
            schema_version="1.5",
            profile=ExportProfile.FULL,
        )

        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert len(data["transitive_packages"]) == 1

    def test_v1_3_output_has_dependency_tree(self, output_file, sample_project_with_transitives, settings):
        """v1.3 output must contain a top-level dependency_tree array."""
        renderer = JsonExportRenderer(settings)
        renderer.render(
            sample_project_with_transitives,
            destination=str(output_file),
            schema_version="1.5",
            profile=ExportProfile.FULL,
        )

        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert "dependency_tree" in data
        assert isinstance(data["dependency_tree"], list)

    def test_v1_3_dependency_tree_has_roots_for_both_paths(
        self, output_file, sample_project_with_transitives, settings
    ):
        """Tree must have roots for react-dom and react (the two direct parents from the test fixtures)."""
        renderer = JsonExportRenderer(settings)
        renderer.render(
            sample_project_with_transitives,
            destination=str(output_file),
            schema_version="1.5",
            profile=ExportProfile.FULL,
        )

        data = json.loads(output_file.read_text(encoding="utf-8"))
        root_names = {r["package_name"] for r in data["dependency_tree"]}
        assert "react-dom" in root_names
        assert "react" in root_names

    def test_v1_3_tree_nodes_carry_constraint_fields(self, output_file, sample_project_with_transitives, settings):
        """Each tree node must carry ref, ct, and version_constraint."""
        renderer = JsonExportRenderer(settings)
        renderer.render(
            sample_project_with_transitives,
            destination=str(output_file),
            schema_version="1.5",
            profile=ExportProfile.FULL,
        )

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
        renderer.render(
            sample_project_with_transitives,
            destination=str(output_file),
            schema_version="1.5",
            profile=ExportProfile.FULL,
        )

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
        renderer.render(
            sample_project_with_transitives,
            destination=str(output_file),
            schema_version="1.5",
            profile=ExportProfile.FULL,
        )

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
        renderer.render(
            sample_project_with_transitives,
            destination=str(output_file),
            schema_version="1.5",
            profile=ExportProfile.FULL,
        )

        data = json.loads(output_file.read_text(encoding="utf-8"))
        entry = data["transitive_packages"][0]
        assert "dependency_path" not in entry
        assert "dependency_paths" not in entry

    def test_v1_3_invariant_fields_on_transitive_entry(self, output_file, sample_project_with_transitives, settings):
        """Invariant fields (id, package_name, installed_version, cve) must be on transitive entries."""
        renderer = JsonExportRenderer(settings)
        renderer.render(
            sample_project_with_transitives,
            destination=str(output_file),
            schema_version="1.5",
            profile=ExportProfile.FULL,
        )

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
        renderer.render(
            sample_project_with_transitives,
            destination=str(output_file),
            schema_version="1.5",
            profile=ExportProfile.FULL,
        )

        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert "constraint_type_map" in data
        assert data["constraint_type_map"] == ["DECLARED", "NARROWED", "PINNED", "ADDITIVE", "OVERRIDE"]

    def test_v1_3_tree_node_has_no_null_fields(self, output_file, sample_project_with_transitives, settings):
        """Tree nodes must not contain null or empty-list fields."""
        renderer = JsonExportRenderer(settings)
        renderer.render(
            sample_project_with_transitives,
            destination=str(output_file),
            schema_version="1.5",
            profile=ExportProfile.FULL,
        )

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
        renderer.render(
            sample_project_with_transitives,
            destination=str(output_file),
            schema_version="1.5",
            profile=ExportProfile.FULL,
        )

        data = json.loads(output_file.read_text(encoding="utf-8"))
        # transitive_record_b has NARROWED constraint with source_file="package.json"
        entry = data["transitive_packages"][0]
        assert entry.get("constraint_source_file") == "package.json"

    def test_v1_3_cve_taken_from_first_record(self, output_file, sample_project_with_transitives, settings):
        """CVE data is read from the first record in the group (invariant field)."""
        renderer = JsonExportRenderer(settings)
        renderer.render(
            sample_project_with_transitives,
            destination=str(output_file),
            schema_version="1.5",
            profile=ExportProfile.FULL,
        )

        data = json.loads(output_file.read_text(encoding="utf-8"))
        # transitive_record_a (first) has 1 CVE; transitive_record_b has 0
        assert len(data["transitive_packages"][0]["cve"]) == 1

    def test_v1_3_output_validates_against_v1_3_schema(self, output_file, sample_project_with_transitives, settings):
        """v1.3 output must pass jsonschema validation against the v1.3 schema."""
        from jsonschema import validate

        renderer = JsonExportRenderer(settings)
        renderer.render(
            sample_project_with_transitives,
            destination=str(output_file),
            schema_version="1.5",
            profile=ExportProfile.FULL,
        )

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

        data = json.loads(output_file.read_text(encoding="utf-8"))
        entry = data["transitive_packages"][0]
        assert entry["is_prerelease"] is True
        assert entry["is_yanked"] is False

    def test_v1_4_output_validates_against_v1_4_schema(self, output_file, settings, sample_project_with_transitives):
        """v1.4 output must pass jsonschema validation against the v1.4 schema."""
        from jsonschema import validate

        renderer = JsonExportRenderer(settings)
        renderer.render(
            sample_project_with_transitives,
            destination=str(output_file),
            schema_version="1.5",
            profile=ExportProfile.FULL,
        )

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        JsonExportRenderer(settings).render(
            metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL
        )

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

        pkg = json.loads(output_file.read_text(encoding="utf-8"))["production_packages"][0]
        assert pkg["requires_constraint_widening"] is False

    def test_v1_5_emits_dependency_health_action_and_validates(
        self, output_file, settings, sample_project_metrics_record
    ):
        import dataclasses

        record = dataclasses.replace(
            sample_project_metrics_record,
            triage=TriageResult(ACTION_REFACTOR, "No exploit pressure, but ...", None, 0, False),
        )
        metrics = ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[record],
            optional_packages=[],
        )
        JsonExportRenderer(settings).render(
            metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL
        )

        data = json.loads(output_file.read_text(encoding="utf-8"))
        pkg = data["production_packages"][0]
        assert pkg["dependency_health_action"] == "refactor"
        assert "triage_action" not in pkg
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5))

    def test_v1_5_emits_module_system_fields_and_validates(self, output_file, settings, sample_project_metrics_record):
        """latest_compatible_major/module_system/recommended_module_system/breaking_change
        round-trip on PackageMetrics and validate against the v1.5 schema."""
        import dataclasses

        record = dataclasses.replace(
            sample_project_metrics_record,
            compatibility=CompatibilityFacts(
                latest_compatible_major="6.0.0",
                latest_preserving_module_system="4.1.2",
                module_system=ModuleSystem.CJS,
                module_system_note="ESM-only: won't load via require() on Node 18.20.8",
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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

        data = json.loads(output_file.read_text(encoding="utf-8"))
        pkg = data["production_packages"][0]
        assert pkg["latest_compatible_major"] == "6.0.0"
        assert pkg["latest_preserving_module_system"] == "4.1.2"
        assert pkg["module_system_note"] == "ESM-only: won't load via require() on Node 18.20.8"
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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
            "runtime_mismatch": None,
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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

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
        renderer.render(metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL)

        data = json.loads(output_file.read_text(encoding="utf-8"))
        entry = data["transitive_packages"][0]
        assert "latest_in_range" not in entry
        assert "latest_in_major" not in entry
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5))


@pytest.fixture
def engagement_record():
    """ScanRecord carrying a two-bucket engagement sample, for the raw-bucket export."""
    buckets = [
        EngagementBucket(index=0, issues_opened=4, issues_closed=3, prs_opened=2, prs_closed=2),
        EngagementBucket(index=1, issues_opened=1, issues_closed=0, prs_opened=1, prs_closed=0),
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
        JsonExportRenderer(settings).render(
            metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL
        )
        return json.loads(output_file.read_text(encoding="utf-8"))

    def test_buckets_exported_as_fixed_order_rows(self, output_file, settings, engagement_record):
        """Oldest bucket first, one [issues_opened, issues_closed, prs_opened, prs_closed] row each."""
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
    JsonExportRenderer(settings).render(
        metrics, destination=str(output_file), schema_version="1.5", profile=ExportProfile.FULL
    )

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


# ── Export profiles ────────────────────────────────────────────────────────────


def profile_record(name: str, installed: str = "1.0.0", **fields: Any) -> ScanRecord:
    """A ScanRecord with the full-only fields populated, so a profile test can watch them go."""
    record = ScanRecord(
        package_name=name,
        dependency_name=name,
        is_optional_dependency=False,
        installed_version=installed,
        latest_version="2.0.0",
        versions_diff_index=VersionsDifference(installed, "2.0.0", 5, "DIFF_MAJOR"),
        time_lag_days=100,
        releases_lag=3,
        cve=[],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
        version_constraint=f"^{installed}",
        version_constraint_declared=f"^{installed}",
        version_age_days=400,
        license=["MIT"],
        repo_url=f"https://github.com/example/{name}",
        homepage_url=f"https://example.com/{name}",
        package_url=f"https://www.npmjs.com/package/{name}",
        purl=f"pkg:npm/{name}@{installed}",
        days_since_push=30,
    )
    return dataclasses.replace(record, **fields)


def enumerated_advisory(name: str) -> CVE:
    """An advisory that enumerates sixty affected versions - D3's single largest field."""
    return CVE(
        id=f"GHSA-{name}",
        cve_ids=(f"CVE-2024-{name}",),
        source=CveDatabase.OSV,
        package_name=name,
        package_registry=ProjectPackagesRegistry.NPM,
        summary=f"{name} is vulnerable",
        severity=Severity.HIGH,
        affected_versions=tuple(f"0.{minor}.0" for minor in range(60)),
        published="2024-01-01T00:00:00Z",
        link=f"https://osv.dev/GHSA-{name}",
        epss=0.2,
        fix_versions=("1.0.1",),
        affected_ranges=(AffectedRange(fixed="1.0.1"),),
    )


@pytest.fixture
def profile_scan() -> ScanResult:
    """Two direct dependencies (one vulnerable, one with nothing to do) and five transitives, only
    one of which needs attention - the other four merely drift."""
    vulnerable = profile_record("vulnerable", cve=[enumerated_advisory("vulnerable")], recommended_version="1.0.1")
    quiet = profile_record(
        "quiet",
        latest_version="1.0.0",
        versions_diff_index=VersionsDifference("1.0.0", "1.0.0", 0, "LATEST"),
        time_lag_days=0,
        releases_lag=0,
    )
    transitives = [
        profile_record(
            "risky-dep",
            dependency_path=["vulnerable"],
            cve=[enumerated_advisory("risky-dep")],
            recommended_version="1.0.1",
        ),
        *(profile_record(f"drift-{i}", dependency_path=["quiet"], recommended_version="2.0.0") for i in range(4)),
    ]
    return ScanResult(
        project_name="profiles",
        project_path="/path/to/profiles",
        packages_registry=ProjectPackagesRegistry.NPM.value,
        production_packages=[vulnerable, quiet],
        optional_packages=[],
        transitive_packages=transitives,
        ignored_packages=[
            IgnoredDependency(name="private-lib", spec="git+https://example.com/private-lib.git", reason="git source")
        ],
        upgrade_paths=[
            UpgradePath(
                package_name="quiet",
                current_constraint="^1.0.0",
                latest_in_range="1.0.0",
                latest_available="2.0.0",
                suggested_constraint="^2.0.0",
            )
        ],
        manifest_lock_divergent=["quiet"],
        engine_context=EngineContext({"node": "20.11.0"}, EngineContextSource.PROVIDED),
        runtime_mismatch=RuntimeMismatch(
            engine="node",
            pinned="22.12.0",
            pin_file=".nvmrc",
            runtime="20.11.0",
            runtime_source=EngineContextSource.PROVIDED,
        ),
    )


def render_profile(
    settings: Settings,
    scan: ScanResult,
    output_file,
    profile: ExportProfile | None = None,
    schema_version: str | None = None,
) -> dict:
    """Render *scan* the way `ossiq export` does - the renderer's own defaults when an argument is None."""
    renderer = JsonExportRenderer(settings)
    options: dict[str, Any] = {}
    if profile is not None:
        options["profile"] = profile
    if schema_version is not None:
        options["schema_version"] = schema_version
    renderer.render(scan, destination=str(output_file), **options)
    return json.loads(output_file.read_text(encoding="utf-8"))


class TestExportProfiles:
    """D3: `ossiq export` emits the standard profile; `--full` keeps today's document."""

    def test_default_is_standard_and_validates_against_its_own_schema(self, settings, profile_scan, output_file):
        data = render_profile(settings, profile_scan, output_file)

        assert data["metadata"]["profile"] == "standard"
        validate(
            instance=data,
            schema=json_schema_registry.load_schema(json_schema_registry.get_latest_version(), ExportProfile.STANDARD),
        )

    def test_full_validates_against_the_full_schema_and_not_the_standard_one(self, settings, profile_scan, output_file):
        data = render_profile(settings, profile_scan, output_file, ExportProfile.FULL)

        assert data["metadata"]["profile"] == "full"
        latest = json_schema_registry.get_latest_version()
        validate(instance=data, schema=json_schema_registry.load_schema(latest, ExportProfile.FULL))
        with pytest.raises(ValidationError):
            validate(instance=data, schema=json_schema_registry.load_schema(latest, ExportProfile.STANDARD))

    def test_standard_carries_no_full_only_field(self, settings, profile_scan, output_file):
        data = render_profile(settings, profile_scan, output_file)

        assert not data.keys() & export_models.full_only_fields(export_models.ExportData)
        assert not data["metadata"]["data_completeness"].keys() & export_models.full_only_fields(
            export_models.DataCompletenessExport
        )
        for entry in data["production_packages"]:
            assert not entry.keys() & export_models.full_only_fields(export_models.PackageMetrics)
        for entry in data["transitive_packages"]:
            assert not entry.keys() & export_models.full_only_fields(export_models.TransitivePackageMetrics)
        for entry in data["production_packages"] + data["transitive_packages"]:
            for cve in entry.get("cve", []):
                assert not cve.keys() & export_models.full_only_fields(export_models.CVEInfo)

    def test_standard_keeps_every_direct_dependency(self, settings, profile_scan, output_file):
        """B7: an omitted entry can't be told apart from one that was never analysed."""
        data = render_profile(settings, profile_scan, output_file)

        assert [entry["package_name"] for entry in data["production_packages"]] == ["vulnerable", "quiet"]

    def test_standard_keeps_only_the_transitives_that_need_attention(self, settings, profile_scan, output_file):
        data = render_profile(settings, profile_scan, output_file)

        assert [entry["package_name"] for entry in data["transitive_packages"]] == ["risky-dep"]
        assert data["summary"]["transitive_packages"] == 5

    def test_full_keeps_every_transitive_and_the_tree(self, settings, profile_scan, output_file):
        data = render_profile(settings, profile_scan, output_file, ExportProfile.FULL)

        assert len(data["transitive_packages"]) == data["summary"]["transitive_packages"] == 5
        assert {root["package_name"] for root in data["dependency_tree"]} == {"vulnerable", "quiet"}
        assert data["constraint_type_map"] == export_models.CONSTRAINT_TYPE_MAP

    def test_standard_emits_required_fields_even_when_null(self, settings, profile_scan, output_file):
        profile_scan.production_packages[1].latest_version = None

        (_, quiet) = render_profile(settings, profile_scan, output_file)["production_packages"]

        assert quiet["latest_version"] is None
        assert quiet["cve"] == []
        assert "recommended_version" not in quiet

    def test_standard_is_a_fraction_of_full(self, settings, profile_scan, tmp_path):
        standard = render_profile(settings, profile_scan, tmp_path / "standard.json")
        full = render_profile(settings, profile_scan, tmp_path / "full.json", ExportProfile.FULL)

        standard_bytes = len(json.dumps(standard, separators=(",", ":")))
        full_bytes = len(json.dumps(full, separators=(",", ":")))
        assert standard_bytes <= 0.4 * full_bytes, (standard_bytes, full_bytes)

    def test_standard_field_sets_are_a_deliberate_choice(self):
        """Guards against the payload creeping back: a new field fails here until someone decides
        whether an agent needs it (leave it) or only dashboards and archives do (tag it FULL_ONLY)."""

        def standard_fields(model) -> set[str]:
            return set(model.model_fields) - export_models.full_only_fields(model)

        assert standard_fields(export_models.CVEInfo) == {
            "id",
            "cve_ids",
            "severity",
            "summary",
            "epss",
            "fix_age_days",
            "link",
            "affected_ranges",
            "fixed_in",
        }
        shared = {
            "package_name",
            "installed_version",
            "latest_version",
            "time_lag_days",
            "releases_lag",
            "cve",
            "latest_in_range",
            "latest_in_major",
            "latest_compatible_major",
            "latest_preserving_module_system",
            "recommended_version",
            "rejected_candidates",
            "next_action",
            "module_system",
            "recommended_module_system",
            "module_system_note",
            "engine_requirement",
            "engine_compatible",
            "is_prerelease",
            "is_yanked",
            "is_deprecated",
            "is_package_unpublished",
            "epss",
            "runs_code_at_install",
            "install_execution_reason",
            "maintenance_risk",
            "maintenance_state",
            "deprecation_signals",
            "deprecation_successor",
            "archived",
            "dependency_health_action",
            "unresolved_peers",
            # An agent weighing an add or an update acts on a retired package, and the note usually
            # names what replaces it, so neither is dashboard-only.
            "registry_status",
            "deprecation_message",
        }
        assert standard_fields(export_models.PackageMetrics) == shared | {
            "dependency_name",
            "is_optional_dependency",
            "version_constraint_declared",
            "constraint_type",
            # An agent reading OVERRIDE has to tell the user's rule, which holds an update, from the one
            # OSS IQ wrote and moves itself.
            "constraint_ossiq_authored",
            "extras",
            "breaking_change",
            "recommended_from_rung",
            "requires_constraint_widening",
            "update_transitive_impacts",
            "strategy",
        }
        assert standard_fields(export_models.TransitivePackageMetrics) == shared | {"required_by"}

    @pytest.mark.parametrize("profile", [ExportProfile.STANDARD, ExportProfile.FULL])
    def test_cve_carries_its_ranges_and_fixes(self, settings, profile_scan, output_file, profile):
        data = render_profile(settings, profile_scan, output_file, profile)

        (cve,) = data["production_packages"][0]["cve"]
        assert cve["affected_ranges"] == ["<1.0.1"]
        assert cve["fixed_in"] == ["1.0.1"]
        assert ("affected_versions" in cve) is (profile == ExportProfile.FULL)

    @pytest.mark.parametrize("profile", [ExportProfile.STANDARD, ExportProfile.FULL])
    def test_transitive_carries_its_recommendation_and_direct_roots(self, settings, profile_scan, output_file, profile):
        data = render_profile(settings, profile_scan, output_file, profile)

        risky = next(entry for entry in data["transitive_packages"] if entry["package_name"] == "risky-dep")
        assert risky["recommended_version"] == "1.0.1"
        assert risky["required_by"] == ["vulnerable"]

    @pytest.mark.parametrize("profile", [ExportProfile.STANDARD, ExportProfile.FULL])
    def test_scan_level_facts_reach_both_profiles(self, settings, profile_scan, output_file, profile):
        data = render_profile(settings, profile_scan, output_file, profile)

        assert data["ignored_packages"] == [
            {"name": "private-lib", "spec": "git+https://example.com/private-lib.git", "reason": "git source"}
        ]
        assert data["upgrade_paths"][0]["suggested_constraint"] == "^2.0.0"
        assert data["manifest_lock_divergent"] == ["quiet"]
        assert data["runtime_context"]["engine_context_source"] == "provided"
        assert data["runtime_context"]["runtime_mismatch"] == {
            "engine": "node",
            "pinned": "22.12.0",
            "pin_file": ".nvmrc",
            "runtime": "20.11.0",
            "runtime_source": "provided",
        }

    def test_dependency_name_is_null_unless_aliased(self, settings, profile_scan, output_file):
        profile_scan.production_packages[0].dependency_name = "vulnerable-alias"

        vulnerable, quiet = render_profile(settings, profile_scan, output_file, ExportProfile.FULL)[
            "production_packages"
        ]

        assert vulnerable["dependency_name"] == "vulnerable-alias"
        assert quiet["dependency_name"] is None


@pytest.fixture
def peer_scan(profile_scan: ScanResult) -> ScanResult:
    """profile_scan plus the frontend/ case: a package whose optional peer is installed out of its reach,
    a transitive that needs nothing else but a missing required peer, and the repair for the first."""
    quiet = profile_scan.production_packages[1]
    quiet.unresolved_peers = [
        UnresolvedPeer("@vue/server-renderer", "3.x", optional=True, installed_elsewhere=("3.5.43",))
    ]
    profile_scan.transitive_packages[1].unresolved_peers = [UnresolvedPeer("host", "^1")]
    profile_scan.peer_repairs = [
        PeerRepair(
            package="@vue/server-renderer",
            spec="~3.5.43",
            is_dev=True,
            requirers=("quiet",),
            family_moves=(
                TransitiveImpact(
                    package_name="@vue/shared",
                    current_version="3.5.42",
                    projected_version="3.5.43",
                    new_constraint="3.5.43",
                    driven_by="@vue/server-renderer",
                    has_conflict=False,
                    kind=ImpactKind.OVERRIDE_BUMP,
                ),
            ),
        )
    ]
    return profile_scan


@pytest.fixture
def widening_scan(sample_project_metrics_record: ScanRecord) -> ScanResult:
    """One direct package whose CVE fix sits past its declared range, with the selector's authorization."""
    record = dataclasses.replace(
        sample_project_metrics_record,
        recommended_version="1.2.0",
        recommended_from_rung=RecommendationRung.IN_MAJOR,
        strategy_selection=StrategySelection(
            strategy=UpdateStrategy.SECURITY,
            target_version="1.2.0",
            rung=RecommendationRung.IN_MAJOR,
            motives=frozenset({UpdateMotive.EXPLOITABLE_CVE}),
            requires_widening=True,
            withheld_reason=None,
            available_at=None,
            escalation="no version of example within its declared range resolves: exploitable_cve",
            widening_authorized=True,
        ),
    )
    return ScanResult(
        project_name="test-project",
        project_path="/path/to/test-project",
        packages_registry=ProjectPackagesRegistry.NPM.value,
        production_packages=[record],
        optional_packages=[],
    )


class TestSchemaVersion17:
    """v1.6 reports peers a package cannot reach and how apply repairs them; v1.5 stays as it was."""

    @pytest.mark.parametrize("profile", [ExportProfile.STANDARD, ExportProfile.FULL])
    def test_a_default_document_is_v1_6_and_validates_against_its_schema(
        self, settings, peer_scan, output_file, profile
    ):
        data = render_profile(settings, peer_scan, output_file, profile)

        assert data["metadata"]["schema_version"] == "1.6"
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_6, profile))

    @pytest.mark.parametrize("profile", [ExportProfile.STANDARD, ExportProfile.FULL])
    def test_unresolved_peers_reach_the_direct_entry(self, settings, peer_scan, output_file, profile):
        data = render_profile(settings, peer_scan, output_file, profile)

        quiet = next(entry for entry in data["production_packages"] if entry["package_name"] == "quiet")
        assert quiet["unresolved_peers"] == [
            {
                "package_name": "@vue/server-renderer",
                "spec": "3.x",
                "optional": True,
                "installed_elsewhere": ["3.5.43"],
            }
        ]

    @pytest.mark.parametrize("profile", [ExportProfile.STANDARD, ExportProfile.FULL])
    def test_peer_repairs_reach_the_root(self, settings, peer_scan, output_file, profile):
        data = render_profile(settings, peer_scan, output_file, profile)

        assert data["peer_repairs"] == [
            {
                "package_name": "@vue/server-renderer",
                "suggested_constraint": "~3.5.43",
                "is_dev_dependency": True,
                "requirers": ["quiet"],
                "family_moves": [
                    {"package_name": "@vue/shared", "current_version": "3.5.42", "projected_version": "3.5.43"}
                ],
            }
        ]

    @pytest.mark.parametrize("profile", [ExportProfile.STANDARD, ExportProfile.FULL])
    def test_the_strategy_verdict_says_when_apply_may_write_a_widening_pick(
        self, settings, widening_scan, output_file, profile
    ):
        data = render_profile(settings, widening_scan, output_file, profile)

        entry = data["production_packages"][0]
        assert entry["requires_constraint_widening"] is True
        assert entry["strategy"]["widening_authorized"] is True
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_6, profile))

    @pytest.mark.parametrize("profile", [ExportProfile.STANDARD, ExportProfile.FULL])
    def test_an_escalated_widening_pick_is_labelled_an_update(self, settings, widening_scan, output_file, profile):
        """The label agrees with `plan`, which writes the pick; the widening flags still say how."""
        record = dataclasses.replace(
            widening_scan.production_packages[0],
            versions_diff_index=VersionsDifference(
                version1="1.0.0", version2="1.2.0", diff_index=4, diff_name="DIFF_MINOR"
            ),
            epss=None,
        )
        scan = dataclasses.replace(widening_scan, production_packages=[record])

        data = render_profile(settings, scan, output_file, profile)

        entry = data["production_packages"][0]
        assert entry["next_action"] == "Update Immediately"
        assert entry["requires_constraint_widening"] is True
        assert entry["strategy"]["widening_authorized"] is True
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_6, profile))

    def test_standard_keeps_a_transitive_that_only_has_an_unresolved_peer(self, settings, peer_scan, output_file):
        data = render_profile(settings, peer_scan, output_file)

        assert [entry["package_name"] for entry in data["transitive_packages"]] == ["risky-dep", "drift-0"]
        drifting = data["transitive_packages"][1]
        assert drifting["unresolved_peers"] == [
            {"package_name": "host", "spec": "^1", "optional": False, "installed_elsewhere": []}
        ]

    def test_a_package_with_every_peer_resolved_says_so_by_saying_nothing(self, settings, profile_scan, output_file):
        data = render_profile(settings, profile_scan, output_file)

        assert all("unresolved_peers" not in entry for entry in data["production_packages"])
        assert all("unresolved_peers" not in entry for entry in data["transitive_packages"])
        assert data["peer_repairs"] == []

    @pytest.mark.parametrize("profile", [ExportProfile.STANDARD, ExportProfile.FULL])
    def test_the_registrys_verdict_and_its_note_reach_direct_and_transitive_entries(
        self, settings, profile_scan, output_file, profile
    ):
        direct = profile_scan.production_packages[0]
        direct.registry_status = RegistryStatus.DEPRECATED
        direct.deprecation_message = "use String.prototype.padStart()"
        transitive = profile_scan.transitive_packages[0]
        transitive.registry_status = RegistryStatus.ARCHIVED

        data = render_profile(settings, profile_scan, output_file, profile)

        assert data["production_packages"][0]["registry_status"] == "deprecated"
        assert data["production_packages"][0]["deprecation_message"] == "use String.prototype.padStart()"
        assert data["transitive_packages"][0]["registry_status"] == "archived"
        # Transitive entries leave a null out rather than spelling it.
        assert "deprecation_message" not in data["transitive_packages"][0]
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_6, profile))

    def test_a_registry_that_gave_no_verdict_exports_null_not_active(self, settings, profile_scan, output_file):
        data = render_profile(settings, profile_scan, output_file, ExportProfile.FULL)

        assert data["production_packages"][0]["registry_status"] is None

    def test_the_full_profile_lists_an_empty_unresolved_peers_on_direct_entries(
        self, settings, profile_scan, output_file
    ):
        data = render_profile(settings, profile_scan, output_file, ExportProfile.FULL)

        assert all(entry["unresolved_peers"] == [] for entry in data["production_packages"])


class TestOssiqAuthoredOverrideExport:
    """constraint_ossiq_authored tells an OVERRIDE the user holds from the one OSS IQ wrote and moves itself."""

    @pytest.fixture
    def override_scan(self, profile_scan: ScanResult) -> ScanResult:
        authored = ConstraintSource(type=ConstraintType.OVERRIDE, source_file="package.json", is_ossiq_authored=True)
        profile_scan.production_packages[0].constraint_info = authored
        profile_scan.transitive_packages[0].constraint_info = authored
        return profile_scan

    def test_a_direct_package_says_whose_override_it_is(self, settings, override_scan, output_file):
        data = render_profile(settings, override_scan, output_file)

        vulnerable, quiet = data["production_packages"]
        assert (vulnerable["constraint_type"], vulnerable["constraint_ossiq_authored"]) == ("OVERRIDE", True)
        assert quiet["constraint_ossiq_authored"] is False
        validate(
            instance=data,
            schema=json_schema_registry.load_schema(json_schema_registry.get_latest_version(), ExportProfile.STANDARD),
        )

    def test_a_transitive_package_says_it_in_the_full_profile_only(
        self, settings, override_scan, output_file, tmp_path
    ):
        full = render_profile(settings, override_scan, output_file, ExportProfile.FULL)
        standard = render_profile(settings, override_scan, tmp_path / "standard.json")

        flagged = {e["package_name"] for e in full["transitive_packages"] if e["constraint_ossiq_authored"]}
        assert flagged == {"risky-dep"}
        assert all("constraint_ossiq_authored" not in e for e in standard["transitive_packages"])
        validate(
            instance=full,
            schema=json_schema_registry.load_schema(json_schema_registry.get_latest_version(), ExportProfile.FULL),
        )

    def test_the_tree_still_reports_the_override_it_is(self, settings, override_scan, output_file):
        data = render_profile(settings, override_scan, output_file, ExportProfile.FULL)

        risky = next(i for i, e in enumerate(data["transitive_packages"]) if e["package_name"] == "risky-dep")
        (vulnerable_root,) = (root for root in data["dependency_tree"] if root["package_name"] == "vulnerable")
        (node,) = (child for child in vulnerable_root["children"] if child["ref"] == risky)
        assert data["constraint_type_map"][node["ct"]] == "OVERRIDE"

    def test_a_v1_5_document_does_not_carry_it(self, settings, override_scan, output_file):
        data = render_profile(settings, override_scan, output_file, ExportProfile.FULL, schema_version="1.5")

        assert all("constraint_ossiq_authored" not in e for e in data["production_packages"])
        assert all("constraint_ossiq_authored" not in e for e in data["transitive_packages"])


class TestSchemaVersion15StaysAsReleased:
    """`--schema-version 1.5` is a promise to consumers who pinned it: nothing from 1.6 may leak in."""

    @pytest.mark.parametrize("profile", [ExportProfile.STANDARD, ExportProfile.FULL])
    def test_a_v1_5_document_carries_none_of_the_1_6_fields_and_still_validates(
        self, settings, peer_scan, output_file, profile
    ):
        data = render_profile(settings, peer_scan, output_file, profile, schema_version="1.5")

        assert data["metadata"]["schema_version"] == "1.5"
        assert "peer_repairs" not in data
        for entry in [*data["production_packages"], *data["transitive_packages"]]:
            assert "unresolved_peers" not in entry
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5, profile))

    def test_standard_v1_5_drops_the_peer_only_transitive_as_it_always_did(self, settings, peer_scan, output_file):
        data = render_profile(settings, peer_scan, output_file, schema_version="1.5")

        assert [entry["package_name"] for entry in data["transitive_packages"]] == ["risky-dep"]

    @pytest.mark.parametrize("profile", [ExportProfile.STANDARD, ExportProfile.FULL])
    def test_a_v1_5_strategy_verdict_has_no_widening_authorization(self, settings, widening_scan, output_file, profile):
        data = render_profile(settings, widening_scan, output_file, profile, schema_version="1.5")

        assert "widening_authorized" not in data["production_packages"][0]["strategy"]
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5, profile))

    def test_a_v1_5_document_is_the_v1_6_one_minus_the_new_fields(self, settings, peer_scan, output_file, tmp_path):
        old = render_profile(settings, peer_scan, output_file, ExportProfile.FULL, schema_version="1.5")
        new = render_profile(settings, peer_scan, tmp_path / "new.json", ExportProfile.FULL)

        for document in (old, new):
            document["metadata"].pop("export_timestamp")
            document["metadata"].pop("schema_version")
        new.pop("peer_repairs")
        for entry in [*new["production_packages"], *new["transitive_packages"]]:
            for added_in_1_6 in (
                "unresolved_peers",
                "registry_status",
                "deprecation_message",
                "constraint_ossiq_authored",
            ):
                entry.pop(added_in_1_6, None)
        assert old == new

    @pytest.mark.parametrize("profile", [ExportProfile.STANDARD, ExportProfile.FULL])
    def test_a_v1_5_document_has_no_registry_verdict(self, settings, profile_scan, output_file, profile):
        profile_scan.production_packages[0].registry_status = RegistryStatus.DEPRECATED
        profile_scan.production_packages[0].deprecation_message = "use something else"

        data = render_profile(settings, profile_scan, output_file, profile, schema_version="1.5")

        for entry in [*data["production_packages"], *data["transitive_packages"]]:
            assert "registry_status" not in entry
            assert "deprecation_message" not in entry
        validate(instance=data, schema=json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5, profile))
