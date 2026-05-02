"""
Base test class for CSV export renderer.

Subclasses set schema_version (and optionally override expected_packages_headers)
and inherit all shared renderer tests. Version-specific assertions live in the
test_csv_schema_registry_v*.py version files.
"""

import csv
import json
from pathlib import Path

import pytest

from ossiq.domain.common import Command, ConstraintType, ProjectPackagesRegistry, UserInterfaceType
from ossiq.domain.cve import CVE, CveDatabase, Severity
from ossiq.domain.exceptions import DestinationDoesntExist
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VersionsDifference
from ossiq.service.project import ScanRecord, ScanResult
from ossiq.settings import Settings
from ossiq.ui.renderers.export.csv import CsvExportRenderer
from ossiq.ui.renderers.export.csv_datapackage import validate_datapackage

# Renderer always outputs this column order for non-v1.4 schemas.
_PACKAGES_HEADERS_BASE = [
    "package_name",
    "dependency_name",
    "dependency_type",
    "is_optional_dependency",
    "installed_version",
    "latest_version",
    "time_lag_days",
    "releases_lag",
    "cve_count",
    "version_constraint",
    "constraint_type",
    "constraint_source_file",
    "extras",
    "license",
    "purl",
]

_PACKAGES_HEADERS_V14 = [
    "package_name",
    "dependency_name",
    "dependency_type",
    "is_optional_dependency",
    "installed_version",
    "latest_version",
    "time_lag_days",
    "version_age_days",
    "releases_lag",
    "cve_count",
    "version_constraint",
    "constraint_type",
    "constraint_source_file",
    "extras",
    "is_prerelease",
    "is_yanked",
    "is_deprecated",
    "is_package_unpublished",
    "license",
    "purl",
]

_SUMMARY_HEADERS = [
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

_CVES_HEADERS = [
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


class CsvExportRendererBaseTest:
    """Shared renderer tests for all CSV schema versions. Not collected directly."""

    schema_version: str  # set by each subclass, e.g. "1.0", "1.4"
    expected_packages_headers: list = _PACKAGES_HEADERS_BASE  # v1.4 overrides
    # Renderer always emits v1.3 column format for older schemas, so Frictionless
    # datapackage validation only passes for v1.2+. Set False in v1.0/v1.1 subclasses.
    datapackage_validates: bool = True

    # ── fixtures ──────────────────────────────────────────────────────────────

    @pytest.fixture
    def settings(self):
        return Settings()

    @pytest.fixture
    def sample_cve(self):
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
    def sample_prod_record(self, sample_cve):
        return ScanRecord(
            package_name="react",
            dependency_name="react",
            is_optional_dependency=False,
            installed_version="17.0.2",
            latest_version="18.2.0",
            versions_diff_index=VersionsDifference("17.0.2", "18.2.0", 5, "DIFF_MAJOR"),
            time_lag_days=245,
            releases_lag=12,
            cve=[sample_cve],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
        )

    @pytest.fixture
    def sample_dev_record(self):
        return ScanRecord(
            package_name="pytest",
            dependency_name="pytest",
            is_optional_dependency=True,
            installed_version="7.0.0",
            latest_version="7.2.0",
            versions_diff_index=VersionsDifference("7.0.0", "7.2.0", 2, "DIFF_MINOR"),
            time_lag_days=90,
            releases_lag=5,
            cve=[],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
        )

    @pytest.fixture
    def sample_metrics(self, sample_prod_record, sample_dev_record):
        return ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry=ProjectPackagesRegistry.NPM.value,
            production_packages=[sample_prod_record],
            optional_packages=[sample_dev_record],
        )

    @pytest.fixture
    def output_path(self, tmp_path):
        return tmp_path / "export.csv"

    # ── helpers ───────────────────────────────────────────────────────────────

    def _render(self, renderer: CsvExportRenderer, data: ScanResult, destination: Path) -> None:
        renderer.render(data, destination=str(destination), schema_version=self.schema_version)

    def _folder(self, output_path: Path) -> Path:
        return output_path.parent / output_path.stem

    # ── shared tests ─────────────────────────────────────────────────────────

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
        assert CsvExportRenderer.supports(command, user_interface_type) == expected

    def test_export_creates_folder_with_all_files(self, settings, sample_metrics, output_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, sample_metrics, output_path)
        folder = self._folder(output_path)
        assert folder.is_dir()
        for fname in ("summary.csv", "packages.csv", "cves.csv", "datapackage.json"):
            assert (folder / fname).exists()

    def test_summary_csv_has_correct_headers(self, settings, sample_metrics, output_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, sample_metrics, output_path)
        with open(self._folder(output_path) / "summary.csv", encoding="utf-8-sig", newline="") as f:
            assert csv.DictReader(f).fieldnames == _SUMMARY_HEADERS

    def test_packages_csv_has_correct_headers(self, settings, sample_metrics, output_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, sample_metrics, output_path)
        with open(self._folder(output_path) / "packages.csv", encoding="utf-8-sig", newline="") as f:
            assert csv.DictReader(f).fieldnames == self.expected_packages_headers

    def test_cves_csv_has_correct_headers(self, settings, sample_metrics, output_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, sample_metrics, output_path)
        with open(self._folder(output_path) / "cves.csv", encoding="utf-8-sig", newline="") as f:
            assert csv.DictReader(f).fieldnames == _CVES_HEADERS

    def test_summary_schema_version_matches(self, settings, sample_metrics, output_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, sample_metrics, output_path)
        with open(self._folder(output_path) / "summary.csv", encoding="utf-8-sig", newline="") as f:
            row = next(csv.DictReader(f))
        assert row["schema_version"] == self.schema_version

    def test_summary_row_values(self, settings, sample_metrics, output_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, sample_metrics, output_path)
        with open(self._folder(output_path) / "summary.csv", encoding="utf-8-sig", newline="") as f:
            row = next(csv.DictReader(f))
        assert row["project_name"] == "test-project"
        assert row["project_path"] == "/path/to/test-project"
        assert row["project_registry"] == "npm"
        assert row["total_packages"] == "2"
        assert row["production_packages"] == "1"
        assert row["development_packages"] == "1"
        assert row["packages_with_cves"] == "1"
        assert row["total_cves"] == "1"
        assert row["packages_outdated"] == "2"

    def test_packages_csv_row_count(self, settings, sample_metrics, output_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, sample_metrics, output_path)
        with open(self._folder(output_path) / "packages.csv", encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 2
        assert rows[0]["package_name"] == "react"
        assert rows[0]["dependency_type"] == "production"
        assert rows[0]["cve_count"] == "1"
        assert rows[1]["package_name"] == "pytest"
        assert rows[1]["dependency_type"] == "development"
        assert rows[1]["cve_count"] == "0"

    def test_cves_csv_foreign_key_links_to_packages(self, settings, sample_metrics, output_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, sample_metrics, output_path)
        folder = self._folder(output_path)
        with open(folder / "packages.csv", encoding="utf-8-sig", newline="") as f:
            package_names = {pkg["package_name"] for pkg in csv.DictReader(f)}
        with open(folder / "cves.csv", encoding="utf-8-sig", newline="") as f:
            cves = list(csv.DictReader(f))
        assert len(cves) == 1
        assert cves[0]["cve_id"] == "GHSA-test-1234"
        assert cves[0]["package_name"] in package_names

    def test_boolean_fields_serialized_as_lowercase(self, settings, sample_metrics, output_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, sample_metrics, output_path)
        with open(self._folder(output_path) / "packages.csv", encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        assert rows[0]["is_optional_dependency"] == "false"
        assert rows[1]["is_optional_dependency"] == "true"

    def test_none_fields_serialized_as_empty_strings(self, settings, tmp_path):
        metrics = ScanResult(
            project_name="test",
            project_path="/test",
            packages_registry="NPM",
            production_packages=[
                ScanRecord(
                    package_name="package1",
                    dependency_name="package1",
                    is_optional_dependency=False,
                    installed_version="1.0.0",
                    latest_version=None,
                    versions_diff_index=VersionsDifference("1.0.0", "1.0.0", 0, "SAME"),
                    time_lag_days=None,
                    releases_lag=None,
                    cve=[],
                    constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
                )
            ],
            optional_packages=[],
        )
        renderer = CsvExportRenderer(settings)
        output_path = tmp_path / "export.csv"
        self._render(renderer, metrics, output_path)
        with open(tmp_path / "export" / "packages.csv", encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        assert rows[0]["latest_version"] == ""
        assert rows[0]["time_lag_days"] == ""
        assert rows[0]["releases_lag"] == ""

    def test_list_fields_serialized_as_pipe_delimited(self, settings, sample_metrics, output_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, sample_metrics, output_path)
        with open(self._folder(output_path) / "cves.csv", encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        assert rows[0]["affected_versions"] == "<18.0.0|>=17.0.0"
        assert rows[0]["all_cve_ids"] == "CVE-2023-12345|GHSA-test-1234"

    def test_enum_fields_serialized_as_strings(self, settings, sample_metrics, output_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, sample_metrics, output_path)
        with open(self._folder(output_path) / "cves.csv", encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        assert rows[0]["severity"] == "HIGH"
        assert rows[0]["source"] == "GHSA"
        assert rows[0]["package_registry"] == "npm"

    def test_cve_summary_with_commas_properly_quoted(self, settings, tmp_path):
        cve = CVE(
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
        metrics = ScanResult(
            project_name="test",
            project_path="/test",
            packages_registry="NPM",
            production_packages=[
                ScanRecord(
                    package_name="test-pkg",
                    dependency_name="test-pkg",
                    is_optional_dependency=False,
                    installed_version="1.0.0",
                    latest_version="2.0.0",
                    versions_diff_index=VersionsDifference("1.0.0", "2.0.0", 1, "DIFF"),
                    time_lag_days=10,
                    releases_lag=1,
                    cve=[cve],
                    constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
                )
            ],
            optional_packages=[],
        )
        renderer = CsvExportRenderer(settings)
        output_path = tmp_path / "export.csv"
        self._render(renderer, metrics, output_path)
        with open(tmp_path / "export" / "cves.csv", encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        assert rows[0]["summary"] == "This summary contains, multiple, commas"

    def test_unicode_project_name_preserved(self, settings, tmp_path):
        metrics = ScanResult(
            project_name="tëst-ünïcødé",
            project_path="/path/to/project",
            packages_registry="NPM",
            production_packages=[],
            optional_packages=[],
        )
        renderer = CsvExportRenderer(settings)
        output_path = tmp_path / "export.csv"
        self._render(renderer, metrics, output_path)
        with open(tmp_path / "export" / "summary.csv", encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        assert rows[0]["project_name"] == "tëst-ünïcødé"

    def test_project_name_placeholder_replaced_in_folder_name(self, settings, sample_metrics, tmp_path):
        renderer = CsvExportRenderer(settings)
        output_template = tmp_path / "export_{project_name}.csv"
        renderer.render(sample_metrics, destination=str(output_template), schema_version=self.schema_version)
        folder = tmp_path / "export_test-project"
        assert folder.is_dir()
        for fname in ("summary.csv", "packages.csv", "cves.csv", "datapackage.json"):
            assert (folder / fname).exists()

    def test_all_files_created_in_named_folder(self, settings, sample_metrics, tmp_path):
        renderer = CsvExportRenderer(settings)
        output_path = tmp_path / "my_custom_export.csv"
        self._render(renderer, sample_metrics, output_path)
        folder = tmp_path / "my_custom_export"
        assert folder.is_dir()
        assert len(list(folder.glob("*.csv"))) == 3
        for fname in ("summary.csv", "packages.csv", "cves.csv", "datapackage.json"):
            assert (folder / fname).exists()

    def test_raises_when_destination_directory_missing(self, settings, sample_metrics):
        renderer = CsvExportRenderer(settings)
        with pytest.raises(DestinationDoesntExist):
            renderer.render(
                sample_metrics,
                destination="/nonexistent/dir/export.csv",
                schema_version=self.schema_version,
            )

    def test_unsupported_schema_version_raises(self, settings, sample_metrics, tmp_path):
        renderer = CsvExportRenderer(settings)
        with pytest.raises(ValueError):
            renderer.render(sample_metrics, destination=str(tmp_path / "export.csv"), schema_version="9.9")

    def test_all_csv_files_readable(self, settings, sample_metrics, output_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, sample_metrics, output_path)
        folder = self._folder(output_path)
        with open(folder / "summary.csv", encoding="utf-8-sig", newline="") as f:
            assert len(list(csv.DictReader(f))) == 1
        with open(folder / "packages.csv", encoding="utf-8-sig", newline="") as f:
            assert len(list(csv.DictReader(f))) == 2
        with open(folder / "cves.csv", encoding="utf-8-sig", newline="") as f:
            assert len(list(csv.DictReader(f))) == 1

    def test_empty_project_creates_empty_packages_csv(self, settings, tmp_path):
        metrics = ScanResult(
            project_name="empty-project",
            project_path="/test",
            packages_registry="NPM",
            production_packages=[],
            optional_packages=[],
        )
        renderer = CsvExportRenderer(settings)
        output_path = tmp_path / "export.csv"
        self._render(renderer, metrics, output_path)
        with open(tmp_path / "export" / "packages.csv", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 0
        assert reader.fieldnames is not None

    def test_packages_without_cves_creates_empty_cves_csv(self, settings, tmp_path):
        metrics = ScanResult(
            project_name="no-cves",
            project_path="/test",
            packages_registry="NPM",
            production_packages=[
                ScanRecord(
                    package_name="safe-pkg",
                    dependency_name="safe-pkg",
                    is_optional_dependency=False,
                    installed_version="1.0.0",
                    latest_version="1.0.0",
                    versions_diff_index=VersionsDifference("1.0.0", "1.0.0", 0, "SAME"),
                    time_lag_days=0,
                    releases_lag=0,
                    cve=[],
                    constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
                )
            ],
            optional_packages=[],
        )
        renderer = CsvExportRenderer(settings)
        output_path = tmp_path / "export.csv"
        self._render(renderer, metrics, output_path)
        with open(tmp_path / "export" / "cves.csv", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 0
        assert reader.fieldnames is not None

    def test_datapackage_is_valid(self, settings, sample_metrics, output_path):
        if not self.datapackage_validates:
            pytest.skip(
                "renderer emits v1.3 column format for this schema version; datapackage schema mismatch by design"
            )
        renderer = CsvExportRenderer(settings)
        self._render(renderer, sample_metrics, output_path)
        is_valid, errors = validate_datapackage(self._folder(output_path) / "datapackage.json")
        assert is_valid is True, f"Data package validation failed: {errors}"

    def test_datapackage_json_structure(self, settings, sample_metrics, output_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, sample_metrics, output_path)
        with open(self._folder(output_path) / "datapackage.json", encoding="utf-8") as f:
            descriptor = json.load(f)
        assert descriptor["profile"] == "tabular-data-package"
        assert {r["name"] for r in descriptor["resources"]} == {"summary", "packages", "cves"}
        for resource in descriptor["resources"]:
            assert "/" not in resource["path"]
            assert resource["path"].endswith(".csv")

    def test_cves_fk_satisfies_packages(self, settings, sample_metrics, output_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, sample_metrics, output_path)
        folder = self._folder(output_path)
        with open(folder / "packages.csv", encoding="utf-8-sig", newline="") as f:
            package_names = {pkg["package_name"] for pkg in csv.DictReader(f)}
        with open(folder / "cves.csv", encoding="utf-8-sig", newline="") as f:
            for cve in csv.DictReader(f):
                assert cve["package_name"] in package_names

    def test_packages_csv_contains_purl_values(self, settings, sample_metrics, output_path):
        sample_metrics.production_packages[0].purl = "pkg:npm/react@17.0.2"
        sample_metrics.optional_packages[0].purl = "pkg:npm/pytest@7.0.0"
        renderer = CsvExportRenderer(settings)
        self._render(renderer, sample_metrics, output_path)
        with open(self._folder(output_path) / "packages.csv", encoding="utf-8-sig", newline="") as f:
            purl_values = [row["purl"] for row in csv.DictReader(f)]
        assert "pkg:npm/react@17.0.2" in purl_values
        assert "pkg:npm/pytest@7.0.0" in purl_values
