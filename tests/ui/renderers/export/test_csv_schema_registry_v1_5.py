"""Tests for CSV export schema registry v1.5."""

import csv as csv_module

import pytest

from ossiq.domain.common import ConstraintType, ExportCsvSchemaVersion
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VersionsDifference
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.ui.renderers.export.csv import CsvExportRenderer
from tests.ui.renderers.export.test_csv_base import (
    _CVES_HEADERS_V15,
    _PACKAGES_HEADERS_V15,
    _SUMMARY_HEADERS_V15,
    CsvExportRendererBaseTest,
)
from tests.ui.renderers.export.test_csv_schema_registry_base import CsvSchemaRegistryBaseTest


class TestCsvSchemaRegistryV15(CsvSchemaRegistryBaseTest):
    version = ExportCsvSchemaVersion.V1_5
    packages_field_count = 22
    summary_field_count = 14
    cves_field_count = 12
    included_versions = [
        ExportCsvSchemaVersion.V1_0,
        ExportCsvSchemaVersion.V1_1,
        ExportCsvSchemaVersion.V1_2,
        ExportCsvSchemaVersion.V1_3,
        ExportCsvSchemaVersion.V1_4,
        ExportCsvSchemaVersion.V1_5,
    ]

    def test_packages_schema_has_epss_column(self, packages_schema):
        field = next(f for f in packages_schema["fields"] if f["name"] == "epss")
        assert field["type"] == "number"

    def test_packages_schema_has_runs_code_at_install_column(self, packages_schema):
        field = next(f for f in packages_schema["fields"] if f["name"] == "runs_code_at_install")
        assert field["type"] == "boolean"

    def test_summary_schema_has_project_epss_columns(self, summary_schema):
        field_names = [f["name"] for f in summary_schema["fields"]]
        assert "project_epss" in field_names
        assert "packages_with_epss" in field_names
        assert "packages_with_unscored_cves" in field_names

    def test_cves_schema_has_epss_and_fix_age_days_columns(self, cves_schema):
        field_names = [f["name"] for f in cves_schema["fields"]]
        assert "epss" in field_names
        assert "fix_age_days" in field_names

    def test_no_epss_field_is_required(self, packages_schema):
        epss_fields = {"epss", "runs_code_at_install"}
        for field in packages_schema["fields"]:
            if field["name"] in epss_fields:
                assert not field.get("constraints", {}).get("required"), f"{field['name']} must not be required"

    def test_v1_4_schema_still_registered(self, registry):
        path = registry.get_schema_path(ExportCsvSchemaVersion.V1_4, "packages")
        assert path.exists()


class TestCsvRendererV15(CsvExportRendererBaseTest):
    schema_version = "1.5"
    expected_packages_headers = _PACKAGES_HEADERS_V15
    expected_summary_headers = _SUMMARY_HEADERS_V15
    expected_cves_headers = _CVES_HEADERS_V15

    @pytest.fixture
    def scored_record(self):
        return ScanRecord(
            package_name="risky-lib",
            dependency_name="risky-lib",
            is_optional_dependency=False,
            installed_version="0.1.0",
            latest_version="0.2.0",
            versions_diff_index=VersionsDifference("0.1.0", "0.2.0", 1, "DIFF_MINOR"),
            time_lag_days=5,
            releases_lag=1,
            cve=[],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
            epss=0.8,
            runs_code_at_install=True,
        )

    @pytest.fixture
    def unscored_record(self):
        return ScanRecord(
            package_name="safe-lib",
            dependency_name="safe-lib",
            is_optional_dependency=False,
            installed_version="1.0.0",
            latest_version="1.0.0",
            versions_diff_index=VersionsDifference("1.0.0", "1.0.0", 0, "LATEST"),
            time_lag_days=0,
            releases_lag=0,
            cve=[],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
        )

    def _metrics_with(self, record: ScanRecord) -> ScanResult:
        return ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry="npm",
            production_packages=[record],
            optional_packages=[],
        )

    def test_epss_columns_populated_for_scored_package(self, settings, scored_record, tmp_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, self._metrics_with(scored_record), tmp_path / "export.csv")
        with open(tmp_path / "export" / "packages.csv", encoding="utf-8-sig", newline="") as f:
            row = next(csv_module.DictReader(f))
        assert row["epss"] == "0.8"
        assert row["runs_code_at_install"] == "true"

    def test_epss_columns_empty_when_not_computed(self, settings, unscored_record, tmp_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, self._metrics_with(unscored_record), tmp_path / "export.csv")
        with open(tmp_path / "export" / "packages.csv", encoding="utf-8-sig", newline="") as f:
            row = next(csv_module.DictReader(f))
        assert row["epss"] == ""
        assert row["runs_code_at_install"] == ""
