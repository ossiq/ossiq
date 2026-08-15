"""Tests for CSV export schema registry v1.5."""

import csv as csv_module

import pytest

from ossiq.domain.common import ConstraintType, ExportCsvSchemaVersion
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VersionsDifference
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.ui.renderers.export.csv import CsvExportRenderer
from tests.ui.renderers.export.test_csv_base import _PACKAGES_HEADERS_V15, CsvExportRendererBaseTest
from tests.ui.renderers.export.test_csv_schema_registry_base import CsvSchemaRegistryBaseTest


class TestCsvSchemaRegistryV15(CsvSchemaRegistryBaseTest):
    version = ExportCsvSchemaVersion.V1_5
    packages_field_count = 28
    included_versions = [
        ExportCsvSchemaVersion.V1_0,
        ExportCsvSchemaVersion.V1_1,
        ExportCsvSchemaVersion.V1_2,
        ExportCsvSchemaVersion.V1_3,
        ExportCsvSchemaVersion.V1_4,
        ExportCsvSchemaVersion.V1_5,
    ]

    def test_packages_schema_has_gate_status_column(self, packages_schema):
        field = next(f for f in packages_schema["fields"] if f["name"] == "gate_status")
        assert field["type"] == "string"
        assert set(field["constraints"]["enum"]) == {"pass", "quarantine", "block"}

    def test_packages_schema_has_gate_reason_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "gate_reason" in field_names

    def test_packages_schema_has_fitness_column(self, packages_schema):
        field = next(f for f in packages_schema["fields"] if f["name"] == "fitness")
        assert field["type"] == "integer"

    def test_packages_schema_has_risk_float_columns(self, packages_schema):
        for name in ("expected_exposure", "p_vuln", "p_supplychain", "impact", "exposure_window_days"):
            field = next(f for f in packages_schema["fields"] if f["name"] == name)
            assert field["type"] == "number"

    def test_no_health_field_is_required(self, packages_schema):
        health_fields = {
            "gate_status",
            "gate_reason",
            "fitness",
            "expected_exposure",
            "p_vuln",
            "p_supplychain",
            "impact",
            "exposure_window_days",
        }
        for field in packages_schema["fields"]:
            if field["name"] in health_fields:
                assert not field.get("constraints", {}).get("required"), f"{field['name']} must not be required"

    def test_v1_4_schema_still_registered(self, registry):
        path = registry.get_schema_path(ExportCsvSchemaVersion.V1_4, "packages")
        assert path.exists()


class TestCsvRendererV15(CsvExportRendererBaseTest):
    schema_version = "1.5"
    expected_packages_headers = _PACKAGES_HEADERS_V15

    @pytest.fixture
    def blocked_record(self):
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
            gate_decision=("block", "known critical CVE with public exploit"),
            fitness=12,
            impact=2.0,
            p_vuln=0.8,
            p_supplychain=0.1,
            expected_exposure=1.7,
            exposure_window_days=30.0,
        )

    @pytest.fixture
    def passing_record(self):
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

    def test_gate_and_health_columns_populated_for_blocked_package(self, settings, blocked_record, tmp_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, self._metrics_with(blocked_record), tmp_path / "export.csv")
        with open(tmp_path / "export" / "packages.csv", encoding="utf-8-sig", newline="") as f:
            row = next(csv_module.DictReader(f))
        assert row["gate_status"] == "block"
        assert row["gate_reason"] == "known critical CVE with public exploit"
        assert row["fitness"] == "12"
        assert row["expected_exposure"] == "1.7"
        assert row["p_vuln"] == "0.8"
        assert row["p_supplychain"] == "0.1"
        assert row["impact"] == "2.0"
        assert row["exposure_window_days"] == "30.0"

    def test_gate_and_health_columns_empty_when_not_computed(self, settings, passing_record, tmp_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, self._metrics_with(passing_record), tmp_path / "export.csv")
        with open(tmp_path / "export" / "packages.csv", encoding="utf-8-sig", newline="") as f:
            row = next(csv_module.DictReader(f))
        assert row["gate_status"] == ""
        assert row["gate_reason"] == ""
        assert row["fitness"] == ""
        assert row["expected_exposure"] == ""
