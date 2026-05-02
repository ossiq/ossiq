"""Tests for CSV export schema registry v1.4."""

import csv as csv_module

import pytest

from ossiq.domain.common import ConstraintType, ExportCsvSchemaVersion
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VersionsDifference
from ossiq.service.project import ScanRecord, ScanResult
from ossiq.ui.renderers.export.csv import CsvExportRenderer
from ossiq.ui.renderers.export.csv_schema_registry import csv_schema_registry
from tests.ui.renderers.export.test_csv_base import _PACKAGES_HEADERS_V14, CsvExportRendererBaseTest
from tests.ui.renderers.export.test_csv_schema_registry_base import CsvSchemaRegistryBaseTest


class TestCsvSchemaRegistryV14(CsvSchemaRegistryBaseTest):
    version = ExportCsvSchemaVersion.V1_4
    packages_field_count = 20
    included_versions = [
        ExportCsvSchemaVersion.V1_0,
        ExportCsvSchemaVersion.V1_1,
        ExportCsvSchemaVersion.V1_2,
        ExportCsvSchemaVersion.V1_3,
        ExportCsvSchemaVersion.V1_4,
    ]

    def test_packages_schema_has_version_age_days_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "version_age_days" in field_names

    def test_version_age_days_is_integer_type(self, packages_schema):
        field = next(f for f in packages_schema["fields"] if f["name"] == "version_age_days")
        assert field["type"] == "integer"

    def test_version_age_days_positioned_after_time_lag_days(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert field_names.index("version_age_days") == field_names.index("time_lag_days") + 1

    def test_packages_schema_has_is_prerelease_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "is_prerelease" in field_names

    def test_packages_schema_has_is_yanked_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "is_yanked" in field_names

    def test_packages_schema_has_is_deprecated_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "is_deprecated" in field_names

    def test_packages_schema_has_is_package_unpublished_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "is_package_unpublished" in field_names

    def test_is_prerelease_is_boolean_type(self, packages_schema):
        field = next(f for f in packages_schema["fields"] if f["name"] == "is_prerelease")
        assert field["type"] == "boolean"

    def test_is_yanked_is_boolean_type(self, packages_schema):
        field = next(f for f in packages_schema["fields"] if f["name"] == "is_yanked")
        assert field["type"] == "boolean"

    def test_v1_3_schema_still_registered(self, registry):
        path = registry.get_schema_path(ExportCsvSchemaVersion.V1_3, "packages")
        assert path.exists()


class TestCsvRendererV14(CsvExportRendererBaseTest):
    schema_version = "1.4"
    expected_packages_headers = _PACKAGES_HEADERS_V14

    @pytest.fixture
    def prerelease_record(self):
        return ScanRecord(
            package_name="mylib",
            dependency_name="mylib",
            is_optional_dependency=False,
            installed_version="1.0.0b2",
            latest_version="1.0.0",
            versions_diff_index=VersionsDifference("1.0.0b2", "1.0.0", 1, "DIFF_PATCH"),
            time_lag_days=10,
            releases_lag=1,
            cve=[],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
            is_installed_prerelease=True,
            is_installed_yanked=False,
        )

    @pytest.fixture
    def yanked_record(self):
        return ScanRecord(
            package_name="oldlib",
            dependency_name="oldlib",
            is_optional_dependency=False,
            installed_version="0.9.0",
            latest_version="1.0.0",
            versions_diff_index=VersionsDifference("0.9.0", "1.0.0", 2, "DIFF_MAJOR"),
            time_lag_days=100,
            releases_lag=5,
            cve=[],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
            is_installed_prerelease=False,
            is_installed_yanked=True,
        )

    @pytest.fixture
    def deprecated_record(self):
        return ScanRecord(
            package_name="oldutil",
            dependency_name="oldutil",
            is_optional_dependency=False,
            installed_version="1.0.0",
            latest_version="2.0.0",
            versions_diff_index=VersionsDifference("1.0.0", "2.0.0", 2, "DIFF_MAJOR"),
            time_lag_days=200,
            releases_lag=10,
            cve=[],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
            is_installed_prerelease=False,
            is_installed_yanked=False,
            is_installed_deprecated=True,
            is_installed_package_unpublished=False,
        )

    @pytest.fixture
    def unpublished_record(self):
        return ScanRecord(
            package_name="gone-pkg",
            dependency_name="gone-pkg",
            is_optional_dependency=False,
            installed_version="1.0.0",
            latest_version="1.0.0",
            versions_diff_index=VersionsDifference("1.0.0", "1.0.0", 0, "NO_DIFF"),
            time_lag_days=0,
            releases_lag=0,
            cve=[],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
            is_installed_prerelease=False,
            is_installed_yanked=False,
            is_installed_deprecated=False,
            is_installed_package_unpublished=True,
        )

    def _metrics_with(self, record: ScanRecord) -> ScanResult:
        return ScanResult(
            project_name="test-project",
            project_path="/path/to/test-project",
            packages_registry="npm",
            production_packages=[record],
            optional_packages=[],
        )

    def test_no_schema_version_defaults_to_latest(self, settings, sample_metrics, tmp_path):
        renderer = CsvExportRenderer(settings)
        renderer.render(sample_metrics, destination=str(tmp_path / "export.csv"))
        with open(tmp_path / "export" / "summary.csv", encoding="utf-8-sig", newline="") as f:
            row = next(csv_module.DictReader(f))
        assert row["schema_version"] == csv_schema_registry.get_latest_version().value

    def test_is_prerelease_true_for_prerelease_package(self, settings, prerelease_record, tmp_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, self._metrics_with(prerelease_record), tmp_path / "export.csv")
        with open(tmp_path / "export" / "packages.csv", encoding="utf-8-sig", newline="") as f:
            row = next(csv_module.DictReader(f))
        assert row["is_prerelease"] == "true"
        assert row["is_yanked"] == "false"

    def test_is_yanked_true_for_yanked_package(self, settings, yanked_record, tmp_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, self._metrics_with(yanked_record), tmp_path / "export.csv")
        with open(tmp_path / "export" / "packages.csv", encoding="utf-8-sig", newline="") as f:
            row = next(csv_module.DictReader(f))
        assert row["is_prerelease"] == "false"
        assert row["is_yanked"] == "true"

    def test_is_deprecated_true_for_deprecated_package(self, settings, deprecated_record, tmp_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, self._metrics_with(deprecated_record), tmp_path / "export.csv")
        with open(tmp_path / "export" / "packages.csv", encoding="utf-8-sig", newline="") as f:
            row = next(csv_module.DictReader(f))
        assert row["is_deprecated"] == "true"
        assert row["is_package_unpublished"] == "false"

    def test_is_package_unpublished_true_for_unpublished_package(self, settings, unpublished_record, tmp_path):
        renderer = CsvExportRenderer(settings)
        self._render(renderer, self._metrics_with(unpublished_record), tmp_path / "export.csv")
        with open(tmp_path / "export" / "packages.csv", encoding="utf-8-sig", newline="") as f:
            row = next(csv_module.DictReader(f))
        assert row["is_package_unpublished"] == "true"
        assert row["is_deprecated"] == "false"
