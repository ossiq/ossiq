"""Tests for CSV export schema registry v1.0."""

import pytest

from ossiq.domain.common import ExportCsvSchemaVersion
from ossiq.ui.renderers.export.csv_schema_registry import CsvSchemaRegistry
from tests.ui.renderers.export.test_csv_base import CsvExportRendererBaseTest
from tests.ui.renderers.export.test_csv_schema_registry_base import CsvSchemaRegistryBaseTest


class TestCsvSchemaRegistryV10(CsvSchemaRegistryBaseTest):
    version = ExportCsvSchemaVersion.V1_0
    packages_field_count = 8
    included_versions = [ExportCsvSchemaVersion.V1_0]

    def test_packages_schema_first_field_is_package_name(self, packages_schema):
        assert packages_schema["fields"][0]["name"] == "package_name"
        assert packages_schema["fields"][0]["type"] == "string"

    def test_packages_schema_has_no_dependency_name_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "dependency_name" not in field_names

    def test_packages_schema_has_no_version_constraint_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "version_constraint" not in field_names

    def test_packages_schema_has_no_license_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "license" not in field_names

    def test_packages_schema_has_no_version_age_days_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "version_age_days" not in field_names

    def test_get_schema_path_raises_for_invalid_type(self):
        from typing import cast

        from ossiq.ui.renderers.export.csv_schema_registry import SchemaType

        registry = CsvSchemaRegistry()
        with pytest.raises(ValueError, match="Schema type 'invalid' not found"):
            registry.get_schema_path(ExportCsvSchemaVersion.V1_0, cast(SchemaType, "invalid"))

    def test_validate_csv_with_valid_summary(self, tmp_path):
        registry = CsvSchemaRegistry()
        csv_file = tmp_path / "test-summary.csv"
        csv_content = (
            "schema_version,export_timestamp,project_name,project_path,project_registry,"
            "total_packages,production_packages,development_packages,packages_with_cves,total_cves,packages_outdated\n"
            "1.0,2025-01-09T12:00:00,test-project,/path/to/project,npm,10,8,2,3,5,4\n"
        )
        csv_file.write_text(csv_content, encoding="utf-8-sig")
        is_valid, errors = registry.validate_csv(csv_file, ExportCsvSchemaVersion.V1_0, "summary")
        assert is_valid is True, f"Validation failed: {errors}"
        assert len(errors) == 0

    def test_validate_csv_fails_with_wrong_columns(self, tmp_path):
        registry = CsvSchemaRegistry()
        csv_file = tmp_path / "test-summary.csv"
        csv_file.write_text("wrong_column,another_column\nvalue1,value2\n", encoding="utf-8-sig")
        is_valid, errors = registry.validate_csv(csv_file, ExportCsvSchemaVersion.V1_0, "summary")
        assert is_valid is False
        assert len(errors) > 0
        assert "Column mismatch" in errors[0]

    def test_validate_csv_fails_with_wrong_row_count_for_summary(self, tmp_path):
        registry = CsvSchemaRegistry()
        csv_file = tmp_path / "test-summary.csv"
        csv_content = (
            "schema_version,export_timestamp,project_name,project_path,project_registry,"
            "total_packages,production_packages,development_packages,packages_with_cves,total_cves,packages_outdated\n"
            "1.0,2025-01-09T12:00:00,test-project,/path/to/project,npm,10,8,2,3,5,4\n"
            "1.0,2025-01-09T12:00:00,test-project2,/path/to/project2,pypi,20,15,5,5,10,8\n"
        )
        csv_file.write_text(csv_content, encoding="utf-8-sig")
        is_valid, errors = registry.validate_csv(csv_file, ExportCsvSchemaVersion.V1_0, "summary")
        assert is_valid is False
        assert len(errors) > 0
        assert "should have exactly 1 data row" in errors[0]

    def test_validate_csv_with_empty_packages(self, tmp_path):
        registry = CsvSchemaRegistry()
        csv_file = tmp_path / "test-packages.csv"
        csv_content = (
            "package_name,dependency_type,is_optional_dependency,installed_version,"
            "latest_version,time_lag_days,releases_lag,cve_count\n"
        )
        csv_file.write_text(csv_content, encoding="utf-8-sig")
        is_valid, errors = registry.validate_csv(csv_file, ExportCsvSchemaVersion.V1_0, "packages")
        assert is_valid is True, f"Validation failed: {errors}"
        assert len(errors) == 0

    def test_validate_csv_with_valid_packages(self, tmp_path):
        registry = CsvSchemaRegistry()
        csv_file = tmp_path / "test-packages.csv"
        csv_content = (
            "package_name,dependency_type,is_optional_dependency,installed_version,"
            "latest_version,time_lag_days,releases_lag,cve_count\n"
            "react,production,false,17.0.2,18.2.0,245,12,1\n"
            "lodash,development,true,4.17.20,4.17.21,180,1,0\n"
        )
        csv_file.write_text(csv_content, encoding="utf-8-sig")
        is_valid, errors = registry.validate_csv(csv_file, ExportCsvSchemaVersion.V1_0, "packages")
        assert is_valid is True, f"Validation failed: {errors}"
        assert len(errors) == 0

    def test_validate_csv_with_valid_cves(self, tmp_path):
        registry = CsvSchemaRegistry()
        csv_file = tmp_path / "test-cves.csv"
        csv_content = (
            "cve_id,package_name,package_registry,source,severity,summary,"
            "affected_versions,all_cve_ids,published,link\n"
            "GHSA-test-1234,react,npm,GHSA,HIGH,Test vulnerability,<18.0.0,"
            "CVE-2023-12345|GHSA-test-1234,2023-03-15T00:00:00,https://example.com\n"
        )
        csv_file.write_text(csv_content, encoding="utf-8-sig")
        is_valid, errors = registry.validate_csv(csv_file, ExportCsvSchemaVersion.V1_0, "cves")
        assert is_valid is True, f"Validation failed: {errors}"
        assert len(errors) == 0


class TestCsvRendererV10(CsvExportRendererBaseTest):
    schema_version = "1.0"
    datapackage_validates = False
