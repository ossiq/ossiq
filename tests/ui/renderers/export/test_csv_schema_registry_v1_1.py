"""Tests for CSV export schema registry v1.1."""

from ossiq.domain.common import ExportCsvSchemaVersion
from tests.ui.renderers.export.test_csv_base import CsvExportRendererBaseTest
from tests.ui.renderers.export.test_csv_schema_registry_base import CsvSchemaRegistryBaseTest


class TestCsvSchemaRegistryV11(CsvSchemaRegistryBaseTest):
    version = ExportCsvSchemaVersion.V1_1
    packages_field_count = 12
    included_versions = [ExportCsvSchemaVersion.V1_0, ExportCsvSchemaVersion.V1_1]

    def test_packages_schema_has_dependency_name_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "dependency_name" in field_names

    def test_packages_schema_has_version_constraint_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "version_constraint" in field_names

    def test_packages_schema_has_license_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "license" in field_names

    def test_packages_schema_has_purl_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "purl" in field_names

    def test_packages_schema_has_no_constraint_type_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "constraint_type" not in field_names

    def test_packages_schema_has_no_version_age_days_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "version_age_days" not in field_names

    def test_packages_schema_has_no_is_prerelease_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "is_prerelease" not in field_names


class TestCsvRendererV11(CsvExportRendererBaseTest):
    schema_version = "1.1"
    datapackage_validates = False
