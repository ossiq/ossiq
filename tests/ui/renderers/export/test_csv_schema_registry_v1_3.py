"""Tests for CSV export schema registry v1.3."""

from ossiq.domain.common import ExportCsvSchemaVersion
from tests.ui.renderers.export.test_csv_base import CsvExportRendererBaseTest
from tests.ui.renderers.export.test_csv_schema_registry_base import CsvSchemaRegistryBaseTest


class TestCsvSchemaRegistryV13(CsvSchemaRegistryBaseTest):
    version = ExportCsvSchemaVersion.V1_3
    packages_field_count = 15
    included_versions = [
        ExportCsvSchemaVersion.V1_0,
        ExportCsvSchemaVersion.V1_1,
        ExportCsvSchemaVersion.V1_2,
        ExportCsvSchemaVersion.V1_3,
    ]

    def test_packages_schema_has_constraint_type_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "constraint_type" in field_names

    def test_packages_schema_has_extras_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "extras" in field_names

    def test_packages_schema_has_no_version_age_days_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "version_age_days" not in field_names

    def test_packages_schema_has_no_is_prerelease_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "is_prerelease" not in field_names

    def test_packages_schema_has_no_is_yanked_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "is_yanked" not in field_names

    def test_packages_schema_has_no_is_deprecated_column(self, packages_schema):
        field_names = [f["name"] for f in packages_schema["fields"]]
        assert "is_deprecated" not in field_names


class TestCsvRendererV13(CsvExportRendererBaseTest):
    schema_version = "1.3"
