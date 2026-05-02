"""
Base test class for CSV schema registry tests.

Subclasses set class-level attributes (version, packages_field_count, etc.) and
inherit all shared infrastructure tests. Version-specific assertions live only
in the version files.
"""

from pathlib import Path

import pytest

from ossiq.domain.common import ExportCsvSchemaVersion
from ossiq.ui.renderers.export.csv_schema_registry import CsvSchemaRegistry, csv_schema_registry


class CsvSchemaRegistryBaseTest:
    """Shared tests for all CSV schema versions. Not collected directly by pytest."""

    version: ExportCsvSchemaVersion
    packages_field_count: int
    summary_field_count: int = 11
    cves_field_count: int = 10
    included_versions: list

    @pytest.fixture
    def registry(self):
        return CsvSchemaRegistry()

    @pytest.fixture
    def summary_schema(self, registry):
        return registry.load_schema(self.version, "summary")

    @pytest.fixture
    def packages_schema(self, registry):
        return registry.load_schema(self.version, "packages")

    @pytest.fixture
    def cves_schema(self, registry):
        return registry.load_schema(self.version, "cves")

    @pytest.mark.parametrize("schema_type", ["summary", "packages", "cves"])
    def test_get_schema_path_returns_valid_path(self, registry, schema_type):
        path = registry.get_schema_path(self.version, schema_type)
        assert isinstance(path, Path)
        assert path.name == f"{schema_type}-schema-v{self.version.value}.json"
        assert path.exists()

    def test_load_summary_schema_has_correct_structure(self, summary_schema):
        assert isinstance(summary_schema, dict)
        assert "fields" in summary_schema
        assert len(summary_schema["fields"]) == self.summary_field_count
        assert summary_schema["fields"][0]["name"] == "schema_version"

    def test_load_packages_schema_has_correct_structure(self, packages_schema):
        assert isinstance(packages_schema, dict)
        assert "fields" in packages_schema
        assert "primaryKey" in packages_schema
        assert packages_schema["primaryKey"] == ["package_name"]

    def test_load_packages_schema_has_expected_field_count(self, packages_schema):
        assert len(packages_schema["fields"]) == self.packages_field_count

    def test_load_cves_schema_has_correct_structure(self, cves_schema):
        assert isinstance(cves_schema, dict)
        assert "fields" in cves_schema
        assert len(cves_schema["fields"]) == self.cves_field_count
        assert cves_schema["fields"][0]["name"] == "cve_id"
        assert "foreignKeys" in cves_schema

    def test_cves_schema_foreign_key_references_packages(self, cves_schema):
        fk = cves_schema["foreignKeys"][0]
        assert fk["fields"] == ["package_name"]
        assert fk["reference"]["resource"] == "packages"
        assert fk["reference"]["fields"] == ["package_name"]

    @pytest.mark.parametrize("schema_type", ["summary", "packages", "cves"])
    def test_validate_schema_passes(self, registry, schema_type):
        is_valid, errors = registry.validate_schema(self.version, schema_type)
        assert is_valid is True, f"Schema validation failed: {errors}"
        assert len(errors) == 0

    def test_summary_schema_fields_have_required_properties(self, summary_schema):
        for field in summary_schema["fields"]:
            assert "name" in field, f"Field missing name: {field}"
            assert "type" in field, f"Field {field.get('name', 'unknown')} missing type"

    def test_get_latest_version_returns_v1_4(self, registry):
        assert registry.get_latest_version() == ExportCsvSchemaVersion.V1_4

    def test_list_versions_includes_version(self, registry):
        assert self.version in registry.list_versions()

    def test_list_versions_includes_all_expected(self, registry):
        versions = registry.list_versions()
        for v in self.included_versions:
            assert v in versions, f"Missing version in registry: {v}"

    def test_list_schema_types_returns_all_types(self, registry):
        types = registry.list_schema_types(self.version)
        assert isinstance(types, list)
        assert len(types) == 3
        assert "summary" in types
        assert "packages" in types
        assert "cves" in types

    def test_global_registry_instance_accessible(self):
        path = csv_schema_registry.get_schema_path(self.version, "summary")
        assert isinstance(csv_schema_registry, CsvSchemaRegistry)
        assert path.exists()
