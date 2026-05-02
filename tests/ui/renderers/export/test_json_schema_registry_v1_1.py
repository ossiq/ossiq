"""Tests for export schema registry v1.1."""

from ossiq.domain.common import ExportJsonSchemaVersion
from tests.ui.renderers.export.test_json_schema_registry_base import SchemaRegistryBaseTest


class TestSchemaRegistryV11(SchemaRegistryBaseTest):
    version = ExportJsonSchemaVersion.V1_1
    schema_path_name = "export_schema_v1.1.json"
    schema_title = "OSS-IQ Export Schema v1.1"
    required_top_level_properties = [
        "metadata",
        "project",
        "summary",
        "production_packages",
        "development_packages",
        "transitive_packages",
    ]
    required_definitions = ["PackageMetrics", "CVEInfo"]
    included_versions = [ExportJsonSchemaVersion.V1_0, ExportJsonSchemaVersion.V1_1]

    def test_transitive_packages_in_required_array(self, schema):
        assert "transitive_packages" in schema["required"]

    def test_package_metrics_has_dependency_name_field(self, schema):
        assert "dependency_name" in schema["$defs"]["PackageMetrics"]["properties"]

    def test_dependency_name_allows_null(self, schema):
        dependency_name = schema["$defs"]["PackageMetrics"]["properties"]["dependency_name"]
        assert "null" in dependency_name["type"]

    def test_package_metrics_has_dependency_path_field(self, schema):
        assert "dependency_path" in schema["$defs"]["PackageMetrics"]["properties"]

    def test_dependency_path_allows_null(self, schema):
        dependency_path = schema["$defs"]["PackageMetrics"]["properties"]["dependency_path"]
        assert "null" in dependency_path["type"]

    def test_transitive_packages_items_ref_package_metrics(self, schema):
        items_ref = schema["properties"]["transitive_packages"]["items"]["$ref"]
        assert items_ref == "#/$defs/PackageMetrics"

    def test_schema_version_const_is_1_1(self, schema):
        const = schema["properties"]["metadata"]["properties"]["schema_version"]["const"]
        assert const == "1.1"
