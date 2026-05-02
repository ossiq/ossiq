"""Tests for export schema registry v1.4."""

from ossiq.domain.common import ExportJsonSchemaVersion
from tests.ui.renderers.export.test_json_schema_registry_base import SchemaRegistryBaseTest


class TestSchemaRegistryV14(SchemaRegistryBaseTest):
    version = ExportJsonSchemaVersion.V1_4
    schema_path_name = "export_schema_v1.4.json"
    schema_title = "OSS-IQ Export Schema v1.4"
    required_top_level_properties = [
        "metadata",
        "project",
        "summary",
        "production_packages",
        "development_packages",
        "transitive_packages",
        "dependency_tree",
        "constraint_type_map",
    ]
    required_definitions = [
        "PackageMetrics",
        "CVEInfo",
        "DependencyTreeRoot",
        "DependencyTreeNode",
        "TransitivePackageMetrics",
    ]
    included_versions = [
        ExportJsonSchemaVersion.V1_0,
        ExportJsonSchemaVersion.V1_1,
        ExportJsonSchemaVersion.V1_2,
        ExportJsonSchemaVersion.V1_3,
        ExportJsonSchemaVersion.V1_4,
    ]

    def test_schema_version_const_is_1_4(self, schema):
        const = schema["properties"]["metadata"]["properties"]["schema_version"]["const"]
        assert const == "1.4"

    def test_schema_contains_is_prerelease_in_package_metrics(self, schema):
        props = schema["$defs"]["PackageMetrics"]["properties"]
        required = schema["$defs"]["PackageMetrics"]["required"]
        assert "is_prerelease" in props
        assert props["is_prerelease"]["type"] == "boolean"
        assert "is_prerelease" in required

    def test_schema_contains_is_yanked_in_package_metrics(self, schema):
        props = schema["$defs"]["PackageMetrics"]["properties"]
        required = schema["$defs"]["PackageMetrics"]["required"]
        assert "is_yanked" in props
        assert props["is_yanked"]["type"] == "boolean"
        assert "is_yanked" in required

    def test_schema_contains_is_deprecated_in_package_metrics(self, schema):
        props = schema["$defs"]["PackageMetrics"]["properties"]
        required = schema["$defs"]["PackageMetrics"]["required"]
        assert "is_deprecated" in props
        assert props["is_deprecated"]["type"] == "boolean"
        assert "is_deprecated" in required

    def test_schema_contains_is_package_unpublished_in_package_metrics(self, schema):
        props = schema["$defs"]["PackageMetrics"]["properties"]
        required = schema["$defs"]["PackageMetrics"]["required"]
        assert "is_package_unpublished" in props
        assert props["is_package_unpublished"]["type"] == "boolean"
        assert "is_package_unpublished" in required

    def test_schema_contains_is_prerelease_in_transitive_package_metrics(self, schema):
        props = schema["$defs"]["TransitivePackageMetrics"]["properties"]
        required = schema["$defs"]["TransitivePackageMetrics"]["required"]
        assert "is_prerelease" in props
        assert props["is_prerelease"]["type"] == "boolean"
        assert "is_prerelease" in required

    def test_schema_contains_is_yanked_in_transitive_package_metrics(self, schema):
        props = schema["$defs"]["TransitivePackageMetrics"]["properties"]
        required = schema["$defs"]["TransitivePackageMetrics"]["required"]
        assert "is_yanked" in props
        assert props["is_yanked"]["type"] == "boolean"
        assert "is_yanked" in required

    def test_schema_contains_is_deprecated_in_transitive_package_metrics(self, schema):
        props = schema["$defs"]["TransitivePackageMetrics"]["properties"]
        required = schema["$defs"]["TransitivePackageMetrics"]["required"]
        assert "is_deprecated" in props
        assert props["is_deprecated"]["type"] == "boolean"
        assert "is_deprecated" in required

    def test_schema_contains_is_package_unpublished_in_transitive_package_metrics(self, schema):
        props = schema["$defs"]["TransitivePackageMetrics"]["properties"]
        required = schema["$defs"]["TransitivePackageMetrics"]["required"]
        assert "is_package_unpublished" in props
        assert props["is_package_unpublished"]["type"] == "boolean"
        assert "is_package_unpublished" in required

    def test_v1_3_schema_still_registered(self, registry):
        path = registry.get_schema_path(ExportJsonSchemaVersion.V1_3)
        assert path.exists()
