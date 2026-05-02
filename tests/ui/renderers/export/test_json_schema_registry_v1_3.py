"""Tests for export schema registry v1.3."""

from ossiq.domain.common import ExportJsonSchemaVersion
from tests.ui.renderers.export.test_json_schema_registry_base import SchemaRegistryBaseTest


class TestSchemaRegistryV13(SchemaRegistryBaseTest):
    version = ExportJsonSchemaVersion.V1_3
    schema_path_name = "export_schema_v1.3.json"
    schema_title = "OSS-IQ Export Schema v1.3"
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
    ]

    def test_schema_version_const_is_1_3(self, schema):
        const = schema["properties"]["metadata"]["properties"]["schema_version"]["const"]
        assert const == "1.3"

    def test_transitive_packages_items_ref_transitive_package_metrics(self, schema):
        items_ref = schema["properties"]["transitive_packages"]["items"]["$ref"]
        assert items_ref == "#/$defs/TransitivePackageMetrics"

    def test_production_packages_items_still_ref_package_metrics(self, schema):
        items_ref = schema["properties"]["production_packages"]["items"]["$ref"]
        assert items_ref == "#/$defs/PackageMetrics"

    def test_dependency_tree_items_ref_dependency_tree_root(self, schema):
        items_ref = schema["properties"]["dependency_tree"]["items"]["$ref"]
        assert items_ref == "#/$defs/DependencyTreeRoot"

    def test_schema_does_not_contain_dependency_path_definition(self, schema):
        assert "DependencyPath" not in schema["$defs"]

    def test_schema_contains_transitive_package_metrics_definition(self, schema):
        assert "TransitivePackageMetrics" in schema["$defs"]

    def test_transitive_package_metrics_has_no_dependency_paths_field(self, schema):
        props = schema["$defs"]["TransitivePackageMetrics"].get("properties", {})
        assert "dependency_paths" not in props

    def test_dependency_tree_node_ct_is_integer(self, schema):
        ct = schema["$defs"]["DependencyTreeNode"]["properties"]["ct"]
        assert ct["type"] == "integer"
        assert ct["minimum"] == 0

    def test_dependency_tree_node_has_no_constraint_type_string_field(self, schema):
        props = schema["$defs"]["DependencyTreeNode"].get("properties", {})
        assert "constraint_type" not in props

    def test_transitive_package_metrics_has_id_field(self, schema):
        props = schema["$defs"]["TransitivePackageMetrics"].get("properties", {})
        assert "id" in props
        assert props["id"]["type"] == "integer"
        assert props["id"]["minimum"] == 0

    def test_schema_has_constraint_type_map_property(self, schema):
        props = schema["properties"]
        assert "constraint_type_map" in props
        assert props["constraint_type_map"]["type"] == "array"

    def test_dependency_tree_node_ref_is_integer(self, schema):
        ref_schema = schema["$defs"]["DependencyTreeNode"]["properties"]["ref"]
        assert ref_schema["type"] == "integer"
        assert ref_schema["minimum"] == 0

    def test_dependency_tree_node_children_ref_self(self, schema):
        children_ref = schema["$defs"]["DependencyTreeNode"]["properties"]["children"]["items"]["$ref"]
        assert children_ref == "#/$defs/DependencyTreeNode"
