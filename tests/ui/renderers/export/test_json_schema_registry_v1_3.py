"""
Tests for export schema registry v1.3.

This test suite follows pytest best practices:
- AAA pattern (Arrange-Act-Assert) for clear test structure
- Parametrization to reduce test duplication
- Fixtures for reusable setup/teardown
- Single responsibility per test
"""

import json
from pathlib import Path

import pytest

from ossiq.domain.common import ExportJsonSchemaVersion
from ossiq.ui.renderers.export.json_schema_registry import SchemaRegistry, json_schema_registry


@pytest.fixture
def registry():
    """Create a SchemaRegistry instance for tests."""
    return SchemaRegistry()


@pytest.fixture
def v1_3_schema(registry):
    """Load v1.3 schema for tests."""
    return registry.load_schema(ExportJsonSchemaVersion.V1_3)


class TestSchemaRegistryV13:
    """Test suite for schema registry v1.3."""

    def test_get_schema_path_returns_valid_path_for_v1_3(self, registry):
        """Test getting schema path for v1.3 returns existing file.

        AAA Pattern:
        - Arrange: Registry fixture
        - Act: Get schema path for v1.3
        - Assert: Path is valid and file exists
        """
        # Act
        path = registry.get_schema_path(ExportJsonSchemaVersion.V1_3)

        # Assert
        assert isinstance(path, Path)
        assert path.name == "export_schema_v1.3.json"
        assert path.exists()

    def test_load_schema_returns_valid_json_schema(self, v1_3_schema):
        """Test loading v1.3 schema returns valid JSON schema structure.

        AAA Pattern:
        - Arrange: Load schema via fixture
        - Act: Schema is already loaded
        - Assert: Verify schema structure and metadata
        """
        # Assert
        assert isinstance(v1_3_schema, dict)
        assert v1_3_schema["$schema"] == "http://json-schema.org/draft-07/schema#"
        assert v1_3_schema["title"] == "OSS-IQ Export Schema v1.3"

    @pytest.mark.parametrize(
        "required_property",
        [
            "metadata",
            "project",
            "summary",
            "production_packages",
            "development_packages",
            "transitive_packages",
            "dependency_tree",
            "constraint_type_map",
        ],
    )
    def test_schema_contains_required_properties(self, v1_3_schema, required_property):
        """Test schema contains all required top-level properties.

        AAA Pattern:
        - Arrange: Load schema and parametrize properties
        - Act: Extract properties from schema
        - Assert: Required property exists
        """
        # Act
        properties = v1_3_schema["properties"]

        # Assert
        assert required_property in properties

    def test_schema_version_const_is_1_3(self, v1_3_schema):
        """Test metadata schema_version const value is 1.3.

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract schema_version const
        - Assert: Const is "1.3"
        """
        # Act
        schema_version_const = v1_3_schema["properties"]["metadata"]["properties"]["schema_version"]["const"]

        # Assert
        assert schema_version_const == "1.3"

    def test_transitive_packages_items_ref_transitive_package_metrics(self, v1_3_schema):
        """Test transitive_packages array items reference TransitivePackageMetrics, not PackageMetrics.

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract transitive_packages items $ref
        - Assert: References TransitivePackageMetrics definition
        """
        # Act
        items_ref = v1_3_schema["properties"]["transitive_packages"]["items"]["$ref"]

        # Assert
        assert items_ref == "#/$defs/TransitivePackageMetrics"

    def test_production_packages_items_still_ref_package_metrics(self, v1_3_schema):
        """Test production_packages still references PackageMetrics (regression guard).

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract production_packages items $ref
        - Assert: References PackageMetrics
        """
        # Act
        items_ref = v1_3_schema["properties"]["production_packages"]["items"]["$ref"]

        # Assert
        assert items_ref == "#/$defs/PackageMetrics"

    def test_dependency_tree_items_ref_dependency_tree_root(self, v1_3_schema):
        """Test dependency_tree array items reference DependencyTreeRoot.

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract dependency_tree items $ref
        - Assert: References DependencyTreeRoot definition
        """
        # Act
        items_ref = v1_3_schema["properties"]["dependency_tree"]["items"]["$ref"]

        # Assert
        assert items_ref == "#/$defs/DependencyTreeRoot"

    def test_schema_does_not_contain_dependency_path_definition(self, v1_3_schema):
        """Test $defs no longer contains the old DependencyPath definition.

        AAA Pattern:
        - Arrange: Load schema
        - Act: Check $defs
        - Assert: DependencyPath is absent
        """
        # Assert
        assert "DependencyPath" not in v1_3_schema["$defs"]

    def test_schema_contains_transitive_package_metrics_definition(self, v1_3_schema):
        """Test $defs contains TransitivePackageMetrics definition.

        AAA Pattern:
        - Arrange: Load schema
        - Act: Check $defs
        - Assert: TransitivePackageMetrics is defined
        """
        # Assert
        assert "TransitivePackageMetrics" in v1_3_schema["$defs"]

    def test_transitive_package_metrics_has_no_dependency_paths_field(self, v1_3_schema):
        """TransitivePackageMetrics must not contain a dependency_paths property.

        AAA Pattern:
        - Arrange: Load schema
        - Act: Check TransitivePackageMetrics properties
        - Assert: dependency_paths is absent
        """
        # Act
        props = v1_3_schema["$defs"]["TransitivePackageMetrics"].get("properties", {})

        # Assert
        assert "dependency_paths" not in props

    def test_dependency_tree_node_ct_is_integer(self, v1_3_schema):
        """Test DependencyTreeNode.ct is a non-negative integer (index into constraint_type_map).

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract ct definition from DependencyTreeNode
        - Assert: Type is integer with minimum 0
        """
        # Act
        ct = v1_3_schema["$defs"]["DependencyTreeNode"]["properties"]["ct"]

        # Assert
        assert ct["type"] == "integer"
        assert ct["minimum"] == 0

    def test_dependency_tree_node_has_no_constraint_type_string_field(self, v1_3_schema):
        """Test DependencyTreeNode no longer has a constraint_type string field."""
        props = v1_3_schema["$defs"]["DependencyTreeNode"].get("properties", {})
        assert "constraint_type" not in props

    def test_transitive_package_metrics_has_id_field(self, v1_3_schema):
        """Test TransitivePackageMetrics has an id integer field."""
        props = v1_3_schema["$defs"]["TransitivePackageMetrics"].get("properties", {})
        assert "id" in props
        assert props["id"]["type"] == "integer"
        assert props["id"]["minimum"] == 0

    def test_schema_has_constraint_type_map_property(self, v1_3_schema):
        """Test top-level schema has a constraint_type_map array property."""
        props = v1_3_schema["properties"]
        assert "constraint_type_map" in props
        assert props["constraint_type_map"]["type"] == "array"

    def test_dependency_tree_node_ref_is_integer(self, v1_3_schema):
        """Test DependencyTreeNode.ref is an integer with minimum 0.

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract ref definition
        - Assert: Type is integer, minimum is 0
        """
        # Act
        ref_schema = v1_3_schema["$defs"]["DependencyTreeNode"]["properties"]["ref"]

        # Assert
        assert ref_schema["type"] == "integer"
        assert ref_schema["minimum"] == 0

    def test_dependency_tree_node_children_ref_self(self, v1_3_schema):
        """Test DependencyTreeNode.children items reference DependencyTreeNode (recursive).

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract children items $ref
        - Assert: Self-reference for recursive structure
        """
        # Act
        children_ref = v1_3_schema["$defs"]["DependencyTreeNode"]["properties"]["children"]["items"]["$ref"]

        # Assert
        assert children_ref == "#/$defs/DependencyTreeNode"

    @pytest.mark.parametrize(
        "definition_name",
        ["PackageMetrics", "CVEInfo", "DependencyTreeRoot", "DependencyTreeNode", "TransitivePackageMetrics"],
    )
    def test_schema_contains_required_definitions(self, v1_3_schema, definition_name):
        """Test schema contains all expected model definitions in $defs.

        AAA Pattern:
        - Arrange: Load schema and parametrize definition names
        - Act: Extract definitions from schema
        - Assert: Required definition exists
        """
        # Act
        definitions = v1_3_schema["$defs"]

        # Assert
        assert definition_name in definitions

    def test_get_latest_version_returns_v1_3(self, registry):
        """Test registry returns v1.3 as the latest schema version.

        AAA Pattern:
        - Arrange: Registry fixture
        - Act: Get latest version
        - Assert: Version is v1.3
        """
        # Act
        latest = registry.get_latest_version()

        # Assert
        assert latest == ExportJsonSchemaVersion.V1_4

    def test_list_versions_includes_all_four_versions(self, registry):
        """Test listing all registered versions includes v1.0 through v1.3.

        AAA Pattern:
        - Arrange: Registry fixture
        - Act: List all versions
        - Assert: All four versions are present
        """
        # Act
        versions = registry.list_versions()

        # Assert
        assert ExportJsonSchemaVersion.V1_0 in versions
        assert ExportJsonSchemaVersion.V1_1 in versions
        assert ExportJsonSchemaVersion.V1_2 in versions
        assert ExportJsonSchemaVersion.V1_3 in versions

    def test_schema_file_contains_valid_json(self, registry):
        """Test schema file on disk can be parsed as valid JSON.

        AAA Pattern:
        - Arrange: Get schema file path
        - Act: Parse file as JSON
        - Assert: Result is a dictionary
        """
        # Arrange
        schema_path = registry.get_schema_path(ExportJsonSchemaVersion.V1_3)

        # Act
        with open(schema_path, encoding="utf-8") as f:
            data = json.load(f)

        # Assert
        assert isinstance(data, dict)

    def test_global_registry_instance_accessible(self):
        """Test global registry singleton is accessible and functional for v1.3.

        AAA Pattern:
        - Arrange: Global json_schema_registry instance
        - Act: Get schema path from global instance
        - Assert: Instance is valid and path exists
        """
        # Act
        path = json_schema_registry.get_schema_path(ExportJsonSchemaVersion.V1_3)

        # Assert
        assert isinstance(json_schema_registry, SchemaRegistry)
        assert path.exists()
