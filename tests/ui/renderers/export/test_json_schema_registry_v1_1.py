"""
Tests for export schema registry v1.1.

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
def v1_1_schema(registry):
    """Load v1.1 schema for tests."""
    return registry.load_schema(ExportJsonSchemaVersion.V1_1)


class TestSchemaRegistryV11:
    """Test suite for schema registry v1.1."""

    def test_get_schema_path_returns_valid_path_for_v1_1(self, registry):
        """Test getting schema path for v1.1 returns existing file.

        AAA Pattern:
        - Arrange: Registry fixture
        - Act: Get schema path for v1.1
        - Assert: Path is valid and file exists
        """
        # Act
        path = registry.get_schema_path(ExportJsonSchemaVersion.V1_1)

        # Assert
        assert isinstance(path, Path)
        assert path.name == "export_schema_v1.1.json"
        assert path.exists()

    def test_load_schema_returns_valid_json_schema(self, v1_1_schema):
        """Test loading v1.1 schema returns valid JSON schema structure.

        AAA Pattern:
        - Arrange: Load schema via fixture
        - Act: Schema is already loaded
        - Assert: Verify schema structure and metadata
        """
        # Assert
        assert isinstance(v1_1_schema, dict)
        assert v1_1_schema["$schema"] == "http://json-schema.org/draft-07/schema#"
        assert v1_1_schema["title"] == "OSS-IQ Export Schema v1.1"

    @pytest.mark.parametrize(
        "required_property",
        [
            "metadata",
            "project",
            "summary",
            "production_packages",
            "development_packages",
            "transitive_packages",
        ],
    )
    def test_schema_contains_required_properties(self, v1_1_schema, required_property):
        """Test schema contains all required top-level properties including transitive_packages.

        AAA Pattern:
        - Arrange: Load schema and parametrize properties
        - Act: Extract properties from schema
        - Assert: Required property exists
        """
        # Act
        properties = v1_1_schema["properties"]

        # Assert
        assert required_property in properties

    def test_schema_has_required_top_level_fields(self, v1_1_schema):
        """Test loaded schema has expected top-level structure fields.

        AAA Pattern:
        - Arrange: Load schema via fixture
        - Act: Check for required schema fields
        - Assert: Verify properties and required fields exist
        """
        # Assert
        assert "properties" in v1_1_schema
        assert "required" in v1_1_schema

    def test_transitive_packages_in_required_array(self, v1_1_schema):
        """Test transitive_packages is listed as a required field.

        AAA Pattern:
        - Arrange: Load schema
        - Act: Check required array
        - Assert: transitive_packages is required
        """
        # Act
        required = v1_1_schema["required"]

        # Assert
        assert "transitive_packages" in required

    def test_get_latest_version_returns_v1_1(self, registry):
        """Test registry returns v1.1 as the latest schema version.

        AAA Pattern:
        - Arrange: Registry fixture
        - Act: Get latest version
        - Assert: Version is v1.1
        """
        # Act
        latest = registry.get_latest_version()

        # Assert
        assert latest == ExportJsonSchemaVersion.V1_1

    def test_list_versions_includes_v1_0_and_v1_1(self, registry):
        """Test listing all registered versions includes both v1.0 and v1.1.

        AAA Pattern:
        - Arrange: Registry fixture
        - Act: List all versions
        - Assert: Both versions are present
        """
        # Act
        versions = registry.list_versions()

        # Assert
        assert ExportJsonSchemaVersion.V1_0 in versions
        assert ExportJsonSchemaVersion.V1_1 in versions

    def test_schema_file_contains_valid_json(self, registry):
        """Test schema file on disk can be parsed as valid JSON.

        AAA Pattern:
        - Arrange: Get schema file path
        - Act: Parse file as JSON
        - Assert: Result is a dictionary
        """
        # Arrange
        schema_path = registry.get_schema_path(ExportJsonSchemaVersion.V1_1)

        # Act
        with open(schema_path, encoding="utf-8") as f:
            data = json.load(f)

        # Assert
        assert isinstance(data, dict)

    @pytest.mark.parametrize(
        "definition_name",
        ["PackageMetrics", "CVEInfo"],
    )
    def test_schema_contains_required_definitions(self, v1_1_schema, definition_name):
        """Test schema contains expected model definitions in $defs.

        AAA Pattern:
        - Arrange: Load schema and parametrize definition names
        - Act: Extract definitions from schema
        - Assert: Required definition exists
        """
        # Act
        definitions = v1_1_schema["$defs"]

        # Assert
        assert definition_name in definitions

    def test_package_metrics_has_dependency_name_field(self, v1_1_schema):
        """Test PackageMetrics definition includes dependency_name property.

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract PackageMetrics properties
        - Assert: dependency_name field is present
        """
        # Act
        package_metrics_props = v1_1_schema["$defs"]["PackageMetrics"]["properties"]

        # Assert
        assert "dependency_name" in package_metrics_props

    def test_dependency_name_allows_null(self, v1_1_schema):
        """Test dependency_name field allows null (when no alias is used).

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract dependency_name type definition
        - Assert: null is an allowed type
        """
        # Act
        dependency_name = v1_1_schema["$defs"]["PackageMetrics"]["properties"]["dependency_name"]

        # Assert
        assert "null" in dependency_name["type"]

    def test_package_metrics_has_dependency_path_field(self, v1_1_schema):
        """Test PackageMetrics definition includes dependency_path property.

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract PackageMetrics properties
        - Assert: dependency_path field is present
        """
        # Act
        package_metrics_props = v1_1_schema["$defs"]["PackageMetrics"]["properties"]

        # Assert
        assert "dependency_path" in package_metrics_props

    def test_dependency_path_allows_null(self, v1_1_schema):
        """Test dependency_path field allows null (for direct dependencies).

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract dependency_path type definition
        - Assert: null is an allowed type
        """
        # Act
        dependency_path = v1_1_schema["$defs"]["PackageMetrics"]["properties"]["dependency_path"]

        # Assert
        assert "null" in dependency_path["type"]

    def test_transitive_packages_items_ref_package_metrics(self, v1_1_schema):
        """Test transitive_packages array items reference PackageMetrics definition.

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract transitive_packages items $ref
        - Assert: References PackageMetrics definition
        """
        # Act
        items_ref = v1_1_schema["properties"]["transitive_packages"]["items"]["$ref"]

        # Assert
        assert items_ref == "#/$defs/PackageMetrics"

    def test_schema_version_const_is_1_1(self, v1_1_schema):
        """Test metadata schema_version const value is 1.1.

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract schema_version const
        - Assert: Const is "1.1"
        """
        # Act
        schema_version_const = v1_1_schema["properties"]["metadata"]["properties"]["schema_version"]["const"]

        # Assert
        assert schema_version_const == "1.1"

    def test_global_registry_instance_accessible(self):
        """Test global registry singleton is accessible and functional for v1.1.

        AAA Pattern:
        - Arrange: Global json_schema_registry instance
        - Act: Get schema path from global instance
        - Assert: Instance is valid and path exists
        """
        # Act
        path = json_schema_registry.get_schema_path(ExportJsonSchemaVersion.V1_1)

        # Assert
        assert isinstance(json_schema_registry, SchemaRegistry)
        assert path.exists()
