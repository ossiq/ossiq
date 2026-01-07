"""
Tests for export schema registry.

This test suite follows pytest best practices:
- AAA pattern (Arrange-Act-Assert) for clear test structure
- Parametrization to reduce test duplication
- Fixtures for reusable setup/teardown
- Single responsibility per test
- Mocking external dependencies where appropriate
"""

import json
from pathlib import Path

import pytest

from ossiq.domain.common import ExportJsonSchemaVersion
from ossiq.ui.renderers.export.schema_registry import SchemaRegistry, schema_registry


@pytest.fixture
def registry():
    """Create a SchemaRegistry instance for tests."""
    return SchemaRegistry()


@pytest.fixture
def v1_0_schema(registry):
    """Load v1.0 schema for tests."""
    return registry.load_schema(ExportJsonSchemaVersion.V1_0)


class TestSchemaRegistryV10:
    """Test suite for schema registry."""

    def test_get_schema_path_returns_valid_path_for_v1_0(self, registry):
        """Test getting schema path for v1.0 returns existing file.

        AAA Pattern:
        - Arrange: Registry fixture
        - Act: Get schema path for v1.0
        - Assert: Path is valid and file exists
        """
        # Act
        path = registry.get_schema_path(ExportJsonSchemaVersion.V1_0)

        # Assert
        assert isinstance(path, Path)
        assert path.name == "export_schema_v1.0.json"
        assert path.exists()

    def test_load_schema_returns_valid_json_schema(self, v1_0_schema):
        """Test loading v1.0 schema returns valid JSON schema structure.

        AAA Pattern:
        - Arrange: Load schema via fixture
        - Act: Schema is already loaded
        - Assert: Verify schema structure and metadata
        """
        # Assert
        assert isinstance(v1_0_schema, dict)
        assert v1_0_schema["$schema"] == "http://json-schema.org/draft-07/schema#"
        assert v1_0_schema["title"] == "OSS-IQ Export Schema v1.0"

    @pytest.mark.parametrize(
        "required_property",
        ["metadata", "project", "summary", "production_packages", "development_packages"],
    )
    def test_schema_contains_required_properties(self, v1_0_schema, required_property):
        """Test schema contains all required top-level properties.

        AAA Pattern:
        - Arrange: Load schema and parametrize properties
        - Act: Extract properties from schema
        - Assert: Required property exists
        """
        # Act
        properties = v1_0_schema["properties"]

        # Assert
        assert required_property in properties

    def test_schema_has_required_top_level_fields(self, v1_0_schema):
        """Test loaded schema has expected top-level structure fields.

        AAA Pattern:
        - Arrange: Load schema via fixture
        - Act: Check for required schema fields
        - Assert: Verify properties and required fields exist
        """
        # Assert
        assert "properties" in v1_0_schema
        assert "required" in v1_0_schema

    def test_get_latest_version_returns_v1_0(self, registry):
        """Test registry returns correct latest schema version.

        AAA Pattern:
        - Arrange: Registry fixture
        - Act: Get latest version
        - Assert: Version is v1.0
        """
        # Act
        latest = registry.get_latest_version()

        # Assert
        assert latest == ExportJsonSchemaVersion.V1_0

    def test_list_versions_includes_v1_0(self, registry):
        """Test listing all registered versions includes v1.0.

        AAA Pattern:
        - Arrange: Registry fixture
        - Act: List all versions
        - Assert: v1.0 is in the list
        """
        # Act
        versions = registry.list_versions()

        # Assert
        assert isinstance(versions, list)
        assert len(versions) >= 1
        assert ExportJsonSchemaVersion.V1_0 in versions

    def test_global_registry_instance_accessible(self):
        """Test global registry singleton is accessible and functional.

        AAA Pattern:
        - Arrange: Global schema_registry instance
        - Act: Get schema path from global instance
        - Assert: Instance is valid and path exists
        """
        # Act
        path = schema_registry.get_schema_path(ExportJsonSchemaVersion.V1_0)

        # Assert
        assert isinstance(schema_registry, SchemaRegistry)
        assert path.exists()

    def test_schema_file_contains_valid_json(self, registry):
        """Test schema file on disk can be parsed as valid JSON.

        AAA Pattern:
        - Arrange: Get schema file path
        - Act: Parse file as JSON
        - Assert: Result is a dictionary
        """
        # Arrange
        schema_path = registry.get_schema_path(ExportJsonSchemaVersion.V1_0)

        # Act
        with open(schema_path, encoding="utf-8") as f:
            data = json.load(f)

        # Assert
        assert isinstance(data, dict)

    @pytest.mark.parametrize(
        "definition_name",
        ["PackageMetrics", "CVEInfo"],
    )
    def test_schema_contains_required_definitions(self, v1_0_schema, definition_name):
        """Test schema contains expected model definitions in $defs.

        AAA Pattern:
        - Arrange: Load schema and parametrize definition names
        - Act: Extract definitions from schema
        - Assert: Required definition exists
        """
        # Act
        definitions = v1_0_schema["$defs"]

        # Assert
        assert definition_name in definitions
