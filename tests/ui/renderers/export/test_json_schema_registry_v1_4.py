"""
Tests for export schema registry v1.4.

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
from ossiq.ui.renderers.export.json_schema_registry import SchemaRegistry


@pytest.fixture
def registry():
    """Create a SchemaRegistry instance for tests."""
    return SchemaRegistry()


@pytest.fixture
def v1_4_schema(registry):
    """Load v1.4 schema for tests."""
    return registry.load_schema(ExportJsonSchemaVersion.V1_4)


class TestSchemaRegistryV14:
    """Test suite for schema registry v1.4."""

    def test_get_schema_path_returns_valid_path_for_v1_4(self, registry):
        """Test getting schema path for v1.4 returns existing file.

        AAA Pattern:
        - Arrange: Registry fixture
        - Act: Get schema path for v1.4
        - Assert: Path is valid and file exists
        """
        # Act
        path = registry.get_schema_path(ExportJsonSchemaVersion.V1_4)

        # Assert
        assert isinstance(path, Path)
        assert path.name == "export_schema_v1.4.json"
        assert path.exists()

    def test_load_schema_returns_valid_json_schema(self, v1_4_schema):
        """Test loading v1.4 schema returns valid JSON schema structure.

        AAA Pattern:
        - Arrange: Load schema via fixture
        - Act: Schema is already loaded
        - Assert: Verify schema structure and metadata
        """
        # Assert
        assert isinstance(v1_4_schema, dict)
        assert v1_4_schema["$schema"] == "http://json-schema.org/draft-07/schema#"
        assert v1_4_schema["title"] == "OSS-IQ Export Schema v1.4"

    def test_schema_version_const_is_1_4(self, v1_4_schema):
        """Test metadata schema_version const value is 1.4.

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract schema_version const
        - Assert: Const is "1.4"
        """
        # Act
        schema_version_const = v1_4_schema["properties"]["metadata"]["properties"]["schema_version"]["const"]

        # Assert
        assert schema_version_const == "1.4"

    def test_schema_contains_is_prerelease_in_package_metrics(self, v1_4_schema):
        """Test PackageMetrics definition contains is_prerelease boolean field.

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract PackageMetrics properties
        - Assert: is_prerelease is a required boolean
        """
        # Act
        props = v1_4_schema["$defs"]["PackageMetrics"]["properties"]
        required = v1_4_schema["$defs"]["PackageMetrics"]["required"]

        # Assert
        assert "is_prerelease" in props
        assert props["is_prerelease"]["type"] == "boolean"
        assert "is_prerelease" in required

    def test_schema_contains_is_yanked_in_package_metrics(self, v1_4_schema):
        """Test PackageMetrics definition contains is_yanked boolean field.

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract PackageMetrics properties
        - Assert: is_yanked is a required boolean
        """
        # Act
        props = v1_4_schema["$defs"]["PackageMetrics"]["properties"]
        required = v1_4_schema["$defs"]["PackageMetrics"]["required"]

        # Assert
        assert "is_yanked" in props
        assert props["is_yanked"]["type"] == "boolean"
        assert "is_yanked" in required

    def test_schema_contains_is_prerelease_in_transitive_package_metrics(self, v1_4_schema):
        """Test TransitivePackageMetrics definition contains is_prerelease boolean field.

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract TransitivePackageMetrics properties
        - Assert: is_prerelease is a required boolean
        """
        # Act
        props = v1_4_schema["$defs"]["TransitivePackageMetrics"]["properties"]
        required = v1_4_schema["$defs"]["TransitivePackageMetrics"]["required"]

        # Assert
        assert "is_prerelease" in props
        assert props["is_prerelease"]["type"] == "boolean"
        assert "is_prerelease" in required

    def test_schema_contains_is_yanked_in_transitive_package_metrics(self, v1_4_schema):
        """Test TransitivePackageMetrics definition contains is_yanked boolean field.

        AAA Pattern:
        - Arrange: Load schema
        - Act: Extract TransitivePackageMetrics properties
        - Assert: is_yanked is a required boolean
        """
        # Act
        props = v1_4_schema["$defs"]["TransitivePackageMetrics"]["properties"]
        required = v1_4_schema["$defs"]["TransitivePackageMetrics"]["required"]

        # Assert
        assert "is_yanked" in props
        assert props["is_yanked"]["type"] == "boolean"
        assert "is_yanked" in required

    def test_get_latest_version_returns_v1_4(self, registry):
        """Test registry returns v1.4 as the latest schema version.

        AAA Pattern:
        - Arrange: Registry fixture
        - Act: Get latest version
        - Assert: Version is v1.4
        """
        # Act
        latest = registry.get_latest_version()

        # Assert
        assert latest == ExportJsonSchemaVersion.V1_4

    def test_list_versions_includes_all_five_versions(self, registry):
        """Test listing all registered versions includes v1.0 through v1.4.

        AAA Pattern:
        - Arrange: Registry fixture
        - Act: List all versions
        - Assert: All five versions are present
        """
        # Act
        versions = registry.list_versions()

        # Assert
        assert ExportJsonSchemaVersion.V1_0 in versions
        assert ExportJsonSchemaVersion.V1_1 in versions
        assert ExportJsonSchemaVersion.V1_2 in versions
        assert ExportJsonSchemaVersion.V1_3 in versions
        assert ExportJsonSchemaVersion.V1_4 in versions

    def test_schema_file_contains_valid_json(self, registry):
        """Test schema file on disk can be parsed as valid JSON.

        AAA Pattern:
        - Arrange: Get schema file path
        - Act: Parse file as JSON
        - Assert: Result is a dictionary
        """
        # Arrange
        schema_path = registry.get_schema_path(ExportJsonSchemaVersion.V1_4)

        # Act
        with open(schema_path, encoding="utf-8") as f:
            data = json.load(f)

        # Assert
        assert isinstance(data, dict)

    def test_v1_3_schema_still_registered(self, registry):
        """Test v1.3 schema is still registered (regression guard).

        AAA Pattern:
        - Arrange: Registry fixture
        - Act: Get schema path for v1.3
        - Assert: Path exists (v1.3 not removed)
        """
        # Act
        path = registry.get_schema_path(ExportJsonSchemaVersion.V1_3)

        # Assert
        assert path.exists()

    @pytest.mark.parametrize(
        "definition_name",
        ["PackageMetrics", "CVEInfo", "DependencyTreeRoot", "DependencyTreeNode", "TransitivePackageMetrics"],
    )
    def test_schema_contains_required_definitions(self, v1_4_schema, definition_name):
        """Test schema contains all expected model definitions in $defs.

        AAA Pattern:
        - Arrange: Load schema and parametrize definition names
        - Act: Extract definitions from schema
        - Assert: Required definition exists
        """
        # Act
        definitions = v1_4_schema["$defs"]

        # Assert
        assert definition_name in definitions
