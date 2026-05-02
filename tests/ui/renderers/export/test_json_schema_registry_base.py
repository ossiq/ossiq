"""
Base test class for JSON schema registry tests.

Subclasses set class-level attributes (version, schema_path_name, etc.) and
inherit all shared infrastructure tests. Version-specific assertions live only
in the version files.
"""

import json
from pathlib import Path

import pytest

from ossiq.domain.common import ExportJsonSchemaVersion
from ossiq.ui.renderers.export.json_schema_registry import SchemaRegistry, json_schema_registry


class SchemaRegistryBaseTest:
    """Shared tests for all schema versions. Not collected directly by pytest."""

    version: ExportJsonSchemaVersion
    schema_path_name: str
    schema_title: str
    required_top_level_properties: list
    required_definitions: list = ["PackageMetrics", "CVEInfo"]
    included_versions: list

    @pytest.fixture
    def registry(self):
        return SchemaRegistry()

    @pytest.fixture
    def schema(self, registry):
        return registry.load_schema(self.version)

    def test_get_schema_path_returns_valid_path(self, registry):
        path = registry.get_schema_path(self.version)
        assert isinstance(path, Path)
        assert path.name == self.schema_path_name
        assert path.exists()

    def test_load_schema_returns_valid_json_schema(self, schema):
        assert isinstance(schema, dict)
        assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"
        assert schema["title"] == self.schema_title

    def test_schema_has_required_top_level_fields(self, schema):
        assert "properties" in schema
        assert "required" in schema

    def test_schema_contains_required_properties(self, schema):
        properties = schema["properties"]
        for prop in self.required_top_level_properties:
            assert prop in properties, f"Missing required property: {prop}"

    def test_schema_contains_required_definitions(self, schema):
        definitions = schema["$defs"]
        for definition in self.required_definitions:
            assert definition in definitions, f"Missing definition: {definition}"

    def test_get_latest_version_returns_v1_4(self, registry):
        assert registry.get_latest_version() == ExportJsonSchemaVersion.V1_4

    def test_list_versions_includes_required_versions(self, registry):
        versions = registry.list_versions()
        for v in self.included_versions:
            assert v in versions, f"Missing version in registry: {v}"

    def test_schema_file_contains_valid_json(self, registry):
        schema_path = registry.get_schema_path(self.version)
        with open(schema_path, encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data, dict)

    def test_global_registry_instance_accessible(self):
        path = json_schema_registry.get_schema_path(self.version)
        assert isinstance(json_schema_registry, SchemaRegistry)
        assert path.exists()
