"""Tests for export schema registry v1.5."""

from ossiq.domain.common import ExportJsonSchemaVersion
from tests.ui.renderers.export.test_json_schema_registry_base import SchemaRegistryBaseTest


class TestSchemaRegistryV15(SchemaRegistryBaseTest):
    version = ExportJsonSchemaVersion.V1_5
    schema_path_name = "export_schema_v1.5.json"
    schema_title = "OSS-IQ Export Schema v1.5"
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
        "GateInfo",
    ]
    included_versions = [
        ExportJsonSchemaVersion.V1_0,
        ExportJsonSchemaVersion.V1_1,
        ExportJsonSchemaVersion.V1_2,
        ExportJsonSchemaVersion.V1_3,
        ExportJsonSchemaVersion.V1_4,
        ExportJsonSchemaVersion.V1_5,
    ]

    def test_schema_version_const_is_1_5(self, schema):
        const = schema["properties"]["metadata"]["properties"]["schema_version"]["const"]
        assert const == "1.5"

    def test_gate_info_has_status_and_reason(self, schema):
        gate_info = schema["$defs"]["GateInfo"]
        assert gate_info["required"] == ["status", "reason"]
        assert gate_info["properties"]["status"]["enum"] == ["pass", "quarantine", "block"]
        assert gate_info["properties"]["reason"]["type"] == "string"

    def test_update_transitive_impacts_export_defined(self, schema):
        assert "TransitiveImpactExport" in schema["$defs"]

    def test_v1_4_schema_still_registered(self, registry):
        path = registry.get_schema_path(ExportJsonSchemaVersion.V1_4)
        assert path.exists()

    def _assert_health_fields_on(self, defs, definition_name):
        props = defs[definition_name]["properties"]
        assert props["exposure_window_days"]["type"] == ["number", "null"]
        assert props["p_vuln"]["type"] == ["number", "null"]
        assert props["p_supplychain"]["type"] == ["number", "null"]
        assert props["impact"]["type"] == ["number", "null"]
        assert props["expected_exposure"]["type"] == ["number", "null"]
        assert props["fitness"]["type"] == ["integer", "null"]
        assert props["fitness"]["minimum"] == 0
        assert props["fitness"]["maximum"] == 100
        assert props["gate"]["anyOf"] == [{"$ref": "#/$defs/GateInfo"}, {"type": "null"}]

    def test_package_metrics_has_health_score_fields(self, schema):
        self._assert_health_fields_on(schema["$defs"], "PackageMetrics")

    def test_transitive_package_metrics_has_health_score_fields(self, schema):
        self._assert_health_fields_on(schema["$defs"], "TransitivePackageMetrics")
