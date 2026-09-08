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
    ]
    included_versions = [
        ExportJsonSchemaVersion.V1_5,
    ]

    def test_schema_version_const_is_1_5(self, schema):
        const = schema["properties"]["metadata"]["properties"]["schema_version"]["const"]
        assert const == "1.5"

    def test_update_transitive_impacts_export_defined(self, schema):
        assert "TransitiveImpactExport" in schema["$defs"]

    def _assert_epss_fields_on(self, defs, definition_name):
        props = defs[definition_name]["properties"]
        assert props["epss"]["type"] == ["number", "null"]
        assert props["runs_code_at_install"]["type"] == ["boolean", "null"]
        assert props["install_execution_reason"]["type"] == ["string", "null"]

    def test_package_metrics_has_epss_fields(self, schema):
        self._assert_epss_fields_on(schema["$defs"], "PackageMetrics")

    def test_transitive_package_metrics_has_epss_fields(self, schema):
        self._assert_epss_fields_on(schema["$defs"], "TransitivePackageMetrics")

    def test_cve_info_has_epss_and_fix_age_days(self, schema):
        props = schema["$defs"]["CVEInfo"]["properties"]
        assert props["epss"]["type"] == ["number", "null"]
        assert props["fix_age_days"]["type"] == ["integer", "null"]

    def _assert_engagement_buckets_on(self, defs, definition_name):
        prop = defs[definition_name]["properties"]["engagement_buckets"]
        assert prop["type"] == ["array", "null"]
        assert prop["items"]["items"]["type"] == "integer"
        assert prop["items"]["minItems"] == prop["items"]["maxItems"] == 4

    def test_package_metrics_has_engagement_buckets(self, schema):
        self._assert_engagement_buckets_on(schema["$defs"], "PackageMetrics")

    def test_transitive_package_metrics_has_engagement_buckets(self, schema):
        self._assert_engagement_buckets_on(schema["$defs"], "TransitivePackageMetrics")

    def test_summary_has_project_epss_fields(self, schema):
        props = schema["properties"]["summary"]["properties"]
        assert props["project_epss"]["type"] == ["number", "null"]
        assert props["packages_with_epss"]["type"] == "integer"
        assert props["packages_with_unscored_cves"]["type"] == "integer"
