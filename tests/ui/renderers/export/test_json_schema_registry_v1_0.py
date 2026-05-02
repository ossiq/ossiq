"""Tests for export schema registry v1.0."""

from ossiq.domain.common import ExportJsonSchemaVersion
from tests.ui.renderers.export.test_json_schema_registry_base import SchemaRegistryBaseTest


class TestSchemaRegistryV10(SchemaRegistryBaseTest):
    version = ExportJsonSchemaVersion.V1_0
    schema_path_name = "export_schema_v1.0.json"
    schema_title = "OSS-IQ Export Schema v1.0"
    required_top_level_properties = [
        "metadata",
        "project",
        "summary",
        "production_packages",
        "development_packages",
    ]
    required_definitions = ["PackageMetrics", "CVEInfo"]
    included_versions = [ExportJsonSchemaVersion.V1_0]
