"""Tests for export schema registry v1.5."""

import typing

import pytest

from ossiq.domain.common import ExportJsonSchemaVersion, ExportProfile
from ossiq.ui.renderers.export import models as export_models
from ossiq.ui.renderers.export.json_schema_registry import json_schema_registry
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
        "StrategySelectionExport",
    ]
    included_versions = [
        ExportJsonSchemaVersion.V1_5,
    ]

    def test_schema_version_const_is_1_5(self, schema):
        const = schema["properties"]["metadata"]["properties"]["schema_version"]["const"]
        assert const == "1.5"

    def test_update_transitive_impacts_export_defined(self, schema):
        assert "TransitiveImpactExport" in schema["$defs"]

    def test_strategy_is_a_nested_object_not_flattened_fields(self, schema):
        props = schema["$defs"]["PackageMetrics"]["properties"]
        assert not [key for key in props if key.startswith("strategy_")]
        assert props["strategy"]["oneOf"][0]["$ref"] == "#/$defs/StrategySelectionExport"

    def _assert_ladder_fields_on(self, defs, definition_name):
        """Both metrics models inherit the ladder rungs from one mixin, so their descriptions
        must be identical — they had already drifted ("Absent when" vs "Null only when")."""
        props = defs[definition_name]["properties"]
        for field in (
            "latest_in_range",
            "latest_in_major",
            "latest_compatible_major",
            "latest_preserving_module_system",
        ):
            assert props[field]["type"] == ["string", "null"]
            assert "Null only when undeterminable" in props[field]["description"]

    def test_package_metrics_has_ladder_fields(self, schema):
        self._assert_ladder_fields_on(schema["$defs"], "PackageMetrics")

    def test_transitive_package_metrics_has_ladder_fields(self, schema):
        self._assert_ladder_fields_on(schema["$defs"], "TransitivePackageMetrics")

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


class TestSchemaRegistryV15Standard(SchemaRegistryBaseTest):
    version = ExportJsonSchemaVersion.V1_5
    profile = ExportProfile.STANDARD
    schema_path_name = "export_schema_v1.5_standard.json"
    schema_title = "OSS-IQ Export Schema v1.5 (standard profile)"
    required_top_level_properties = [
        "metadata",
        "project",
        "summary",
        "production_packages",
        "development_packages",
        "transitive_packages",
    ]
    required_definitions = ["PackageMetrics", "CVEInfo", "TransitivePackageMetrics", "StrategySelectionExport"]
    included_versions = [ExportJsonSchemaVersion.V1_5]

    def test_profile_is_pinned_to_standard(self, schema):
        metadata = schema["properties"]["metadata"]
        assert metadata["properties"]["profile"]["const"] == "standard"
        assert "profile" in metadata["required"]

    def test_the_tree_is_not_part_of_the_standard_profile(self, schema):
        assert "dependency_tree" not in schema["properties"]
        assert "DependencyTreeRoot" not in schema["$defs"]


# Every place the standard schema is a projection of the full one: (JSON pointer path, model).
PROJECTIONS = [
    ((), export_models.ExportData),
    (("properties", "metadata", "properties", "data_completeness"), export_models.DataCompletenessExport),
    (("$defs", "PackageMetrics"), export_models.PackageMetrics),
    (("$defs", "TransitivePackageMetrics"), export_models.TransitivePackageMetrics),
    (("$defs", "CVEInfo"), export_models.CVEInfo),
    (("$defs", "StrategySelectionExport"), export_models.StrategySelectionExport),
]


def at(schema: dict, path: tuple[str, ...]) -> dict:
    for key in path:
        schema = schema[key]
    return schema


@pytest.mark.parametrize(("path", "model"), PROJECTIONS, ids=[model.__name__ for _, model in PROJECTIONS])
class TestStandardSchemaIsAProjectionOfFull:
    """Two hand-maintained schemas stay cheap only while they cannot drift: the standard one must be
    the full one minus exactly the fields the Pydantic models tag FULL_ONLY."""

    @pytest.fixture
    def pair(self, path, model):
        full = at(json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5, ExportProfile.FULL), path)
        standard = at(json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5, ExportProfile.STANDARD), path)
        return full, standard

    def test_properties_are_full_minus_the_full_only_fields(self, pair, model):
        full, standard = pair
        assert set(standard["properties"]) == set(full["properties"]) - export_models.full_only_fields(model)

    def test_shared_properties_are_identical(self, pair, model):
        full, standard = pair
        # metadata differs on purpose: its profile is pinned and its data_completeness projected.
        shared = set(standard["properties"]) - {"metadata"}
        assert {k: standard["properties"][k] for k in shared} == {k: full["properties"][k] for k in shared}

    def test_required_is_full_minus_the_full_only_fields(self, pair, model):
        full, standard = pair
        full_only = export_models.full_only_fields(model)
        assert standard.get("required", []) == [name for name in full.get("required", []) if name not in full_only]

    def test_rejects_unknown_properties(self, pair, model):
        _, standard = pair
        assert standard["additionalProperties"] is False

    def test_every_required_field_is_always_emitted(self, pair, model):
        """The standard dump drops optional nulls and empties; a field it requires must never be one."""
        _, standard = pair
        if not (model.omit_empty_in_standard or model.omit_empty_always):
            return  # drops nothing but its FULL_ONLY fields, so everything else is always there
        for name in standard.get("required", []):
            field = model.model_fields[name]
            nullable = type(None) in typing.get_args(field.annotation)
            # omit_empty_always drops a null even from a required field, so there it must not be nullable
            always_emitted = field.annotation is bool or (
                field.is_required() and not (model.omit_empty_always and nullable)
            )
            assert always_emitted, name
