"""Tests for export schema registry v1.7."""

import pytest

from ossiq.domain.common import ExportJsonSchemaVersion, ExportProfile
from ossiq.domain.packages_manager import PackageManagerCli
from ossiq.service.project.next_action import NEXT_ACTION_PRIORITY
from ossiq.ui.renderers.export.json_schema_registry import json_schema_registry
from tests.ui.renderers.export.test_json_schema_registry_base import SchemaRegistryBaseTest
from tests.ui.renderers.export.test_json_schema_registry_v1_6 import IDENTITY_KEYS, walk

TOP_LEVEL = [
    "metadata",
    "project",
    "summary",
    "production_packages",
    "development_packages",
    "transitive_packages",
]


class RuntimeContextChecks:
    """What 1.7 changed, asserted identically for both profiles."""

    def test_schema_version_const_is_1_7(self, schema):
        assert schema["properties"]["metadata"]["properties"]["schema_version"]["const"] == "1.7"

    def test_package_manager_lists_exactly_the_clis_we_drive(self, schema):
        """The enum is hand-written, so tie it to the enum the scan reports."""
        runtime_context = schema["properties"]["runtime_context"]["properties"]
        assert runtime_context["package_manager"]["enum"] == [*(cli.value for cli in PackageManagerCli), None]
        assert runtime_context["package_manager_version"]["type"] == ["string", "null"]

    def test_the_new_fields_are_optional(self, schema):
        assert not {"package_manager", "package_manager_version"} & set(
            schema["properties"]["runtime_context"].get("required", [])
        )

    def test_npm_cli_version_is_kept_but_deprecated(self, schema):
        npm_cli_version = schema["properties"]["runtime_context"]["properties"]["npm_cli_version"]
        assert npm_cli_version["type"] == ["string", "null"]
        assert npm_cli_version["description"].startswith("Deprecated since 1.7")


class TestSchemaRegistryV17(RuntimeContextChecks, SchemaRegistryBaseTest):
    version = ExportJsonSchemaVersion.V1_7
    schema_path_name = "export_schema_v1.7.json"
    schema_title = "OSS-IQ Export Schema v1.7"
    required_top_level_properties = [*TOP_LEVEL, "dependency_tree", "constraint_type_map"]
    required_definitions = ["PackageMetrics", "CVEInfo", "TransitivePackageMetrics"]
    included_versions = [ExportJsonSchemaVersion.V1_5, ExportJsonSchemaVersion.V1_6, ExportJsonSchemaVersion.V1_7]

    def test_get_latest_version_returns_v1_7(self, registry):
        assert registry.get_latest_version() == ExportJsonSchemaVersion.V1_7


class TestSchemaRegistryV17Standard(RuntimeContextChecks, SchemaRegistryBaseTest):
    version = ExportJsonSchemaVersion.V1_7
    profile = ExportProfile.STANDARD
    schema_path_name = "export_schema_v1.7_standard.json"
    schema_title = "OSS-IQ Export Schema v1.7 (standard profile)"
    required_top_level_properties = TOP_LEVEL
    required_definitions = ["PackageMetrics", "CVEInfo", "TransitivePackageMetrics"]
    included_versions = [ExportJsonSchemaVersion.V1_5, ExportJsonSchemaVersion.V1_6, ExportJsonSchemaVersion.V1_7]

    def test_profile_is_pinned_to_standard(self, schema):
        assert schema["properties"]["metadata"]["properties"]["profile"]["const"] == "standard"


@pytest.mark.parametrize("profile", [ExportProfile.FULL, ExportProfile.STANDARD], ids=["full", "standard"])
class TestV17IsAdditiveOverV16:
    """Released versions are never broken: every v1.6 document must still be a valid v1.7 document."""

    @pytest.fixture
    def pair(self, profile):
        old = json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_6, profile)
        new = json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_7, profile)
        return old, new

    def test_nothing_is_removed_or_retyped(self, pair):
        old, new = pair
        problems = []
        for path, value in walk(old):
            if path and path[-1] in IDENTITY_KEYS:
                continue
            if path == ("properties", "metadata", "properties", "schema_version", "const"):
                continue  # the version itself
            node = new
            try:
                for key in path:
                    node = node[key]
            except (KeyError, IndexError, TypeError):
                problems.append(f"missing: {'/'.join(map(str, path))}")
                continue
            if path and path[-1] == "enum":
                dropped = [allowed for allowed in value if allowed not in node]
                if dropped:
                    problems.append(f"enum lost values: {'/'.join(map(str, path))}: {dropped}")
            elif not isinstance(value, dict | list) and node != value:
                problems.append(f"changed: {'/'.join(map(str, path))}: {value!r} -> {node!r}")
        assert not problems, problems

    def test_nothing_new_is_required(self, pair):
        """A new required property would reject every existing document."""
        old, new = pair
        assert new["required"] == old["required"]
        for name, definition in old["$defs"].items():
            assert new["$defs"][name].get("required") == definition.get("required"), name
        old_context, new_context = (schema["properties"]["runtime_context"] for schema in pair)
        assert new_context.get("required") == old_context.get("required")

    def test_there_are_no_new_definitions(self, pair):
        old, new = pair
        assert set(new["$defs"]) == set(old["$defs"])

    def test_the_only_new_properties_are_the_package_manager_ones(self, pair):
        old, new = pair
        added = set(new["properties"]["runtime_context"]["properties"]) - set(
            old["properties"]["runtime_context"]["properties"]
        )
        assert added == {"package_manager", "package_manager_version"}


LABELS = [*NEXT_ACTION_PRIORITY, None]


@pytest.mark.parametrize("profile", [ExportProfile.FULL, ExportProfile.STANDARD], ids=["full", "standard"])
@pytest.mark.parametrize("definition", ["PackageMetrics", "TransitivePackageMetrics"])
def test_v1_7_lists_exactly_the_next_action_labels_the_scan_can_emit(profile, definition):
    schema = json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_7, profile)
    assert schema["$defs"][definition]["properties"]["next_action"]["enum"] == LABELS
