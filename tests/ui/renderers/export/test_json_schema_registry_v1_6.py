"""Tests for export schema registry v1.6."""

import pytest

from ossiq.domain.common import ExportJsonSchemaVersion, ExportProfile
from ossiq.service.project.next_action import NEXT_ACTION_PRIORITY
from ossiq.ui.renderers.export.json_schema_registry import json_schema_registry
from tests.ui.renderers.export.test_json_schema_registry_base import SchemaRegistryBaseTest

NEW_DEFINITIONS = {"UnresolvedPeerExport", "PeerRepairExport", "PeerRepairMoveExport"}


class TestSchemaRegistryV16(SchemaRegistryBaseTest):
    version = ExportJsonSchemaVersion.V1_6
    schema_path_name = "export_schema_v1.6.json"
    schema_title = "OSS-IQ Export Schema v1.6"
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
    required_definitions = ["PackageMetrics", "CVEInfo", "TransitivePackageMetrics", *NEW_DEFINITIONS]
    included_versions = [ExportJsonSchemaVersion.V1_5, ExportJsonSchemaVersion.V1_6]

    def test_get_latest_version_returns_v1_6(self, registry):
        assert registry.get_latest_version() == ExportJsonSchemaVersion.V1_6

    def test_schema_version_const_is_1_6(self, schema):
        assert schema["properties"]["metadata"]["properties"]["schema_version"]["const"] == "1.6"

    @pytest.mark.parametrize("definition", ["PackageMetrics", "TransitivePackageMetrics"])
    def test_package_metrics_carry_unresolved_peers(self, schema, definition):
        props = schema["$defs"][definition]
        assert props["properties"]["unresolved_peers"]["items"] == {"$ref": "#/$defs/UnresolvedPeerExport"}
        assert "unresolved_peers" not in props["required"]

    def test_the_two_metrics_describe_unresolved_peers_identically(self, schema):
        """They inherit one mixin, so a description that differs means one of them was hand-edited."""
        direct = schema["$defs"]["PackageMetrics"]["properties"]["unresolved_peers"]
        transitive = schema["$defs"]["TransitivePackageMetrics"]["properties"]["unresolved_peers"]
        assert direct == transitive

    def test_unresolved_peer_shape(self, schema):
        peer = schema["$defs"]["UnresolvedPeerExport"]
        assert peer["required"] == ["package_name", "spec", "optional"]
        assert peer["properties"]["optional"]["type"] == "boolean"
        assert peer["properties"]["installed_elsewhere"]["items"] == {"type": "string"}

    def test_peer_repairs_are_a_root_list_that_is_not_required(self, schema):
        assert schema["properties"]["peer_repairs"]["items"] == {"$ref": "#/$defs/PeerRepairExport"}
        assert "peer_repairs" not in schema["required"]

    def test_peer_repair_shape(self, schema):
        repair = schema["$defs"]["PeerRepairExport"]
        assert repair["required"] == ["package_name", "suggested_constraint", "is_dev_dependency", "requirers"]
        assert repair["properties"]["family_moves"]["items"] == {"$ref": "#/$defs/PeerRepairMoveExport"}
        assert schema["$defs"]["PeerRepairMoveExport"]["required"] == [
            "package_name",
            "current_version",
            "projected_version",
        ]

    def test_the_strategy_verdict_carries_the_widening_authorization(self, schema):
        verdict = schema["$defs"]["StrategySelectionExport"]
        assert verdict["properties"]["widening_authorized"]["type"] == "boolean"
        assert "widening_authorized" not in verdict.get("required", [])


class TestSchemaRegistryV16Standard(SchemaRegistryBaseTest):
    version = ExportJsonSchemaVersion.V1_6
    profile = ExportProfile.STANDARD
    schema_path_name = "export_schema_v1.6_standard.json"
    schema_title = "OSS-IQ Export Schema v1.6 (standard profile)"
    required_top_level_properties = [
        "metadata",
        "project",
        "summary",
        "production_packages",
        "development_packages",
        "transitive_packages",
    ]
    required_definitions = ["PackageMetrics", "CVEInfo", "TransitivePackageMetrics", *NEW_DEFINITIONS]
    included_versions = [ExportJsonSchemaVersion.V1_5, ExportJsonSchemaVersion.V1_6]

    def test_profile_is_pinned_to_standard(self, schema):
        assert schema["properties"]["metadata"]["properties"]["profile"]["const"] == "standard"

    def test_peers_are_decision_data_so_the_standard_profile_keeps_them(self, schema):
        assert "unresolved_peers" in schema["$defs"]["PackageMetrics"]["properties"]
        assert "unresolved_peers" in schema["$defs"]["TransitivePackageMetrics"]["properties"]
        assert "peer_repairs" in schema["properties"]

    def test_the_widening_authorization_is_decision_data_so_the_standard_profile_keeps_it(self, schema):
        """The standard schema rejects any property it doesn't list, so a missing entry fails every document."""
        assert "widening_authorized" in schema["$defs"]["StrategySelectionExport"]["properties"]


def walk(node, path=()):
    """Every (path, value) pair of a decoded JSON document."""
    yield path, node
    if path and path[-1] == "enum":
        return  # a set of allowed values, compared as one by the caller, not index by index
    if isinstance(node, dict):
        for key, value in node.items():
            yield from walk(value, (*path, key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk(value, (*path, index))


# What a new version is allowed to change about an old one: its identity and its prose.
IDENTITY_KEYS = {"$id", "title", "description"}


@pytest.mark.parametrize("profile", [ExportProfile.FULL, ExportProfile.STANDARD], ids=["full", "standard"])
class TestV16IsAdditiveOverV15:
    """Released versions are never broken: every v1.5 document must still be a valid v1.6 document."""

    @pytest.fixture
    def pair(self, profile):
        old = json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5, profile)
        new = json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_6, profile)
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

    def test_the_only_new_definitions_are_the_peer_ones(self, pair):
        old, new = pair
        assert set(new["$defs"]) - set(old["$defs"]) == NEW_DEFINITIONS


LABELS = [*NEXT_ACTION_PRIORITY, None]


@pytest.mark.parametrize("profile", [ExportProfile.FULL, ExportProfile.STANDARD], ids=["full", "standard"])
@pytest.mark.parametrize("definition", ["PackageMetrics", "TransitivePackageMetrics"])
class TestNextActionEnumMatchesTheEmitter:
    """The enum is hand-written, so it drifts: 'Wait for cooldown' shipped in the emitter and was never
    added to v1.5's, which made any document with a package inside its cooldown fail its own schema."""

    def test_v1_6_lists_exactly_the_labels_the_scan_can_emit(self, profile, definition):
        schema = json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_6, profile)
        assert schema["$defs"][definition]["properties"]["next_action"]["enum"] == LABELS

    @pytest.mark.xfail(
        strict=True,
        reason="v1.5 shipped (0.1.11 onwards) without 'Wait for cooldown'; a released schema is not amended. "
        "If it is fixed in place, drop this marker.",
    )
    def test_v1_5_lists_them_too(self, profile, definition):
        schema = json_schema_registry.load_schema(ExportJsonSchemaVersion.V1_5, profile)
        assert schema["$defs"][definition]["properties"]["next_action"]["enum"] == LABELS
