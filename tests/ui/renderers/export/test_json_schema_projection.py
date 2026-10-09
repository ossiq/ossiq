"""The standard schema is a projection of the full one, for every registered schema version."""

import typing

import pytest

from ossiq.domain.common import ExportJsonSchemaVersion, ExportProfile
from ossiq.ui.renderers.export import models as export_models
from ossiq.ui.renderers.export.json_schema_registry import json_schema_registry

# Every place the standard schema is a projection of the full one: (JSON pointer path, model).
PROJECTIONS = [
    ((), export_models.ExportData),
    (("properties", "metadata", "properties", "data_completeness"), export_models.DataCompletenessExport),
    (("$defs", "PackageMetrics"), export_models.PackageMetrics),
    (("$defs", "TransitivePackageMetrics"), export_models.TransitivePackageMetrics),
    (("$defs", "CVEInfo"), export_models.CVEInfo),
    (("$defs", "StrategySelectionExport"), export_models.StrategySelectionExport),
]

VERSIONS = [ExportJsonSchemaVersion.V1_5, ExportJsonSchemaVersion.V1_6]


def at(schema: dict, path: tuple[str, ...]) -> dict:
    for key in path:
        schema = schema[key]
    return schema


def test_every_registered_version_is_checked():
    """A new version added to the registry but not to VERSIONS would skip the whole projection check."""
    assert set(VERSIONS) == set(json_schema_registry.list_versions())


@pytest.mark.parametrize("version", VERSIONS, ids=[version.value for version in VERSIONS])
@pytest.mark.parametrize(("path", "model"), PROJECTIONS, ids=[model.__name__ for _, model in PROJECTIONS])
class TestStandardSchemaIsAProjectionOfFull:
    """Two hand-maintained schemas stay cheap only while they cannot drift: the standard one must be
    the full one minus exactly the fields the Pydantic models tag FULL_ONLY."""

    @pytest.fixture
    def pair(self, version, path, model):
        full = at(json_schema_registry.load_schema(version, ExportProfile.FULL), path)
        standard = at(json_schema_registry.load_schema(version, ExportProfile.STANDARD), path)
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
