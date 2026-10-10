"""
Tests for ConstraintSource in domain/project.py.
"""

from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource


class TestConstraintSourceIsOssiqAuthored:
    """Unit tests for ConstraintSource.is_ossiq_authored."""

    def test_defaults_to_false(self):
        source = ConstraintSource(type=ConstraintType.OVERRIDE, source_file="package.json")
        assert source.is_ossiq_authored is False

    def test_explicit_construction_round_trips(self):
        source = ConstraintSource(
            type=ConstraintType.OVERRIDE,
            source_file="package.json",
            scope_path=["foo", "bar"],
            is_ossiq_authored=True,
        )
        assert source.is_ossiq_authored is True
        assert source.type == ConstraintType.OVERRIDE
        assert source.source_file == "package.json"
        assert source.scope_path == ["foo", "bar"]


class TestConstraintSourceIsUserOverride:
    """ConstraintSource.is_user_override: an override someone other than OSS IQ is responsible for."""

    def test_an_override_the_user_wrote_is_one(self):
        source = ConstraintSource(type=ConstraintType.OVERRIDE, source_file="package.json")
        assert source.is_user_override is True

    def test_an_override_ossiq_wrote_is_not(self):
        source = ConstraintSource(type=ConstraintType.OVERRIDE, source_file="package.json", is_ossiq_authored=True)
        assert source.is_user_override is False

    def test_any_other_constraint_is_not(self):
        for constraint_type in (
            ConstraintType.DECLARED,
            ConstraintType.NARROWED,
            ConstraintType.PINNED,
            ConstraintType.ADDITIVE,
        ):
            assert ConstraintSource(type=constraint_type, source_file="package.json").is_user_override is False
