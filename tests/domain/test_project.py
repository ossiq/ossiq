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
