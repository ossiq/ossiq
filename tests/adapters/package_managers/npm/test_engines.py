# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for npm/engines.py: node engine ranges and the floors a manifest declares.
"""

import pytest

from ossiq.adapters.package_managers.npm.engines import declared_engine_floors, extract_min_node_version


# ============================================================================
# Test extract_min_node_version helper
# ============================================================================
class TestExtractMinNodeVersion:
    """Test suite for the extract_min_node_version module-level helper."""

    @pytest.mark.parametrize(
        "node_range,expected",
        [
            (">=18.0.0", "18.0.0"),
            ("^18", "18.0.0"),
            ("~18.4", "18.4.0"),
            ("18 || 20", "18.0.0"),
            (">=18.0.0 <20.0.0", "18.0.0"),
            ("18.x", "18.0.0"),
            (">=14.x", "14.0.0"),
            (">= 18.x", "18.0.0"),
            (">14.x", "15.0.0"),
            ("16.0.0 - 18.0.0", "16.0.0"),
            (">= 18", "18.0.0"),
            (">=14.17", "14.17.0"),
            ("v18.0.0", "18.0.0"),
            ("<20", None),
            ("*", None),
            ("!=19", None),
            # An exclusive floor names a version the range itself excludes, so there is no
            # concrete minimum to report — extract_min_python_version refuses ">" for the
            # same reason. Returning "18.0.0" here made 18.0.0 look admitted when it isn't.
            (">18.0.0", None),
            # ">18" is an X-range, not an exclusive bound: npm reads it as ">=19.0.0".
            (">18", "19.0.0"),
            # A branch with no floor means the range has none.
            ("<16 || >=18", None),
            ("^14.x", "14.0.0"),
            (">=18.0.0 || >19.0.0", "18.0.0"),
            ("14.17.1", "14.17.1"),
            ("14", "14.0.0"),
            ("not-a-version", None),
            ("", None),
        ],
    )
    def test_extract_min_node_version(self, node_range: str, expected: str | None) -> None:
        assert extract_min_node_version(node_range) == expected


class TestDeclaredEngineFloors:
    """The declared fallback carried only `node`, so the --no-probe-runtime path had no npm floor
    to check an `engines.npm` requirement against even once the matcher could evaluate one."""

    def test_node_and_npm_floors_are_both_carried(self):
        floors = declared_engine_floors({"node": ">=18.0.0", "npm": ">=9.0.0"})

        assert floors == {"node": "18.0.0", "npm": "9.0.0"}

    def test_the_npm_floor_is_parsed_as_an_npm_range(self):
        assert declared_engine_floors({"npm": "^8.6.0"}) == {"npm": "8.6.0"}

    def test_unevaluable_package_managers_are_not_carried(self):
        """pnpm/yarn have no adapter and no probe, so a declared floor for one would be checked
        only on the declared path — worse than not checking it at all."""
        assert declared_engine_floors({"pnpm": "^8.6.0", "yarn": "~4.1"}) is None

    def test_a_range_with_no_nameable_floor_is_dropped_not_guessed(self):
        assert declared_engine_floors({"node": ">=18.0.0", "npm": "*"}) == {"node": "18.0.0"}

    def test_non_string_and_absent_engines_are_ignored(self):
        assert declared_engine_floors({"node": {"nested": "junk"}}) is None
        assert declared_engine_floors({}) is None
        assert declared_engine_floors(None) is None

    def test_unknown_engine_keys_are_not_carried(self):
        """Only keys the matcher can actually evaluate; a floor nothing checks is noise."""
        assert declared_engine_floors({"bun": ">=1.0.0", "node": ">=18.0.0"}) == {"node": "18.0.0"}
