"""Tests for pnpm/overrides.py: pnpm's flat override keys read as npm override rules."""

import pytest

from ossiq.adapters.package_managers.npm.overrides import OverrideRule
from ossiq.adapters.package_managers.pnpm.overrides import parse_pnpm_override_rules


class TestParsePnpmOverrideRules:
    @pytest.mark.parametrize(
        "overrides, expected",
        [
            ({"foo": "1.0.0"}, [OverrideRule("foo", "1.0.0", None, (), "foo")]),
            ({"foo@^2": "2.5.0"}, [OverrideRule("foo", "2.5.0", "^2", (), "foo@^2")]),
            ({"@s/foo@<3": "2.0.0"}, [OverrideRule("@s/foo", "2.0.0", "<3", (), "@s/foo@<3")]),
            ({"qar@1>zoo": "2.1.3"}, [OverrideRule("zoo", "2.1.3", None, ("qar",), "qar@1>zoo")]),
            ({"@s/qar>zoo@^1": "1.2.0"}, [OverrideRule("zoo", "1.2.0", "^1", ("@s/qar",), "@s/qar>zoo@^1")]),
            # A `>` right after `@`, `|` or a space belongs to a range, not to a parent selector.
            ({"foo@>1": "2.0.0"}, [OverrideRule("foo", "2.0.0", ">1", (), "foo@>1")]),
            ({"foo@^1 || >2": "2.0.0"}, [OverrideRule("foo", "2.0.0", "^1 || >2", (), "foo@^1 || >2")]),
        ],
    )
    def test_key_forms(self, overrides, expected):
        assert parse_pnpm_override_rules(overrides) == expected

    @pytest.mark.parametrize("overrides", [None, [], "foo", {"foo": {"bar": "1"}}, {"foo": None}, {1: "2.0.0"}])
    def test_anything_but_string_rules_yields_nothing(self, overrides):
        assert parse_pnpm_override_rules(overrides) == []

    def test_rules_keep_document_order(self):
        rules = parse_pnpm_override_rules({"b": "1", "a": "2", "c@1>d": "3"})

        assert [rule.raw_key for rule in rules] == ["b", "a", "c@1>d"]
