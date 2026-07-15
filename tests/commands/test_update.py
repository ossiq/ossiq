"""Tests for update command and NPM adapter helper methods."""

from __future__ import annotations

import pytest
import typer

from ossiq.commands.plan import (
    CommandPlanOptions,
    check_override_ignore_conflict,
    parse_override_specs,
)


class TestCommandUpdatePinWiring:
    def test_pin_all_true_passed_to_options(self) -> None:
        options = CommandPlanOptions(project_path="/some/path", pin_all=True)
        assert options.pin_all is True

    def test_pin_all_false_by_default(self) -> None:
        options = CommandPlanOptions(project_path="/some/path")
        assert options.pin_all is False


class TestParseOverrideSpecs:
    def test_simple_spec_parsed(self) -> None:
        assert parse_override_specs(["lodash==4.17.21"]) == (("lodash", "4.17.21"),)

    def test_scoped_npm_name_parsed(self) -> None:
        assert parse_override_specs(["@scope/pkg==1.2.3"]) == (("@scope/pkg", "1.2.3"),)

    def test_none_returns_empty(self) -> None:
        assert parse_override_specs(None) == ()

    def test_missing_separator_rejected(self) -> None:
        with pytest.raises(typer.BadParameter):
            parse_override_specs(["lodash@4.17.21"])

    def test_empty_version_rejected(self) -> None:
        with pytest.raises(typer.BadParameter):
            parse_override_specs(["lodash=="])

    def test_empty_name_rejected(self) -> None:
        with pytest.raises(typer.BadParameter):
            parse_override_specs(["==1.2.3"])

    def test_duplicate_same_version_deduped(self) -> None:
        assert parse_override_specs(["lodash==4.17.21", "lodash==4.17.21"]) == (("lodash", "4.17.21"),)

    def test_duplicate_conflicting_versions_rejected(self) -> None:
        with pytest.raises(typer.BadParameter):
            parse_override_specs(["lodash==4.17.21", "lodash==4.17.20"])


class TestCheckOverrideIgnoreConflict:
    def test_disjoint_sets_pass(self) -> None:
        check_override_ignore_conflict((("lodash", "4.17.21"),), ("express",))

    def test_conflicting_package_rejected(self) -> None:
        with pytest.raises(typer.BadParameter):
            check_override_ignore_conflict((("lodash", "4.17.21"),), ("lodash",))
