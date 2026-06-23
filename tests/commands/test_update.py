"""Tests for update command and NPM adapter helper methods."""

from __future__ import annotations

import pytest
import typer

from ossiq.commands.plan import (
    CommandPlanOptions,
    build_npm_apply_args,
    check_override_ignore_conflict,
    npm_cli_extra_args,
    parse_override_specs,
)
from ossiq.service.update import UpdatePlan


class TestCommandUpdatePinWiring:
    def test_pin_all_true_passed_to_options(self) -> None:
        options = CommandPlanOptions(project_path="/some/path", pin_all=True)
        assert options.pin_all is True

    def test_pin_all_false_by_default(self) -> None:
        options = CommandPlanOptions(project_path="/some/path")
        assert options.pin_all is False


class TestBuildNpmApplyArgs:
    def test_base_always_includes_registry_type(self) -> None:
        options = CommandPlanOptions(project_path="/p")
        assert "--registry-type npm" in build_npm_apply_args(options)

    def test_pin_all_flag_included_when_set(self) -> None:
        options = CommandPlanOptions(project_path="/p", pin_all=True)
        assert "--pin-all" in build_npm_apply_args(options)

    def test_pin_all_flag_absent_when_not_set(self) -> None:
        options = CommandPlanOptions(project_path="/p", pin_all=False)
        assert "--pin-all" not in build_npm_apply_args(options)

    def test_rewrite_versions_flag_included_when_set(self) -> None:
        options = CommandPlanOptions(project_path="/p", rewrite_versions=True)
        assert "--rewrite-versions" in build_npm_apply_args(options)

    def test_rewrite_versions_flag_absent_when_not_set(self) -> None:
        options = CommandPlanOptions(project_path="/p", rewrite_versions=False)
        assert "--rewrite-versions" not in build_npm_apply_args(options)

    def test_ignore_packages_included(self) -> None:
        options = CommandPlanOptions(project_path="/p", ignore_packages=("lodash", "express"))
        args = build_npm_apply_args(options)
        assert "--ignore lodash" in args
        assert "--ignore express" in args

    def test_security_flag_included(self) -> None:
        options = CommandPlanOptions(project_path="/p", security_only=True)
        assert "--security" in build_npm_apply_args(options)

    def test_production_flag_included(self) -> None:
        options = CommandPlanOptions(project_path="/p", production=True)
        assert "--production" in build_npm_apply_args(options)

    def test_overrides_included(self) -> None:
        options = CommandPlanOptions(project_path="/p", overrides=(("lodash", "4.17.21"),))
        assert "--override lodash==4.17.21" in build_npm_apply_args(options)


class TestNpmCliExtraArgs:
    """Regression: registry_type is the StrEnum value 'NPM', not lowercase 'npm'."""

    def make_plan(self, registry_type: str) -> UpdatePlan:
        return UpdatePlan(
            project_name="p",
            project_path="/p",
            registry_type=registry_type,
            package_manager_name="npm",
            direct_entries=[],
            transitive_entries=[],
        )

    def test_uppercase_npm_registry_gets_freeze_args(self) -> None:
        options = CommandPlanOptions(project_path="/p", pin_all=True)
        args = npm_cli_extra_args(self.make_plan("NPM"), options)
        assert "--registry-type npm" in args
        assert "--pin-all" in args

    def test_pypi_registry_gets_no_args(self) -> None:
        options = CommandPlanOptions(project_path="/p", pin_all=True)
        assert npm_cli_extra_args(self.make_plan("PYPI"), options) == ""


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
