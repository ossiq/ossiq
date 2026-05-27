"""Tests for update command and NPM adapter helper methods."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ossiq.adapters.package_managers.api_npm import NPM_STATE_FILE, PackageManagerJsNpm
from ossiq.commands.plan import CommandPlanOptions, build_npm_freeze_args


def write_state(tmp_path: Path, original_overrides: dict, locked: dict | None = None) -> None:
    state = {
        "original_overrides": original_overrides,
        "locked_overrides": locked or {},
    }
    (tmp_path / NPM_STATE_FILE).write_text(json.dumps(state))


def write_manifest(tmp_path: Path, overrides: dict) -> None:
    pkg: dict = {"name": "test", "overrides": overrides}
    (tmp_path / "package.json").write_text(json.dumps(pkg))


def make_npm_pm(project_path: str) -> PackageManagerJsNpm:
    return PackageManagerJsNpm(project_path, MagicMock())


class TestRestoreState:
    def test_restores_original_overrides_fully(self, tmp_path: Path) -> None:
        write_state(tmp_path, original_overrides={"lodash": "4.17.0", "express": "4.17.0"})
        write_manifest(tmp_path, overrides={"lodash": "4.18.0", "express": "4.17.0", "ms": "2.1.3"})

        make_npm_pm(str(tmp_path)).restore_state(str(tmp_path))

        pkg = json.loads((tmp_path / "package.json").read_text())
        assert pkg["overrides"] == {"lodash": "4.17.0", "express": "4.17.0"}
        assert not (tmp_path / NPM_STATE_FILE).exists()

    def test_preserves_override_for_recommended_package(self, tmp_path: Path) -> None:
        write_state(tmp_path, original_overrides={"lodash": "4.17.0"})
        write_manifest(tmp_path, overrides={"lodash": "4.18.0"})

        make_npm_pm(str(tmp_path)).restore_state(str(tmp_path))

        pkg = json.loads((tmp_path / "package.json").read_text())
        assert pkg["overrides"] == {"lodash": "4.17.0"}

    def test_empty_original_overrides_removes_overrides_key(self, tmp_path: Path) -> None:
        write_state(tmp_path, original_overrides={})
        write_manifest(tmp_path, overrides={"lodash": "4.18.0"})

        make_npm_pm(str(tmp_path)).restore_state(str(tmp_path))

        pkg = json.loads((tmp_path / "package.json").read_text())
        assert "overrides" not in pkg

    def test_missing_state_file_raises(self, tmp_path: Path) -> None:
        write_manifest(tmp_path, overrides={})

        with pytest.raises(FileNotFoundError):
            make_npm_pm(str(tmp_path)).restore_state(str(tmp_path))

    def test_state_file_deleted_after_restore(self, tmp_path: Path) -> None:
        write_state(tmp_path, original_overrides={})
        write_manifest(tmp_path, overrides={})

        make_npm_pm(str(tmp_path)).restore_state(str(tmp_path))

        assert not (tmp_path / NPM_STATE_FILE).exists()


class TestCommandUpdatePinWiring:
    def test_pin_all_true_passed_to_options(self) -> None:
        options = CommandPlanOptions(project_path="/some/path", pin_all=True)
        assert options.pin_all is True

    def test_pin_all_false_by_default(self) -> None:
        options = CommandPlanOptions(project_path="/some/path")
        assert options.pin_all is False


class TestBuildNpmFreezeArgs:
    def test_base_always_includes_registry_type(self) -> None:
        options = CommandPlanOptions(project_path="/p")
        assert "--registry-type npm" in build_npm_freeze_args(options)

    def test_pin_all_flag_included_when_set(self) -> None:
        options = CommandPlanOptions(project_path="/p", pin_all=True)
        assert "--pin-all" in build_npm_freeze_args(options)

    def test_pin_all_flag_absent_when_not_set(self) -> None:
        options = CommandPlanOptions(project_path="/p", pin_all=False)
        assert "--pin-all" not in build_npm_freeze_args(options)

    def test_ignore_packages_included(self) -> None:
        options = CommandPlanOptions(project_path="/p", ignore_packages=("lodash", "express"))
        args = build_npm_freeze_args(options)
        assert "--ignore lodash" in args
        assert "--ignore express" in args

    def test_security_flag_included(self) -> None:
        options = CommandPlanOptions(project_path="/p", security_only=True)
        assert "--security" in build_npm_freeze_args(options)

    def test_production_flag_included(self) -> None:
        options = CommandPlanOptions(project_path="/p", production=True)
        assert "--production" in build_npm_freeze_args(options)
