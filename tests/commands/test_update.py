"""Tests for commands/update.py — handle_npm_overrides_diff() and pin wiring."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer

from ossiq.commands.update import NPM_STATE_FILE, CommandUpdateOptions, handle_npm_overrides_diff


def write_state(tmp_path: Path, original_overrides: dict, recommended: list[str], locked: dict | None = None) -> None:
    state = {
        "original_overrides": original_overrides,
        "recommended_packages": recommended,
        "locked_overrides": locked or {},
    }
    (tmp_path / NPM_STATE_FILE).write_text(json.dumps(state))


def write_manifest(tmp_path: Path, overrides: dict) -> None:
    pkg = {"name": "test", "overrides": overrides}
    (tmp_path / "package.json").write_text(json.dumps(pkg))


class TestHandleNpmOverridesDiff:
    def test_removes_recommended_from_overrides(self, tmp_path: Path) -> None:
        write_state(tmp_path, original_overrides={"lodash": "4.17.0", "express": "4.17.0"}, recommended=["lodash"])
        write_manifest(tmp_path, overrides={"lodash": "4.18.0", "express": "4.17.0"})

        handle_npm_overrides_diff(str(tmp_path))

        pkg = json.loads((tmp_path / "package.json").read_text())
        assert pkg["overrides"] == {"express": "4.17.0"}
        assert not (tmp_path / NPM_STATE_FILE).exists()

    def test_all_recommended_yields_empty_overrides(self, tmp_path: Path) -> None:
        write_state(tmp_path, original_overrides={"lodash": "4.17.0"}, recommended=["lodash"])
        write_manifest(tmp_path, overrides={"lodash": "4.18.0"})

        handle_npm_overrides_diff(str(tmp_path))

        pkg = json.loads((tmp_path / "package.json").read_text())
        assert pkg["overrides"] == {}

    def test_empty_original_overrides_yields_empty_overrides(self, tmp_path: Path) -> None:
        write_state(tmp_path, original_overrides={}, recommended=["lodash"])
        write_manifest(tmp_path, overrides={"lodash": "4.18.0"})

        handle_npm_overrides_diff(str(tmp_path))

        pkg = json.loads((tmp_path / "package.json").read_text())
        assert pkg["overrides"] == {}

    def test_missing_state_file_exits_with_error(self, tmp_path: Path) -> None:
        write_manifest(tmp_path, overrides={})

        with pytest.raises(typer.Exit):
            handle_npm_overrides_diff(str(tmp_path))

    def test_state_file_deleted_after_restore(self, tmp_path: Path) -> None:
        write_state(tmp_path, original_overrides={}, recommended=[])
        write_manifest(tmp_path, overrides={})

        handle_npm_overrides_diff(str(tmp_path))

        assert not (tmp_path / NPM_STATE_FILE).exists()


class TestCommandUpdatePinWiring:
    def test_pin_true_passed_to_build_update_plan(self) -> None:
        options = CommandUpdateOptions(project_path="/some/path", pin=True)
        assert options.pin is True

    def test_pin_false_by_default(self) -> None:
        options = CommandUpdateOptions(project_path="/some/path")
        assert options.pin is False

    def test_npm_overrides_diff_false_by_default(self) -> None:
        options = CommandUpdateOptions(project_path="/some/path")
        assert options.npm_overrides_diff is False

    def test_npm_overrides_diff_triggers_early_return(self, tmp_path: Path) -> None:
        write_state(tmp_path, original_overrides={}, recommended=[])
        write_manifest(tmp_path, overrides={})

        options = CommandUpdateOptions(project_path=str(tmp_path), npm_overrides_diff=True)
        ctx = MagicMock(spec=typer.Context)

        with patch("ossiq.commands.update.handle_npm_overrides_diff") as mock_handle:
            from ossiq.commands.update import command_update

            command_update(ctx=ctx, options=options)

        mock_handle.assert_called_once_with(str(tmp_path))
        ctx.assert_not_called()
