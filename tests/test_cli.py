"""
Tests for the CLI entry point (ossiq.cli).
"""

from typing import Any

import pytest
import requests_cache
import typer
from typer.testing import CliRunner

import ossiq.settings
from ossiq.cli import app, plan_options
from ossiq.strategy.pyramid import UpdateStrategy

runner = CliRunner()


def test_the_old_cache_is_removed_once_with_a_notice_on_stderr():
    legacy = ossiq.settings.LEGACY_CONFIG_PATH.parent / "cache.sqlite3"
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_bytes(b"x" * 2_000_000)

    try:
        first = runner.invoke(app, ["help"])
        second = runner.invoke(app, ["help"])
    finally:
        requests_cache.uninstall_cache()

    assert first.exit_code == 0
    assert second.exit_code == 0
    # stdout carries the MCP protocol and agent JSON, so the notice must stay on stderr.
    assert "Removed the old HTTP cache" in first.stderr
    assert "Removed the old HTTP cache" not in first.stdout
    assert "Removed the old HTTP cache" not in second.stderr
    assert not legacy.exists()


def test_no_cache_leaves_the_old_cache_alone():
    legacy = ossiq.settings.LEGACY_CONFIG_PATH.parent / "cache.sqlite3"
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_bytes(b"x")

    result = runner.invoke(app, ["--no-cache", "help"])

    assert result.exit_code == 0
    assert legacy.exists()


NO_FLAGS: dict[str, Any] = dict(
    registry_type=None,
    allow_prerelease=False,
    allow_prerelease_package=None,
    production=False,
    update_strategy="standard",
    strategy_override=None,
    ignore=None,
    pin_all=False,
    rewrite_versions=False,
    override=None,
    allow_partial=False,
)


def build_options(project_path: str = ".", **changes: Any):
    flags: dict[str, Any] = {**NO_FLAGS, **changes}
    return plan_options(project_path, **flags)


def test_plan_options_builds_the_options_every_planning_command_takes():
    options = build_options("/work/app", production=True, update_strategy="security", override=["Left-Pad==1.3.0"])

    assert options.project_path == "/work/app" and options.production
    assert options.update_strategy is UpdateStrategy.SECURITY
    assert options.overrides == (("left-pad", "1.3.0"),)


@pytest.mark.parametrize(
    "flags",
    [
        {"registry_type": "maven"},
        {"override": ["foo==1.0.0"], "ignore": ["foo"]},
        {"override": ["not-a-spec"]},
        {"update_strategy": "nonsense"},
    ],
)
def test_plan_options_rejects_what_the_flags_cannot_mean(flags):
    with pytest.raises(typer.BadParameter):
        build_options(**flags)
