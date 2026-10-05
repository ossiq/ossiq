"""
Tests for the CLI entry point (ossiq.cli).
"""

import requests_cache
from typer.testing import CliRunner

import ossiq.settings
from ossiq.cli import app

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
