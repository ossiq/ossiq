"""Tests for Settings loading: config file, env vars, and CLI precedence."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

import ossiq.settings
from ossiq.cli import app
from ossiq.settings import Settings

runner = CliRunner()


@pytest.fixture
def config_file(tmp_path) -> Path:
    path = tmp_path / "config"
    path.write_text("# comment\n\nOSSIQ_GITHUB_TOKEN=ghp_from_file\nOSSIQ_COOLDOWN_PERIOD=14\n")
    return path


def test_load_reads_config_file(config_file):
    settings = Settings.load(config_file)
    assert settings.github_token == "ghp_from_file"
    assert settings.cooldown_period == 14


def test_env_var_overrides_config_file(config_file, monkeypatch):
    monkeypatch.setenv("OSSIQ_COOLDOWN_PERIOD", "3")
    settings = Settings.load(config_file)
    assert settings.cooldown_period == 3


def test_load_with_missing_default_file_uses_defaults(tmp_path, monkeypatch):
    monkeypatch.setattr(ossiq.settings, "CONFIG_PATH", tmp_path / "absent")
    settings = Settings.load()
    assert settings.github_token is None
    assert settings.cooldown_period == 7


def test_env_var_works_without_config_file(tmp_path, monkeypatch):
    monkeypatch.setattr(ossiq.settings, "CONFIG_PATH", tmp_path / "absent")
    monkeypatch.setenv("OSSIQ_GITHUB_TOKEN", "ghp_from_env")
    assert Settings.load().github_token == "ghp_from_env"


def test_load_creates_config_dir_if_missing(tmp_path, monkeypatch):
    config_path = tmp_path / "newdir" / "config"
    monkeypatch.setattr(ossiq.settings, "CONFIG_PATH", config_path)
    Settings.load()
    assert config_path.parent.exists()


def test_cache_destination_defaults_under_config_dir():
    assert Settings().cache_destination == str(ossiq.settings.CONFIG_PATH.parent / "cache.sqlite3")


def test_cli_config_option_reaches_settings(config_file):
    result = runner.invoke(app, ["--no-cache", "--config", str(config_file), "--verbose", "help"])
    assert result.exit_code == 0
    assert "cooldown_period" in result.output
    assert "14" in result.output


def test_cli_config_value_not_clobbered_by_typer_defaults(tmp_path):
    # Regression: typer defaults used to silently override config-file values (e.g. cache_ttl)
    path = tmp_path / "config"
    path.write_text("OSSIQ_CACHE_TTL=48\n")
    result = runner.invoke(app, ["--no-cache", "--config", str(path), "--verbose", "help"])
    assert result.exit_code == 0
    assert "48" in result.output


def test_cli_flag_overrides_config_file(config_file):
    result = runner.invoke(
        app, ["--no-cache", "--config", str(config_file), "--cooldown-period", "1", "--verbose", "help"]
    )
    assert result.exit_code == 0
    assert "14" not in result.output


def test_cli_rejects_missing_config_file():
    result = runner.invoke(app, ["--no-cache", "--config", "/nonexistent/ossiq-config", "help"])
    assert result.exit_code == 2
