"""Tests for Settings loading: config file, env vars, and CLI precedence."""

from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

import ossiq.settings
from ossiq.cli import app
from ossiq.settings import GITHUB_CLIENT_ID, GithubAuthMode, Settings, default_config_dir

runner = CliRunner()


@pytest.fixture
def legacy_config() -> Path:
    """The legacy ~/.ossiq/config location (redirected to a temp dir by the autouse fixture)."""
    path = ossiq.settings.LEGACY_CONFIG_PATH
    path.parent.mkdir(parents=True)
    return path


@pytest.fixture
def new_config() -> Path:
    """The new config file location (redirected to a temp dir by the autouse fixture)."""
    path = ossiq.settings.CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


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


def test_stability_cache_ttl_defaults_to_168():
    assert Settings().stability_cache_ttl == 168


def test_responsiveness_auto_follows_token_presence(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert Settings(github_token=None).responsiveness_enabled() is False
    assert Settings(github_token="ghp_x").responsiveness_enabled() is True


def test_responsiveness_explicit_flag_wins(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert Settings(github_token=None, stability_responsiveness=True).responsiveness_enabled() is True
    assert Settings(github_token="ghp_x", stability_responsiveness=False).responsiveness_enabled() is False


def test_responsiveness_off_when_stability_disabled():
    assert Settings(github_token="ghp_x", stability=False).responsiveness_enabled() is False


def test_cli_config_option_reaches_settings(config_file):
    result = runner.invoke(app, ["--no-cache", "--config", str(config_file), "--verbose", "help"])
    assert result.exit_code == 0
    assert "cooldown_period: 14" in result.output


def test_cli_config_value_not_clobbered_by_typer_defaults(tmp_path):
    # Regression: typer defaults used to silently override config-file values (e.g. cache_ttl)
    path = tmp_path / "config"
    path.write_text("OSSIQ_CACHE_TTL=48\n")
    result = runner.invoke(app, ["--no-cache", "--config", str(path), "--verbose", "help"])
    assert result.exit_code == 0
    assert "cache_ttl: 48" in result.output


def test_cli_flag_overrides_config_file(config_file):
    result = runner.invoke(
        app, ["--no-cache", "--config", str(config_file), "--cooldown-period", "1", "--verbose", "help"]
    )
    assert result.exit_code == 0
    # Anchored on the setting: the output also holds a temp path, whose digits can contain "14".
    assert "cooldown_period: 1" in result.output
    assert "cooldown_period: 14" not in result.output


def test_cli_rejects_missing_config_file():
    result = runner.invoke(app, ["--no-cache", "--config", "/nonexistent/ossiq-config", "help"])
    assert result.exit_code == 2


def test_cli_reads_legacy_config_by_default(legacy_config):
    legacy_config.write_text("OSSIQ_COOLDOWN_PERIOD=37\n")
    result = runner.invoke(app, ["--no-cache", "--verbose", "help"])
    assert result.exit_code == 0
    assert "37" in result.output


def test_default_config_dir_follows_xdg_config_home(tmp_path):
    environ = {"XDG_CONFIG_HOME": str(tmp_path / "xdg")}
    assert default_config_dir(environ, tmp_path / "home") == tmp_path / "xdg" / "ossiq"


@pytest.mark.parametrize("environ", [{}, {"XDG_CONFIG_HOME": ""}, {"XDG_CONFIG_HOME": "relative/dir"}])
def test_default_config_dir_falls_back_to_home_dot_config(environ, tmp_path):
    assert default_config_dir(environ, tmp_path) == tmp_path / ".config" / "ossiq"


def test_legacy_config_alone_still_works(legacy_config):
    legacy_config.write_text("OSSIQ_COOLDOWN_PERIOD=21\n")
    assert Settings.load().cooldown_period == 21


def test_new_config_beats_legacy_key_by_key(legacy_config, new_config):
    legacy_config.write_text("OSSIQ_COOLDOWN_PERIOD=10\nOSSIQ_CACHE_TTL=5\n")
    new_config.write_text("OSSIQ_COOLDOWN_PERIOD=20\n")
    settings = Settings.load()
    assert settings.cooldown_period == 20
    assert settings.cache_ttl == 5  # a key only the legacy file sets still comes through


def test_env_var_beats_both_config_files(legacy_config, new_config, monkeypatch):
    legacy_config.write_text("OSSIQ_COOLDOWN_PERIOD=10\n")
    new_config.write_text("OSSIQ_COOLDOWN_PERIOD=20\n")
    monkeypatch.setenv("OSSIQ_COOLDOWN_PERIOD", "3")
    assert Settings.load().cooldown_period == 3


def test_load_with_neither_config_file_creates_only_the_new_dir():
    assert Settings.load().cooldown_period == 7
    assert ossiq.settings.CONFIG_PATH.parent.is_dir()
    assert not ossiq.settings.LEGACY_CONFIG_PATH.parent.exists()


def test_load_never_writes_to_the_legacy_config(legacy_config):
    legacy_config.write_text("OSSIQ_COOLDOWN_PERIOD=10\n")
    before = legacy_config.read_bytes()
    Settings.load()
    assert legacy_config.read_bytes() == before


def test_explicit_config_file_replaces_both_default_files(legacy_config, new_config, tmp_path):
    legacy_config.write_text("OSSIQ_CACHE_TTL=5\n")
    new_config.write_text("OSSIQ_COOLDOWN_PERIOD=20\n")
    explicit = tmp_path / "explicit"
    explicit.write_text("OSSIQ_STABILITY_CACHE_TTL=99\n")
    settings = Settings.load(explicit)
    assert settings.stability_cache_ttl == 99
    assert settings.cache_ttl == 24
    assert settings.cooldown_period == 7


def test_bare_settings_reads_neither_config_file(legacy_config, new_config):
    legacy_config.write_text("OSSIQ_COOLDOWN_PERIOD=10\n")
    new_config.write_text("OSSIQ_COOLDOWN_PERIOD=20\n")
    assert Settings().cooldown_period == 7


def test_cache_destination_follows_config_path(tmp_path, monkeypatch):
    monkeypatch.setattr(ossiq.settings, "CONFIG_PATH", tmp_path / "elsewhere" / "config")
    assert Settings().cache_destination == str(tmp_path / "elsewhere" / "cache.sqlite3")


def test_bare_github_token_env_is_picked_up(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_bare")
    assert Settings().github_token == "ghp_bare"


def test_prefixed_github_token_beats_bare_one(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_bare")
    monkeypatch.setenv("OSSIQ_GITHUB_TOKEN", "ghp_prefixed")
    assert Settings().github_token == "ghp_prefixed"


def test_bare_github_token_env_beats_a_config_file_token(new_config, monkeypatch):
    new_config.write_text("OSSIQ_GITHUB_TOKEN=ghp_from_file\n")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_bare")
    assert Settings.load().github_token == "ghp_bare"


def test_responsiveness_follows_bare_github_token_env(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_bare")
    assert Settings().responsiveness_enabled() is True


def test_repr_and_str_leave_out_the_github_token():
    settings = Settings(github_token="ghp_SECRETVALUE")

    assert "ghp_SECRETVALUE" not in repr(settings)
    assert "ghp_SECRETVALUE" not in str(settings)
    assert settings.github_token == "ghp_SECRETVALUE"


def test_a_token_set_through_model_copy_stays_out_of_repr():
    # authenticate_github hands the keyring token on this way.
    settings = Settings().model_copy(update={"github_token": "gho_SECRETVALUE"})

    assert "gho_SECRETVALUE" not in repr(settings)
    assert settings.github_token == "gho_SECRETVALUE"


def test_github_auth_defaults_to_auto(monkeypatch):
    monkeypatch.delenv("OSSIQ_GITHUB_AUTH")
    assert Settings().github_auth is GithubAuthMode.AUTO


@pytest.mark.parametrize("raw", ["off", "OFF", " Off "])
def test_github_auth_off_from_env_in_any_casing(raw, monkeypatch):
    monkeypatch.setenv("OSSIQ_GITHUB_AUTH", raw)
    assert Settings().github_auth is GithubAuthMode.OFF


def test_github_auth_can_be_set_in_the_new_config_file(new_config, monkeypatch):
    monkeypatch.delenv("OSSIQ_GITHUB_AUTH")
    new_config.write_text("OSSIQ_GITHUB_AUTH=off\n")
    assert Settings.load().github_auth is GithubAuthMode.OFF


def test_github_auth_can_be_set_in_the_legacy_config_file(legacy_config, monkeypatch):
    monkeypatch.delenv("OSSIQ_GITHUB_AUTH")
    legacy_config.write_text("OSSIQ_GITHUB_AUTH=off\n")
    assert Settings.load().github_auth is GithubAuthMode.OFF


def test_github_auth_rejects_an_unknown_value(monkeypatch):
    monkeypatch.setenv("OSSIQ_GITHUB_AUTH", "maybe")
    with pytest.raises(ValidationError):
        Settings()


def test_github_client_id_defaults_to_the_registered_app():
    assert Settings().github_client_id == GITHUB_CLIENT_ID


def test_github_client_id_can_be_overridden_by_env(monkeypatch):
    monkeypatch.setenv("OSSIQ_GITHUB_CLIENT_ID", "Iv1.other")
    assert Settings().github_client_id == "Iv1.other"
