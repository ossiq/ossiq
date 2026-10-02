"""Shared test fixtures."""

import os

import pytest

import ossiq.settings


@pytest.fixture(scope="session")
def httpserver_listen_address() -> tuple[str, None]:
    """Bind the shared test HTTP server by IP so no test pays for resolving `localhost`.

    The server listens on IPv4 only, but on Windows `localhost` is tried as ::1 first and the refused
    attempt costs ~2s per connection, enough to outlast the timers that timing-sensitive tests set.
    """
    return "127.0.0.1", None


@pytest.fixture(autouse=True)
def clean_ossiq_env(monkeypatch):
    """Strip OSSIQ_* and GITHUB_TOKEN so Settings() never picks up the host environment.

    Also turns the GitHub login flow off: a scan without a token must never start a device-flow
    login (or touch the real keychain) from inside a test. Tests that exercise it opt back in.
    """
    for key in list(os.environ):
        if key.startswith("OSSIQ_"):
            monkeypatch.delenv(key)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("OSSIQ_GITHUB_AUTH", "off")


@pytest.fixture(autouse=True)
def isolated_config_dir(tmp_path_factory, monkeypatch):
    """Point the config paths at a temp dir so no test reads or writes the developer's real ones.

    The dir is separate from each test's own `tmp_path`, which tests are free to list or assert empty.
    """
    home = tmp_path_factory.mktemp("ossiq-home")
    config_dir = home / ".config" / "ossiq"
    monkeypatch.setattr(ossiq.settings, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(ossiq.settings, "CONFIG_PATH", config_dir / "config")
    monkeypatch.setattr(ossiq.settings, "LEGACY_CONFIG_PATH", home / ".ossiq" / "config")
