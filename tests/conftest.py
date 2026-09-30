"""Shared test fixtures."""

import os

import pytest

import ossiq.settings


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
