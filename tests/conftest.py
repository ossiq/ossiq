"""Shared test fixtures."""

import os

import pytest


@pytest.fixture(autouse=True)
def clean_ossiq_env(monkeypatch):
    """Strip OSSIQ_* env vars so Settings() never picks up the host environment."""
    for key in list(os.environ):
        if key.startswith("OSSIQ_"):
            monkeypatch.delenv(key)
