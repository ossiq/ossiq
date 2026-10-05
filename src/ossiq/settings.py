# config.py

import os
from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import ClassVar

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from ossiq.messages import (
    ARGS_HELP_CACHE_DESTINATION,
    ARGS_HELP_CACHE_TTL,
    ARGS_HELP_COOLDOWN_PERIOD,
    ARGS_HELP_CUTOFF_DATE,
    ARGS_HELP_DEBUG,
    ARGS_HELP_ENGINE,
    ARGS_HELP_GITHUB_AUTH,
    ARGS_HELP_GITHUB_CLIENT_ID,
    ARGS_HELP_GITHUB_TOKEN,
    ARGS_HELP_PROBE_RUNTIME,
    ARGS_HELP_STABILITY,
    ARGS_HELP_STABILITY_CACHE_TTL,
    ARGS_HELP_STABILITY_RESPONSIVENESS,
)
from ossiq.timeutil import cutoff_datetime_from_iso_date

ENV_PREFIX = "OSSIQ_"

GITHUB_CLIENT_ID = "Ov23liL4Ccg4fDTQwUTw"
"""Client ID of the "OSS IQ" OAuth app (device flow, no scope). Public by design: the device flow
needs no client secret, so shipping this value exposes nothing."""


class GithubAuthMode(StrEnum):
    """Whether a scan may offer the GitHub device-flow login."""

    AUTO = "auto"
    OFF = "off"


def default_config_dir(environ: Mapping[str, str], home: Path) -> Path:
    """Directory that holds the config file and the HTTP cache.

    Args:
        environ: Process environment; only `XDG_CONFIG_HOME` is read.
        home: The user's home directory, used when `XDG_CONFIG_HOME` is unset, empty or relative.

    Returns:
        `$XDG_CONFIG_HOME/ossiq`, else `<home>/.config/ossiq`.
    """
    # The XDG spec says an empty or relative XDG_CONFIG_HOME must be ignored, not resolved.
    xdg = environ.get("XDG_CONFIG_HOME", "")
    base = Path(xdg) if xdg and Path(xdg).is_absolute() else home / ".config"
    return base / "ossiq"


CONFIG_DIR = default_config_dir(os.environ, Path.home())
CONFIG_PATH = CONFIG_DIR / "config"
LEGACY_CONFIG_PATH = Path.home() / ".ossiq" / "config"
"""Where the config file lived before it moved to CONFIG_DIR. Read, never written or created."""


class Settings(BaseSettings):
    """
    The immutable configuration object for the CLI tool.

    pydantic-settings loads values from OSSIQ_-prefixed environment variables;
    Settings.load() additionally reads the config files (dotenv format).
    No env_file is set in model_config so that bare Settings() never touches
    the user's real config files (important for tests).
    """

    model_config = SettingsConfigDict(
        frozen=True,
        env_prefix=ENV_PREFIX,
        extra="ignore",
    )

    # Configuration Fields
    # An explicit alias replaces the env prefix, so both names are spelled out: OSSIQ_GITHUB_TOKEN first,
    # then the bare GITHUB_TOKEN CI convention. Env names match case-insensitively, so the field name
    # `github_token` doubles as that bare name and keeps `Settings(github_token=...)` working.
    # Left out of `repr`, so a Settings value in a log line, a traceback or a containing object's `repr`
    # cannot leak the token.
    github_token: str | None = Field(
        default=None,
        validation_alias=AliasChoices("OSSIQ_GITHUB_TOKEN", "github_token"),
        description=ARGS_HELP_GITHUB_TOKEN,
        repr=False,
    )
    github_auth: GithubAuthMode = Field(default=GithubAuthMode.AUTO, description=ARGS_HELP_GITHUB_AUTH)
    github_client_id: str = Field(default=GITHUB_CLIENT_ID, description=ARGS_HELP_GITHUB_CLIENT_ID)

    # A factory, not a value: CONFIG_PATH is read at construction, so tests can redirect it.
    cache_destination: str = Field(
        default_factory=lambda: str(CONFIG_PATH.parent / "cache.sqlite3"), description=ARGS_HELP_CACHE_DESTINATION
    )
    cache_ttl: int = Field(default=24, description=ARGS_HELP_CACHE_TTL)
    stability_cache_ttl: int = Field(default=168, description=ARGS_HELP_STABILITY_CACHE_TTL)
    verbose: bool = Field(default=False, description="Enable verbose output")
    debug: bool = Field(default=False, description=ARGS_HELP_DEBUG)
    traceback: bool = Field(default=False, description="Show full traceback on error instead of logging to file")

    skip_pypi_enrichment: bool = Field(
        default=False,
        description="Disable PyPI metadata fetching for transitive constraint enrichment",
    )

    cutoff_date: datetime | None = Field(default=None, description=ARGS_HELP_CUTOFF_DATE)
    cooldown_period: int = Field(default=7, description=ARGS_HELP_COOLDOWN_PERIOD)
    stability: bool = Field(default=True, description=ARGS_HELP_STABILITY)
    stability_responsiveness: bool | None = Field(default=None, description=ARGS_HELP_STABILITY_RESPONSIVENESS)
    probe_runtime: bool = Field(default=True, description=ARGS_HELP_PROBE_RUNTIME)
    engine_versions: dict[str, str] = Field(default_factory=dict, description=ARGS_HELP_ENGINE)
    runtime_unknown: bool = Field(
        default=False, description="Treat the runtime as unknown: no probe, no provided version, floor only"
    )

    # Store the environment prefix for reference (not a setting itself)
    ENV_PREFIX: ClassVar[str] = ENV_PREFIX

    @field_validator("cutoff_date", mode="before")
    @classmethod
    def parse_cutoff_date(cls, v: object) -> datetime | None:
        """Accept an ISO date string (YYYY-MM-DD) or a datetime; convert to end-of-day UTC."""
        if v is None or isinstance(v, datetime):
            return v
        if isinstance(v, str):
            return cutoff_datetime_from_iso_date(v)
        raise ValueError(f"cutoff_date must be an ISO date string or datetime, got {type(v)}")

    @field_validator("github_auth", mode="before")
    @classmethod
    def normalize_github_auth(cls, v: object) -> object:
        """Accept any casing of the mode ('OFF' from a shell profile is as good as 'off')."""
        return v.strip().lower() if isinstance(v, str) else v

    @classmethod
    def load(cls, config_file: Path | None = None) -> "Settings":
        """Load settings from the config files; env vars override file values.

        Args:
            config_file: Explicit config file. It replaces the defaults, so neither CONFIG_PATH nor
                LEGACY_CONFIG_PATH is read.

        Returns:
            Settings built from LEGACY_CONFIG_PATH, then CONFIG_PATH (a key in the new file wins),
            then the environment. Only the new config directory is ever created.
        """
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        env_files = [config_file] if config_file is not None else [LEGACY_CONFIG_PATH, CONFIG_PATH]
        # _env_file is a real BaseSettings init param; ty only sees the synthesized model __init__
        # Later files override earlier ones; a file that does not exist is skipped.
        return cls(_env_file=env_files)  # ty: ignore[unknown-argument]

    def responsiveness_enabled(self) -> bool:
        """Whether to run the GraphQL issue/PR/engagement stability channels.

        Explicit --stability-responsiveness / --no-stability-responsiveness wins; otherwise auto:
        on when a GitHub token is available (GraphQL 401s unauthenticated), off without one. Always
        off when --no-stability disables the whole index.
        """
        if not self.stability:
            return False
        if self.stability_responsiveness is not None:
            return self.stability_responsiveness
        return bool(self.github_token)
