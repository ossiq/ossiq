# config.py

from datetime import datetime
from pathlib import Path
from typing import ClassVar

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from ossiq.messages import (
    ARGS_HELP_CACHE_DESTINATION,
    ARGS_HELP_CACHE_TTL,
    ARGS_HELP_COOLDOWN_PERIOD,
    ARGS_HELP_CUTOFF_DATE,
    ARGS_HELP_DEBUG,
    ARGS_HELP_GITHUB_TOKEN,
)
from ossiq.timeutil import cutoff_datetime_from_iso_date

ENV_PREFIX = "OSSIQ_"
CONFIG_PATH = Path.home() / ".ossiq" / "config"


class Settings(BaseSettings):
    """
    The immutable configuration object for the CLI tool.

    pydantic-settings loads values from OSSIQ_-prefixed environment variables;
    Settings.load() additionally reads the config file (dotenv format).
    No env_file is set in model_config so that bare Settings() never touches
    the user's real config file (important for tests).
    """

    model_config = SettingsConfigDict(
        frozen=True,
        env_prefix=ENV_PREFIX,
        extra="ignore",
    )

    # Configuration Fields
    github_token: str | None = Field(default=None, description=ARGS_HELP_GITHUB_TOKEN)

    cache_destination: str = Field(
        default=str(CONFIG_PATH.parent / "cache.sqlite3"), description=ARGS_HELP_CACHE_DESTINATION
    )
    cache_ttl: int = Field(default=24, description=ARGS_HELP_CACHE_TTL)
    verbose: bool = Field(default=False, description="Enable verbose output")
    debug: bool = Field(default=False, description=ARGS_HELP_DEBUG)
    traceback: bool = Field(default=False, description="Show full traceback on error instead of logging to file")

    skip_pypi_enrichment: bool = Field(
        default=False,
        description="Disable PyPI metadata fetching for transitive constraint enrichment",
    )

    cutoff_date: datetime | None = Field(default=None, description=ARGS_HELP_CUTOFF_DATE)
    cooldown_period: int = Field(default=7, description=ARGS_HELP_COOLDOWN_PERIOD)

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

    @classmethod
    def load(cls, config_file: Path | None = None) -> "Settings":
        """Load settings from the config file (default ~/.ossiq/config); env vars override file values."""
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        # _env_file is a real BaseSettings init param; ty only sees the synthesized model __init__
        return cls(_env_file=config_file if config_file is not None else CONFIG_PATH)  # ty: ignore[unknown-argument]
