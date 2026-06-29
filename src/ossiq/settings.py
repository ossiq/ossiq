# config.py

from datetime import datetime
from pathlib import Path
from typing import ClassVar

from pydantic import BaseModel, Field, field_validator

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


class Settings(BaseModel):
    """
    The immutable configuration object for the CLI tool.
    Pydantic handles environment variable loading (using the field names).
    """

    # Configuration to make the instance immutable (read-only after creation)
    # Use 'frozen=True' in Pydantic v2
    model_config = {
        "frozen": True,
        "env_prefix": ENV_PREFIX,
        "extra": "ignore",
    }

    # Configuration Fields
    github_token: str | None = Field(default=None, description=ARGS_HELP_GITHUB_TOKEN)

    cache_destination: str = Field(
        default=str(Path.home() / ".ossiq_cache.sqlite3"), description=ARGS_HELP_CACHE_DESTINATION
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
    def load_from_env(cls) -> "Settings":
        """Load settings from defaults and environment variables."""
        return cls()
