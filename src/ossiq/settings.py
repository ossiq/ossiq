# config.py

from typing import ClassVar

from pydantic import BaseModel, Field

from ossiq.messages import (
    ARGS_HELP_CACHE_DESTINATION,
    ARGS_HELP_CACHE_TTL,
    ARGS_HELP_DEBUG,
    ARGS_HELP_GITHUB_TOKEN,
    ARGS_HELP_PRESENTATION,
)

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

    cache_destination: str = Field(default="./ossiq_cache.sqlite3", description=ARGS_HELP_CACHE_DESTINATION)
    cache_ttl: int = Field(default=24, description=ARGS_HELP_CACHE_TTL)
    presentation: str = Field(default="console", description=ARGS_HELP_PRESENTATION)

    verbose: bool = Field(default=False, description="Enable verbose output")
    debug: bool = Field(default=False, description=ARGS_HELP_DEBUG)

    # Store the environment prefix for reference (not a setting itself)
    ENV_PREFIX: ClassVar[str] = ENV_PREFIX

    @classmethod
    def load_from_env(cls) -> "Settings":
        """Load settings from defaults and environment variables."""
        return cls()
