# config.py

from pydantic import BaseModel, Field
from typing import ClassVar

ENV_PREFIX = "UPDATE_BURDEN_"


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
    github_token: str = Field(
        default=None,
        description="Optional Github Token to authorize calls to the Github API and overcome limits"
    )

    presentation: str = Field(
        default="console",
        description="How to present results, options: console, html"
    )

    # FIXME: instead of specifying folder we could specify either folder or file
    # so that it could be interpret intelligently downstream and make interface
    # a bit more intuitive.
    output_destination: str = Field(
        default=".",
        description="Where to store output, dependson. Relevance depends on the presentation"
    )

    verbose: bool = Field(
        default=False,
        description="Enable verbose output"
    )

    # Store the environment prefix for reference (not a setting itself)
    ENV_PREFIX: ClassVar[str] = ENV_PREFIX

    @classmethod
    def load_from_env(cls) -> "Settings":
        """Load settings from defaults and environment variables."""
        return cls()
