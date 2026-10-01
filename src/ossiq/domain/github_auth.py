"""Value types for the GitHub device-flow login.

Holds no I/O: the OAuth client builds these, the credential store persists them and the service
decides what to do with them.
"""

import math
from dataclasses import dataclass, field
from enum import StrEnum

REFRESH_MARGIN_SECONDS = 300
"""How long before `expires_at` an access token counts as due for a refresh."""

RAISE_LIMIT_ADVICE = (
    "To raise the limit to 5,000 requests/hour, set OSSIQ_GITHUB_TOKEN to a GitHub token (the only option in CI "
    "and containers), or run `ossiq auth login` where a system keyring is available."
)
"""How to lift the unauthenticated limit, worded for any machine: a container cannot hold a login."""


class TokenSource(StrEnum):
    """Where the GitHub token in use came from, highest precedence first."""

    CLI_FLAG = "cli_flag"
    ENV_OSSIQ = "env_ossiq"
    ENV_GITHUB_TOKEN = "env_github_token"
    KEYRING = "keyring"
    CONFIG_FILE = "config_file"
    LEGACY_CONFIG_FILE = "legacy_config_file"


@dataclass(frozen=True)
class GithubCredentials:
    """An OAuth access token and, when the app issues them, its expiry and refresh token.

    Both tokens are left out of `repr`, so a stray log line or traceback cannot leak them.
    """

    access_token: str = field(repr=False)
    refresh_token: str | None = field(default=None, repr=False)
    expires_at: int | None = None
    """Epoch seconds. `None` for a token that never expires."""
    scope: str = ""
    token_type: str = "bearer"

    def needs_refresh(self, now: float) -> bool:
        """Report whether the access token expires within REFRESH_MARGIN_SECONDS.

        Args:
            now: The current time, in epoch seconds.

        Returns:
            False for a token without an expiry.
        """
        return self.expires_at is not None and now > self.expires_at - REFRESH_MARGIN_SECONDS


@dataclass(frozen=True)
class DeviceChallenge:
    """A pending device-flow login: what the user has to do, and the secret that completes it.

    `device_code` is a secret until the user approves, so it stays out of `repr` and out of
    anything shown to the user.
    """

    user_code: str
    verification_uri: str
    expires_at: int
    """Epoch seconds after which GitHub rejects the codes."""
    interval: int
    """Minimum seconds between polls."""
    device_code: str = field(repr=False)

    def seconds_left(self, now: float) -> int:
        """Return the whole seconds until the challenge expires, never negative.

        Args:
            now: The current time, in epoch seconds.
        """
        return max(0, math.ceil(self.expires_at - now))


@dataclass(frozen=True)
class AuthStatus:
    """What `ossiq auth status` reports: which token is in use and what is known about it."""

    source: TokenSource | None
    """`None` when no token resolves."""
    login: str | None = None
    scope: str | None = None
    expires_at: int | None = None
    backend: str | None = None
    legacy_config_in_use: bool = False
