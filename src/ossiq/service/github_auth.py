"""
GitHub login orchestration: which token a scan runs with, and the device-flow login that can supply one.

The one place that joins `Settings`, the credential store and the OAuth client. It returns values
and raises domain errors; showing a challenge or a warning to the user is the front door's job.
"""

import logging
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from dotenv import dotenv_values

import ossiq.settings as settings_module
from ossiq.adapters.credential_store import KeyringCredentialStore
from ossiq.clients.client_github_oauth import GithubOAuthClient, OAuthErrorCode, OAuthFailure
from ossiq.domain.exceptions import (
    CredentialStoreUnavailable,
    GithubAuthDenied,
    GithubAuthRequired,
    GithubAuthTimeout,
)
from ossiq.domain.github_auth import AuthStatus, DeviceChallenge, GithubCredentials, TokenSource
from ossiq.settings import GithubAuthMode, Settings

logger = logging.getLogger(__name__)

VALIDATION_TTL_SECONDS = 600.0
"""How long a token GitHub just accepted is trusted without asking again."""

EXPLICIT_SOURCES = frozenset({TokenSource.CLI_FLAG, TokenSource.ENV_OSSIQ, TokenSource.ENV_GITHUB_TOKEN})
"""Tokens the user set for this run on purpose; they outrank anything in the keyring."""

TRANSIENT_FAILURES = frozenset({OAuthErrorCode.NETWORK_ERROR, OAuthErrorCode.INVALID_RESPONSE})
"""Failures that say nothing about the login itself, so the caller may try again."""


class CredentialStore(Protocol):
    """What the login flow needs from a credential store."""

    def read_credentials(self) -> GithubCredentials | None: ...

    def write_credentials(self, credentials: GithubCredentials) -> None: ...

    def delete_credentials(self) -> None: ...

    def read_pending(self) -> DeviceChallenge | None: ...

    def write_pending(self, challenge: DeviceChallenge) -> None: ...

    def delete_pending(self) -> None: ...

    def available(self) -> bool: ...

    def backend_name(self) -> str | None: ...


class AuthSkipReason(StrEnum):
    """Why a scan runs without a GitHub token when it could not get one."""

    DISABLED = "disabled"
    CI = "ci"
    STORE_UNAVAILABLE = "store_unavailable"
    LOGIN_DENIED = "login_denied"
    LOGIN_EXPIRED = "login_expired"
    LOGIN_UNAVAILABLE = "login_unavailable"


@dataclass(frozen=True)
class GithubAuthResult:
    """The outcome of resolving a token: the settings to scan with, and how they got their token."""

    settings: Settings
    source: TokenSource | None
    """`None` when the scan runs unauthenticated."""
    skipped: AuthSkipReason | None = None
    """Set only when no token resolved; the front door shows it as a diagnostic."""
    detail: str = ""


VALIDATED_TOKENS: dict[str, float] = {}
"""Tokens GitHub accepted in this process, with when. Shared so a long-lived process asks rarely."""


@dataclass(frozen=True)
class AuthDeps:
    """Everything the login flow touches outside `Settings`, injectable so tests need no real clock."""

    store: CredentialStore
    client: GithubOAuthClient
    now: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep
    environ: Mapping[str, str] = field(default_factory=lambda: os.environ)
    validated: dict[str, float] = field(default_factory=lambda: VALIDATED_TOKENS)


def default_deps(settings: Settings) -> AuthDeps:
    """Build the real store and client for these settings."""
    return AuthDeps(store=KeyringCredentialStore(), client=GithubOAuthClient(settings.github_client_id))


def with_github_token(settings: Settings, token: str) -> Settings:
    """Return settings that carry `token`, so the adapter and the responsiveness check both see it."""
    return settings.model_copy(update={"github_token": token})


def file_token(path: Path) -> str | None:
    """Return the token a dotenv-style config file sets, if any."""
    values = dotenv_values(path)
    return values.get("OSSIQ_GITHUB_TOKEN") or values.get("GITHUB_TOKEN") or None


def find_token_source(settings: Settings, environ: Mapping[str, str]) -> TokenSource | None:
    """Work out where `settings.github_token` came from.

    `Settings` merges the CLI flag, the environment and both config files into one value, so the
    source is found by matching that value against each place in precedence order. A value that
    matches none of them was passed on the command line, or in a `--config` file.

    Args:
        settings: Settings as loaded.
        environ: The process environment.

    Returns:
        The winning source, or None when the settings hold no token.
    """
    token = settings.github_token
    if not token:
        return None
    if environ.get("OSSIQ_GITHUB_TOKEN") == token:
        return TokenSource.ENV_OSSIQ
    if environ.get("GITHUB_TOKEN") == token:
        return TokenSource.ENV_GITHUB_TOKEN
    if file_token(settings_module.CONFIG_PATH) == token:
        return TokenSource.CONFIG_FILE
    if file_token(settings_module.LEGACY_CONFIG_PATH) == token:
        return TokenSource.LEGACY_CONFIG_FILE
    return TokenSource.CLI_FLAG


def offline_reason(settings: Settings, environ: Mapping[str, str]) -> AuthSkipReason | None:
    """Return why the keyring and the login flow must be left alone, if they must."""
    if settings.github_auth is GithubAuthMode.OFF:
        return AuthSkipReason.DISABLED
    if environ.get("CI", "").strip().lower() not in ("", "0", "false"):
        return AuthSkipReason.CI
    return None


def keep_current(
    settings: Settings, source: TokenSource | None, reason: AuthSkipReason, detail: str = ""
) -> GithubAuthResult:
    """Carry on with the token the settings already hold, or without one, saying why."""
    if source is not None:
        return GithubAuthResult(settings, source)
    return GithubAuthResult(settings, None, reason, detail)


def authenticate_github(
    settings: Settings,
    deps: AuthDeps | None = None,
    *,
    interactive: bool,
    on_challenge: Callable[[DeviceChallenge], None] | None = None,
    poll_pending: bool = True,
    skip_login: AuthSkipReason | None = None,
) -> GithubAuthResult:
    """Resolve the GitHub token a scan runs with, logging in when none exists.

    Precedence: an explicit token (`--github-token`, `OSSIQ_GITHUB_TOKEN`, `GITHUB_TOKEN`), then the
    keyring login, then a token in a config file. With none of them a device-flow login is offered,
    unless that is switched off, `CI` is set, or the keyring cannot be used: the scan then runs
    unauthenticated and `skipped` says why.

    Args:
        settings: Settings as loaded.
        deps: Store, client and clock; the real ones when omitted.
        interactive: Whether a person is at a terminal. True blocks until the login is approved;
            False raises GithubAuthRequired instead.
        on_challenge: Called with the challenge before an interactive wait, for the front door to show.
        poll_pending: Whether to check a pending login for approval. A process that polls elsewhere
            passes False.
        skip_login: When set, never offer a login and report this reason instead. A long-lived
            process passes it after a login was denied or expired, so it does not ask again.

    Returns:
        The settings to scan with, and where their token came from.

    Raises:
        GithubAuthRequired: A login is needed and `interactive` is False.
    """
    deps = deps or default_deps(settings)
    source = find_token_source(settings, deps.environ)
    if source in EXPLICIT_SOURCES:
        return GithubAuthResult(settings, source)
    reason = offline_reason(settings, deps.environ)
    if reason is not None:
        return keep_current(settings, source, reason)
    try:
        credentials = deps.store.read_credentials()
        usable = ensure_usable(credentials, deps) if credentials is not None else None
    except CredentialStoreUnavailable as error:
        return keep_current(settings, source, AuthSkipReason.STORE_UNAVAILABLE, str(error))
    if usable is not None:
        return GithubAuthResult(with_github_token(settings, usable.access_token), TokenSource.KEYRING)
    if source is not None:
        return GithubAuthResult(settings, source)
    if skip_login is not None:
        return GithubAuthResult(settings, None, skip_login)
    return offer_login(settings, deps, interactive=interactive, on_challenge=on_challenge, poll_pending=poll_pending)


def ensure_usable(credentials: GithubCredentials, deps: AuthDeps) -> GithubCredentials | None:
    """Refresh stored credentials that are due, and check GitHub still accepts them.

    Returns:
        Credentials fit to use, or None once they are discarded.
    """
    if credentials.needs_refresh(deps.now()):
        refreshed = refresh_credentials(credentials, deps, rejected=False)
        if refreshed is None:
            return None
        credentials = refreshed
    return validate_credentials(credentials, deps)


def validate_credentials(credentials: GithubCredentials, deps: AuthDeps) -> GithubCredentials | None:
    """Ask GitHub whether it still accepts the token, at most once per VALIDATION_TTL_SECONDS.

    A token revoked on github.com looks fine locally, so the stored expiry alone cannot tell.
    """
    token = credentials.access_token
    checked_at = deps.validated.get(token)
    if checked_at is not None and deps.now() - checked_at < VALIDATION_TTL_SECONDS:
        return credentials
    outcome = deps.client.fetch_login(token)
    if isinstance(outcome, str):
        deps.validated[token] = deps.now()
        return credentials
    if outcome.code is OAuthErrorCode.UNAUTHORIZED:
        return refresh_credentials(credentials, deps, rejected=True)
    return credentials  # GitHub could not be reached; the token may well still work


def refresh_credentials(credentials: GithubCredentials, deps: AuthDeps, *, rejected: bool) -> GithubCredentials | None:
    """Swap credentials for fresh ones, or discard them when GitHub will not.

    Refresh tokens are single-use, so a refusal may mean another process refreshed first. The store
    is read again before anything is deleted, and whatever it now holds is adopted.

    Args:
        credentials: The stored credentials.
        deps: Store, client and clock.
        rejected: Whether GitHub already refused the access token, rather than it merely being due.

    Returns:
        The new credentials, which are saved. The old ones when GitHub could not be reached and they
        have not expired. None when nothing usable remains.
    """
    now = deps.now()
    still_valid = not rejected and (credentials.expires_at is None or now < credentials.expires_at)
    if credentials.refresh_token is None:
        if still_valid:
            return credentials
        deps.store.delete_credentials()
        return None
    result = deps.client.refresh(credentials.refresh_token)
    if isinstance(result, GithubCredentials):
        save_refreshed(result, deps)
        deps.validated[result.access_token] = now
        return result
    if result.code in TRANSIENT_FAILURES:
        return credentials if still_valid else None
    current = deps.store.read_credentials()
    if current is not None and current != credentials:
        return current
    deps.store.delete_credentials()
    return None


def save_refreshed(credentials: GithubCredentials, deps: AuthDeps) -> None:
    """Store refreshed credentials; if that fails, the run can still use them."""
    try:
        deps.store.write_credentials(credentials)
    except CredentialStoreUnavailable:
        logger.warning("Could not save the refreshed GitHub login to the system keyring; it is used for this run only")


def offer_login(
    settings: Settings,
    deps: AuthDeps,
    *,
    interactive: bool,
    on_challenge: Callable[[DeviceChallenge], None] | None,
    poll_pending: bool,
) -> GithubAuthResult:
    """Finish a pending login, or start one and wait for it or hand it to the caller."""
    polled_just_now = False
    try:
        if poll_pending:
            try:
                resumed = resume_login(deps)
            except GithubAuthTimeout:
                resumed = None  # the pending code expired; a fresh one is requested below
            except GithubAuthDenied:
                return GithubAuthResult(settings, None, AuthSkipReason.LOGIN_DENIED)
            if isinstance(resumed, GithubCredentials):
                return GithubAuthResult(with_github_token(settings, resumed.access_token), TokenSource.KEYRING)
            polled_just_now = resumed is not None
        challenge = begin_login(deps)
    except CredentialStoreUnavailable as error:
        return GithubAuthResult(settings, None, AuthSkipReason.STORE_UNAVAILABLE, str(error))
    if isinstance(challenge, OAuthFailure):
        detail = challenge.description or challenge.error or challenge.code.value
        return GithubAuthResult(settings, None, AuthSkipReason.LOGIN_UNAVAILABLE, detail)
    if not interactive:
        raise GithubAuthRequired(challenge)
    if on_challenge is not None:
        on_challenge(challenge)
    try:
        credentials = await_login(challenge, deps, polled_just_now=polled_just_now)
    except GithubAuthDenied:
        return GithubAuthResult(settings, None, AuthSkipReason.LOGIN_DENIED)
    except GithubAuthTimeout as error:
        return GithubAuthResult(settings, None, AuthSkipReason.LOGIN_EXPIRED, str(error))
    except CredentialStoreUnavailable as error:
        return GithubAuthResult(settings, None, AuthSkipReason.STORE_UNAVAILABLE, str(error))
    return GithubAuthResult(with_github_token(settings, credentials.access_token), TokenSource.KEYRING)


def begin_login(deps: AuthDeps) -> DeviceChallenge | OAuthFailure:
    """Start a login, or return the one already pending so no second code is requested.

    The store is checked first: a login approved while its token cannot be saved is wasted.

    Returns:
        The challenge to show the user, or why GitHub would not issue one.

    Raises:
        CredentialStoreUnavailable: The keyring cannot hold the login.
    """
    if not deps.store.available():
        raise CredentialStoreUnavailable("The system keyring cannot hold a GitHub login on this machine.")
    pending = deps.store.read_pending()
    if pending is not None and pending.seconds_left(deps.now()) > 0:
        return pending
    challenge = deps.client.request_device_code()
    if isinstance(challenge, OAuthFailure):
        return challenge
    deps.store.write_pending(challenge)
    return challenge


def resume_login(deps: AuthDeps) -> GithubCredentials | DeviceChallenge | None:
    """Check once whether the pending login has been approved.

    Returns:
        The credentials, saved, once approved. The challenge while it is still waiting. None when no
        login is pending.

    Raises:
        GithubAuthDenied: The user cancelled the login.
        GithubAuthTimeout: The code expired or GitHub no longer accepts it.
    """
    pending = deps.store.read_pending()
    if pending is None:
        return None
    if pending.seconds_left(deps.now()) == 0:
        deps.store.delete_pending()
        raise GithubAuthTimeout("The login code expired before it was approved.")
    credentials = settle_poll(deps.client.poll_once(pending, pending.interval), deps)
    return credentials if credentials is not None else pending


def await_login(challenge: DeviceChallenge, deps: AuthDeps, *, polled_just_now: bool = False) -> GithubCredentials:
    """Poll until the user approves the login, then save the credentials.

    Args:
        challenge: The login being waited on.
        deps: Store, client and clock.
        polled_just_now: Whether the caller already polled, so one interval must pass first:
            GitHub answers back-to-back polls with `slow_down`.

    Raises:
        GithubAuthDenied: The user cancelled the login.
        GithubAuthTimeout: The code expired, or GitHub no longer accepts it.
        CredentialStoreUnavailable: The approved token could not be saved.
    """
    interval = challenge.interval
    if polled_just_now:
        deps.sleep(interval)
    while True:
        if challenge.seconds_left(deps.now()) == 0:
            deps.store.delete_pending()
            raise GithubAuthTimeout("The login code expired before it was approved.")
        result = deps.client.poll_once(challenge, interval)
        if isinstance(result, OAuthFailure) and result.interval is not None:
            interval = result.interval
        credentials = settle_poll(result, deps)
        if credentials is not None:
            return credentials
        deps.sleep(interval)


def settle_poll(result: GithubCredentials | OAuthFailure, deps: AuthDeps) -> GithubCredentials | None:
    """Act on one poll: save an approval, end the login on a refusal, or say keep waiting.

    Returns:
        The saved credentials, or None when the login is still waiting.
    """
    if isinstance(result, GithubCredentials):
        deps.store.write_credentials(result)
        deps.store.delete_pending()
        return result
    if result.code in TRANSIENT_FAILURES or result.code in (
        OAuthErrorCode.AUTHORIZATION_PENDING,
        OAuthErrorCode.SLOW_DOWN,
    ):
        return None
    deps.store.delete_pending()
    if result.code is OAuthErrorCode.ACCESS_DENIED:
        raise GithubAuthDenied("The login was cancelled on GitHub.")
    if result.code is OAuthErrorCode.EXPIRED_TOKEN:
        raise GithubAuthTimeout("The login code expired before it was approved.")
    raise GithubAuthTimeout(f"GitHub rejected the login code: {result.description or result.error}")


def github_auth_status(settings: Settings, deps: AuthDeps | None = None) -> AuthStatus:
    """Describe the token in use and what is known about it, changing nothing.

    `legacy_config_in_use` is true when the legacy config file holds a token, whether or not it wins.
    """
    deps = deps or default_deps(settings)
    source = find_token_source(settings, deps.environ)
    legacy = file_token(settings_module.LEGACY_CONFIG_PATH) is not None
    token = settings.github_token
    credentials = None
    backend = None
    if source not in EXPLICIT_SOURCES and offline_reason(settings, deps.environ) is None:
        backend = deps.store.backend_name()
        try:
            credentials = deps.store.read_credentials()
        except CredentialStoreUnavailable:
            credentials = None
        if credentials is not None:
            source, token = TokenSource.KEYRING, credentials.access_token
    login = deps.client.fetch_login(token) if token else None
    return AuthStatus(
        source=source,
        login=login if isinstance(login, str) else None,
        scope=credentials.scope if credentials is not None else None,
        expires_at=credentials.expires_at if credentials is not None else None,
        backend=backend,
        legacy_config_in_use=legacy,
    )


def logout_github(settings: Settings, deps: AuthDeps | None = None) -> TokenSource | None:
    """Delete the stored login and any pending one.

    Only local state is removed; GitHub lists the authorization until it is revoked there.

    Returns:
        The source that still supplies a token afterwards, such as an environment variable or a
        config file, or None.

    Raises:
        CredentialStoreUnavailable: The keyring cannot be used.
    """
    deps = deps or default_deps(settings)
    deps.store.delete_credentials()
    deps.store.delete_pending()
    return find_token_source(settings, deps.environ)
