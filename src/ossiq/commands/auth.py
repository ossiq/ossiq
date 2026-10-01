"""`ossiq auth` commands, and the GitHub login that runs ahead of a scan."""

import threading
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass

import typer

import ossiq.settings as settings_module
from ossiq.adapters.credential_store import KEYRING_TIMEOUT_SECONDS
from ossiq.clients.client_github_oauth import OAuthFailure
from ossiq.domain.exceptions import CredentialStoreUnavailable, GithubAuthRequired
from ossiq.domain.github_auth import DeviceChallenge, GithubCredentials, TokenSource
from ossiq.service.github_auth import (
    AuthDeps,
    authenticate_github,
    await_login,
    begin_login,
    default_deps,
    file_token,
    find_token_source,
    github_auth_status,
    logout_github,
    resume_login,
)
from ossiq.settings import Settings
from ossiq.ui import auth as auth_ui
from ossiq.ui.system import describe_token_source, is_interactive, show_error

EXIT_LOGIN_PENDING = 75
"""Exit status when a login was started but not yet approved (EX_TEMPFAIL). The command is meant to be re-run."""


KEYCHAIN_NOTICE_DELAY_SECONDS = 2.0
"""How long the keyring may stay silent before the user is told why."""


@dataclass(frozen=True)
class CommandAuthLoginOptions:
    no_wait: bool = False
    resume: bool = False


@contextmanager
def keychain_wait_notice(delay: float | None = None) -> Generator[threading.Timer]:
    """Say why nothing is happening when the keyring takes long to answer.

    An OS dialog, such as a Keychain prompt after an upgrade, can hold a call for minutes in silence.
    The yielded timer can be cancelled once the wait is over or no longer the keyring's.

    Args:
        delay: Seconds of silence before the notice; KEYCHAIN_NOTICE_DELAY_SECONDS when omitted.
    """
    seconds = KEYCHAIN_NOTICE_DELAY_SECONDS if delay is None else delay
    timer = threading.Timer(seconds, auth_ui.show_keychain_wait, args=(KEYRING_TIMEOUT_SECONDS,))
    timer.daemon = True
    timer.start()
    try:
        yield timer
    finally:
        timer.cancel()


def resolve_github_login(context: typer.Context) -> None:
    """Get the GitHub token a scan is about to need, logging in first when there is none.

    Replaces `context.obj` with settings that carry the token. A login is approved on GitHub in a
    browser: with a terminal this waits for it, without one it prints the code and exits with
    EXIT_LOGIN_PENDING so the command can be re-run after approval.

    Args:
        context: The command's context; its `obj` holds the loaded settings.

    Raises:
        typer.Exit: With EXIT_LOGIN_PENDING, when a login has to be approved first.
    """
    settings: Settings = context.obj
    deps = default_deps(settings)
    announced: list[DeviceChallenge] = []

    with keychain_wait_notice() as notice:

        def announce(challenge: DeviceChallenge) -> None:
            notice.cancel()  # from here the wait is the person's, not the keyring's
            announced.append(challenge)
            auth_ui.show_login_challenge(challenge, now=deps.now(), waiting=True, err=True)

        try:
            result = authenticate_github(settings, deps, interactive=is_interactive(), on_challenge=announce)
        except GithubAuthRequired as required:
            auth_ui.show_login_challenge(required.challenge, now=deps.now(), waiting=False, err=True)
            raise typer.Exit(EXIT_LOGIN_PENDING) from None
    if result.skipped is not None:
        auth_ui.show_auth_skipped(result.skipped, result.detail)
    if announced and result.settings.github_token:
        login = deps.client.fetch_login(result.settings.github_token)
        auth_ui.show_login_success(login if isinstance(login, str) else None, deps.store.backend_name(), err=True)
    if settings.verbose and result.source is TokenSource.KEYRING:
        auth_ui.emit(f"github_token: set ({describe_token_source(TokenSource.KEYRING)})", err=True)
    context.obj = result.settings


def command_auth_login(ctx: typer.Context, options: CommandAuthLoginOptions) -> None:
    """Log in to GitHub with a one-time code, or pick up a login already in progress."""
    deps = default_deps(ctx.obj)
    interactive = is_interactive() and not options.no_wait
    with keychain_wait_notice():
        if options.resume:
            challenge = resume_pending(deps)
            if challenge is None:
                return
        else:
            if already_logged_in(deps):
                return
            started = begin_login(deps)
            if isinstance(started, OAuthFailure):
                show_error(
                    started.description or started.error or started.code.value,
                    title="GitHub Login Unavailable",
                    hint="Check your connection and run `ossiq auth login` again.",
                )
                raise typer.Exit(1)
            challenge = started
    auth_ui.show_login_challenge(challenge, now=deps.now(), waiting=interactive, err=False)
    if not interactive:
        raise typer.Exit(EXIT_LOGIN_PENDING)
    finish_login(deps, await_login(challenge, deps, polled_just_now=options.resume))


def resume_pending(deps: AuthDeps) -> DeviceChallenge | None:
    """Check a login in progress once, finishing it when approved.

    Returns:
        The challenge while it is still waiting for approval, otherwise None.

    Raises:
        typer.Exit: When there is no login in progress.
    """
    outcome = resume_login(deps)
    if outcome is None:
        show_error("No GitHub login is in progress.", title="Nothing To Resume", hint="Run `ossiq auth login`.")
        raise typer.Exit(1)
    if isinstance(outcome, GithubCredentials):
        finish_login(deps, outcome)
        return None
    return outcome


def already_logged_in(deps: AuthDeps) -> bool:
    """Say so and return True when the stored login still works, so a second one is not started."""
    credentials = deps.store.read_credentials()
    if credentials is None:
        return False
    login = deps.client.fetch_login(credentials.access_token)
    if not isinstance(login, str):
        return False
    auth_ui.show_already_logged_in(login)
    return True


def finish_login(deps: AuthDeps, credentials: GithubCredentials) -> None:
    """Report a completed login, and any plaintext token it makes unnecessary."""
    login = deps.client.fetch_login(credentials.access_token)
    auth_ui.show_login_success(login if isinstance(login, str) else None, deps.store.backend_name(), err=False)
    if file_token(settings_module.LEGACY_CONFIG_PATH) is not None:
        auth_ui.show_legacy_token_note()


def command_auth_status(ctx: typer.Context) -> None:
    """Show which GitHub token is in use, where it came from and who it belongs to."""
    deps = default_deps(ctx.obj)
    with keychain_wait_notice():
        status = github_auth_status(ctx.obj, deps)
    auth_ui.show_auth_status(status, now=deps.now())


def command_auth_logout(ctx: typer.Context) -> None:
    """Remove the stored GitHub login and say what, if anything, still supplies a token."""
    settings: Settings = ctx.obj
    deps = default_deps(settings)
    try:
        with keychain_wait_notice():
            remaining = logout_github(settings, deps)
    except CredentialStoreUnavailable as error:
        remaining = find_token_source(settings, deps.environ)
        auth_ui.show_logout(removed=False, remaining=remaining, reason=str(error))
        return
    auth_ui.show_logout(removed=True, remaining=remaining)
