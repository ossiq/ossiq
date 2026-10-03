"""`ossiq auth` commands, and the GitHub login that runs ahead of a scan."""

from dataclasses import dataclass

import typer

from ossiq.domain.exceptions import CredentialStoreUnavailable, GithubAuthRequired, NoLoginInProgress
from ossiq.domain.github_auth import DeviceChallenge, GithubCredentials, TokenSource
from ossiq.service.github_auth import (
    AuthDeps,
    authenticate_github,
    await_login,
    begin_login,
    default_deps,
    find_token_source,
    github_auth_status,
    legacy_token_in_use,
    logout_github,
    resume_login,
    stored_login,
    summarize_login,
)
from ossiq.settings import Settings
from ossiq.ui import auth as auth_ui
from ossiq.ui.system import describe_token_source, is_interactive

EXIT_LOGIN_PENDING = 75
"""Exit status when a login was started but not yet approved (EX_TEMPFAIL). The command is meant to be re-run."""


@dataclass(frozen=True)
class CommandAuthLoginOptions:
    no_wait: bool = False
    resume: bool = False


def login_deps(settings: Settings) -> AuthDeps:
    """Build the login dependencies, with a keyring that is slow to answer explained on stderr."""
    return default_deps(settings, on_keyring_slow=auth_ui.show_keychain_wait)


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
    deps = login_deps(settings)

    def announce(challenge: DeviceChallenge) -> None:
        auth_ui.show_login_challenge(challenge, now=deps.now(), waiting=True, err=True)

    try:
        result = authenticate_github(settings, deps, interactive=is_interactive(), on_challenge=announce)
    except GithubAuthRequired as required:
        auth_ui.show_login_challenge(required.challenge, now=deps.now(), waiting=False, err=True)
        raise typer.Exit(EXIT_LOGIN_PENDING) from None
    if result.skipped is not None:
        auth_ui.show_auth_skipped(result.skipped, result.detail)
    if result.completed_login and result.settings.github_token:
        summary = summarize_login(result.settings.github_token, deps)
        auth_ui.show_login_success(summary.login, summary.backend, err=True)
    if settings.verbose and result.source is TokenSource.KEYRING:
        auth_ui.emit(f"github_token: set ({describe_token_source(TokenSource.KEYRING)})", err=True)
    context.obj = result.settings


def command_auth_login(ctx: typer.Context, options: CommandAuthLoginOptions) -> None:
    """Log in to GitHub with a one-time code, or pick up a login already in progress."""
    deps = login_deps(ctx.obj)
    interactive = is_interactive() and not options.no_wait
    if options.resume:
        challenge = resume_pending(deps)
        if challenge is None:
            return
    else:
        if already_logged_in(deps):
            return
        challenge = begin_login(deps)
    auth_ui.show_login_challenge(challenge, now=deps.now(), waiting=interactive, err=False)
    if not interactive:
        raise typer.Exit(EXIT_LOGIN_PENDING)
    finish_login(deps, await_login(challenge, deps, polled_just_now=options.resume))


def resume_pending(deps: AuthDeps) -> DeviceChallenge | None:
    """Check a login in progress once, finishing it when approved.

    Returns:
        The challenge while it is still waiting for approval, otherwise None.

    Raises:
        NoLoginInProgress: When there is no login in progress.
    """
    outcome = resume_login(deps)
    if outcome is None:
        raise NoLoginInProgress()
    if isinstance(outcome, GithubCredentials):
        finish_login(deps, outcome)
        return None
    return outcome


def already_logged_in(deps: AuthDeps) -> bool:
    """Say so and return True when the stored login still works, so a second one is not started."""
    login = stored_login(deps)
    if login is None:
        return False
    auth_ui.show_already_logged_in(login)
    return True


def finish_login(deps: AuthDeps, credentials: GithubCredentials) -> None:
    """Report a completed login, and any plaintext token it makes unnecessary."""
    summary = summarize_login(credentials.access_token, deps)
    auth_ui.show_login_success(summary.login, summary.backend, err=False)
    if legacy_token_in_use():
        auth_ui.show_legacy_token_note()


def command_auth_status(ctx: typer.Context) -> None:
    """Show which GitHub token is in use, where it came from and who it belongs to."""
    deps = login_deps(ctx.obj)
    auth_ui.show_auth_status(github_auth_status(ctx.obj, deps), now=deps.now())


def command_auth_logout(ctx: typer.Context) -> None:
    """Remove the stored GitHub login and say what, if anything, still supplies a token."""
    settings: Settings = ctx.obj
    deps = login_deps(settings)
    try:
        remaining = logout_github(settings, deps)
    except CredentialStoreUnavailable as error:
        remaining = find_token_source(settings, deps.environ)
        auth_ui.show_logout(removed=False, remaining=remaining, reason=str(error))
        return
    auth_ui.show_logout(removed=True, remaining=remaining)
