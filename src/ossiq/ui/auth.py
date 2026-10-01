"""
Presentation for the GitHub login: the challenge, the outcome of a login, `auth status` and `auth logout`.

The scan front door prints on stderr so piped output stays clean; the `auth` commands print on stdout,
where their output is the payload. Everything is plain text: a URL or a one-time code must survive any
terminal, and an agent reading the output back.
"""

import sys
from datetime import UTC, datetime

from ossiq.domain.github_auth import AuthStatus, DeviceChallenge, TokenSource
from ossiq.service.github_auth import AuthSkipReason
from ossiq.ui.system import RICH_AVAILABLE, console, describe_token_source, error_console, show_warning

BACKEND_LABELS = {
    "keyring.backends.macOS.Keyring": "macOS Keychain",
    "keyring.backends.Windows.WinVaultKeyring": "Windows Credential Manager",
    "keyring.backends.SecretService.Keyring": "Secret Service (the desktop keyring)",
    "keyring.backends.kwallet.DBusKeyring": "KWallet",
    "keyring.backends.fail.Keyring": "none available",
}

SKIP_MESSAGES = {
    AuthSkipReason.STORE_UNAVAILABLE: (
        "GitHub login skipped: {detail} Continuing without a token (60 requests/hour). "
        "To use a token without the system keyring, set OSSIQ_GITHUB_TOKEN."
    ),
    AuthSkipReason.LOGIN_DENIED: (
        "The GitHub login was cancelled. Continuing without a token (60 requests/hour); "
        "run `ossiq auth login` to try again."
    ),
    AuthSkipReason.LOGIN_EXPIRED: (
        "The GitHub login code expired. Continuing without a token (60 requests/hour); "
        "run `ossiq auth login` for a new code."
    ),
    AuthSkipReason.LOGIN_UNAVAILABLE: (
        "Could not start the GitHub login ({detail}). Continuing without a token (60 requests/hour)."
    ),
}
"""Reasons worth a warning. `DISABLED` and `CI` are the user's own choice and stay silent."""

REVOKE_URL = "https://github.com/settings/applications"


def emit(text: str, *, err: bool = False) -> None:
    """Print text unstyled and unwrapped."""
    stream = error_console if err else console
    if RICH_AVAILABLE and stream is not None:
        stream.print(text, markup=False, highlight=False, soft_wrap=True)
    else:
        print(text, file=sys.stderr if err else sys.stdout)


def describe_backend(backend: str | None) -> str:
    """Name a keyring backend the way a person would."""
    if backend is None:
        return "unavailable"
    return BACKEND_LABELS.get(backend, backend)


def format_expiry(expires_at: int | None, now: float) -> str:
    """Show when an access token expires."""
    if expires_at is None:
        return "never"
    when = datetime.fromtimestamp(expires_at, UTC).strftime("%Y-%m-%d %H:%M UTC")
    return f"{when} (expired)" if expires_at <= now else when


def show_login_challenge(challenge: DeviceChallenge, *, now: float, waiting: bool, err: bool) -> None:
    """Tell the user where to go and what to type to approve the login.

    Args:
        challenge: The login to approve. Its device code is never shown.
        now: The current time, in epoch seconds.
        waiting: Whether this process keeps waiting for the approval, or exits until it is re-run.
        err: Print on stderr (a scan in progress) rather than stdout (`ossiq auth login`).
    """
    minutes = challenge.seconds_left(now) // 60
    expires = f"{minutes} minutes" if minutes >= 1 else "less than a minute"
    lines = [
        "GitHub login needed to raise the API limit from 60 to 5,000 requests/hour.",
        f"  1. Open:  {challenge.verification_uri}",
        f"  2. Enter the code:  {challenge.user_code}",
        f"  The code expires in {expires}.",
    ]
    if waiting:
        lines.append("Waiting for approval... (Ctrl-C to stop; `ossiq auth login --resume` picks it up again)")
    else:
        lines.append("Approve it on GitHub, then run the command again (or `ossiq auth login --resume`).")
    emit("\n".join(lines), err=err)


def show_login_success(login: str | None, backend: str | None, *, err: bool) -> None:
    """Confirm a completed login and where its token is kept."""
    who = f"as @{login}" if login else "to GitHub"
    emit(f"✓ Logged in {who}. The token is stored in the system keyring ({describe_backend(backend)}).", err=err)


def show_keychain_wait(give_up_after: float) -> None:
    """Explain a long silence: the system keyring may be waiting on a dialog nobody has answered."""
    emit(
        "Waiting for the system keyring... If a dialog asked for access, approve it "
        f"(ossiq gives up after {give_up_after / 60:g} minutes).",
        err=True,
    )


def show_already_logged_in(login: str) -> None:
    """Say there is nothing to do because a working login already exists."""
    emit(f"Already logged in to GitHub as @{login}. Run `ossiq auth logout` first to log in as someone else.")


def show_legacy_token_note() -> None:
    """Point out a plaintext token left in the legacy config file, which a login makes unnecessary."""
    emit(
        "Note: a GitHub token is still stored in plaintext in ~/.ossiq/config. The login above replaces it, "
        "so you can delete that line (or the file); ossiq never edits it for you."
    )


def show_auth_skipped(reason: AuthSkipReason, detail: str) -> None:
    """Warn that a scan runs without a GitHub token, when the reason is not the user's own choice."""
    template = SKIP_MESSAGES.get(reason)
    if template is not None:
        show_warning(template.format(detail=detail.strip() or reason.value))


def show_auth_status(status: AuthStatus, *, now: float) -> None:
    """Print which GitHub token is in use and what is known about it."""
    lines = ["GitHub token"]
    if status.source is None:
        lines.append("  Not logged in. Run `ossiq auth login` to raise the API limit from 60 to 5,000 requests/hour.")
    else:
        lines.append(f"  Source:   {describe_token_source(status.source)}")
        lines.append(f"  Login:    {'@' + status.login if status.login else 'unknown (GitHub did not confirm it)'}")
        if status.source is TokenSource.KEYRING:
            scope = "none (public data only)" if status.scope == "" else status.scope or "unknown"
            lines.append(f"  Scope:    {scope}")
            lines.append(f"  Expires:  {format_expiry(status.expires_at, now)}")
    lines.append(f"  Storage:  {describe_backend(status.backend)}")
    if status.legacy_config_in_use:
        lines.append(
            "  Warning:  a token is stored in plaintext in ~/.ossiq/config (legacy location); delete it once "
            "you no longer need it."
        )
    emit("\n".join(lines))


def show_logout(*, removed: bool, remaining: TokenSource | None, reason: str = "") -> None:
    """Report what logging out did, and what still gives scans a token."""
    if removed:
        emit("Logged out: the stored GitHub login was removed from this machine.")
        emit(f"GitHub still lists the authorization. To revoke it, open {REVOKE_URL} and remove 'OSS IQ'.")
    else:
        emit(f"Nothing to remove: {reason}".rstrip())
    if remaining is not None:
        emit(f"A token from {describe_token_source(remaining)} is still in use, so scans keep running authenticated.")
