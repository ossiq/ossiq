"""
System-keyring storage for the GitHub login: the OAuth tokens, and a login still in flight.

Every keyring call is bounded by a timeout, because an OS dialog nobody answers blocks the call
rather than failing it.
"""

import json
import logging
import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar, cast

import keyring
import keyring.errors

from ossiq.domain.exceptions import CredentialStoreUnavailable
from ossiq.domain.github_auth import DeviceChallenge, GithubCredentials

logger = logging.getLogger(__name__)

KEYRING_SERVICE = "dev.ossiq.github"
CREDENTIALS_ACCOUNT = "oauth_tokens"
PENDING_ACCOUNT = "device_pending"
KEYRING_TIMEOUT_SECONDS = 180.0
"""Long enough for a person to answer an OS dialog: a Keychain prompt after an upgrade, or a
Secret Service unlock."""

T = TypeVar("T")


@dataclass
class KeyringHealth:
    """Whether the keyring has stopped answering in this process.

    Shared by default: a call stuck in one store leaves the backend stuck for every other store, so
    the wait is paid once per process.
    """

    blocked: bool = False


PROCESS_HEALTH = KeyringHealth()


def describe_keyring_error(error: keyring.errors.KeyringError) -> str:
    """Say what went wrong in words for the user, not keyring's advice to install other backends."""
    if isinstance(error, keyring.errors.NoKeyringError):
        return "No system keyring is available on this machine."
    if isinstance(error, keyring.errors.KeyringLocked):
        return "The system keyring is locked, or access to it was refused."
    return f"The system keyring failed: {error}"


def select_backend() -> None:
    """Make keyring choose its backend now, so one that cannot start reads as an unavailable keyring.

    keyring chooses on first use. A backend named through `PYTHON_KEYRING_BACKEND` or `keyringrc.cfg` that
    cannot start raises a RuntimeError (its viability probe), or an ImportError, AttributeError or
    ValueError (a name that does not resolve), none of them a KeyringError.

    Raises:
        keyring.errors.InitError: The configured backend cannot start.
    """
    try:
        keyring.get_keyring()
    except (RuntimeError, ImportError, AttributeError, ValueError) as error:
        raise keyring.errors.InitError(f"cannot start the configured backend ({error})") from error


def encode_credentials(credentials: GithubCredentials) -> str:
    """Serialize credentials for storage."""
    return json.dumps(
        {
            "access_token": credentials.access_token,
            "refresh_token": credentials.refresh_token,
            "expires_at": credentials.expires_at,
            "scope": credentials.scope,
            "token_type": credentials.token_type,
        }
    )


def decode_credentials(raw: str) -> GithubCredentials | None:
    """Parse stored credentials, or return None when the payload is not usable."""
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    access_token = data.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        return None
    refresh_token = data.get("refresh_token")
    expires_at = data.get("expires_at")
    return GithubCredentials(
        access_token=access_token,
        refresh_token=refresh_token if isinstance(refresh_token, str) and refresh_token else None,
        expires_at=expires_at if isinstance(expires_at, int) and not isinstance(expires_at, bool) else None,
        scope=str(data.get("scope") or ""),
        token_type=str(data.get("token_type") or "bearer"),
    )


def encode_challenge(challenge: DeviceChallenge) -> str:
    """Serialize a pending login for storage."""
    return json.dumps(
        {
            "user_code": challenge.user_code,
            "verification_uri": challenge.verification_uri,
            "expires_at": challenge.expires_at,
            "interval": challenge.interval,
            "device_code": challenge.device_code,
        }
    )


def decode_challenge(raw: str) -> DeviceChallenge | None:
    """Parse a stored pending login, or return None when the payload is not usable."""
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    texts = [data.get(key) for key in ("user_code", "verification_uri", "device_code")]
    numbers = [data.get(key) for key in ("expires_at", "interval")]
    if not all(isinstance(text, str) and text for text in texts):
        return None
    if not all(isinstance(number, int) and not isinstance(number, bool) for number in numbers):
        return None
    return DeviceChallenge(
        user_code=data["user_code"],
        verification_uri=data["verification_uri"],
        expires_at=data["expires_at"],
        interval=data["interval"],
        device_code=data["device_code"],
    )


class KeyringCredentialStore:
    """The GitHub OAuth tokens and a login in flight, kept in the system keyring.

    Every method raises CredentialStoreUnavailable when the keyring cannot be used: absent, locked,
    refused, or silent for longer than the timeout. After one timeout the store stays unavailable
    for the rest of the process. A write replaces the entry in a single call, never delete-then-set.
    """

    def __init__(self, *, timeout: float = KEYRING_TIMEOUT_SECONDS, health: KeyringHealth = PROCESS_HEALTH):
        """Create a store.

        Args:
            timeout: Seconds to wait for one keyring call.
            health: Where a timeout is remembered; tests pass their own.
        """
        self.timeout = timeout
        self.health = health

    def read_credentials(self) -> GithubCredentials | None:
        """Return the stored credentials, or None when absent or unreadable."""
        raw = self.call(lambda: keyring.get_password(KEYRING_SERVICE, CREDENTIALS_ACCOUNT))
        if raw is None:
            return None
        credentials = decode_credentials(raw)
        if credentials is None:
            logger.warning("Ignoring an unreadable %s entry in the system keyring", CREDENTIALS_ACCOUNT)
        return credentials

    def write_credentials(self, credentials: GithubCredentials) -> None:
        """Store credentials, replacing any existing entry."""
        payload = encode_credentials(credentials)
        self.call(lambda: keyring.set_password(KEYRING_SERVICE, CREDENTIALS_ACCOUNT, payload))

    def delete_credentials(self) -> None:
        """Remove the stored credentials; nothing stored is not an error."""
        self.call(lambda: self.delete_entry(CREDENTIALS_ACCOUNT))

    def read_pending(self) -> DeviceChallenge | None:
        """Return the login in flight, or None when absent or unreadable."""
        raw = self.call(lambda: keyring.get_password(KEYRING_SERVICE, PENDING_ACCOUNT))
        if raw is None:
            return None
        challenge = decode_challenge(raw)
        if challenge is None:
            logger.warning("Ignoring an unreadable %s entry in the system keyring", PENDING_ACCOUNT)
        return challenge

    def write_pending(self, challenge: DeviceChallenge) -> None:
        """Store the login in flight, replacing any existing entry."""
        payload = encode_challenge(challenge)
        self.call(lambda: keyring.set_password(KEYRING_SERVICE, PENDING_ACCOUNT, payload))

    def delete_pending(self) -> None:
        """Remove the login in flight; nothing stored is not an error."""
        self.call(lambda: self.delete_entry(PENDING_ACCOUNT))

    def available(self) -> bool:
        """Report whether the keyring answers a real read.

        Choosing a backend says nothing about whether it works: on Linux one is picked even when it
        cannot create a collection, so only an actual read tells.
        """
        try:
            self.read_credentials()
        except CredentialStoreUnavailable:
            return False
        return True

    def backend_name(self) -> str | None:
        """Return the dotted class name of the keyring backend in use, or None when unavailable."""
        try:
            backend = self.call(keyring.get_keyring)
        except CredentialStoreUnavailable:
            return None
        return f"{type(backend).__module__}.{type(backend).__qualname__}"

    def delete_entry(self, account: str) -> None:
        """Delete one entry, treating an entry that was never there as deleted."""
        try:
            keyring.delete_password(KEYRING_SERVICE, account)
        except keyring.errors.PasswordDeleteError:
            # Backends raise this for a missing entry, but also for a refused delete.
            if keyring.get_password(KEYRING_SERVICE, account) is not None:
                raise

    def call(self, operation: Callable[[], T]) -> T:
        """Run one keyring operation on a daemon thread, bounded by the timeout.

        Raises:
            CredentialStoreUnavailable: The keyring failed, or did not answer in time.
        """
        if self.health.blocked:
            raise CredentialStoreUnavailable("The system keyring stopped answering earlier in this run.")

        outcome: queue.Queue[tuple[T | None, Exception | None]] = queue.Queue(maxsize=1)

        def run() -> None:
            try:
                select_backend()  # inside the timeout: probing a backend can wait on a prompt too
                outcome.put((operation(), None))
            except Exception as error:  # handed to the calling thread, which decides what it means
                outcome.put((None, error))

        # A daemon thread, so a call stuck on a dialog cannot keep the process from exiting.
        threading.Thread(target=run, daemon=True, name="ossiq-keyring").start()
        try:
            value, error = outcome.get(timeout=self.timeout)
        except queue.Empty:
            self.health.blocked = True
            raise CredentialStoreUnavailable(
                f"The system keyring did not answer within {self.timeout:g} seconds."
            ) from None
        if isinstance(error, keyring.errors.KeyringError):
            raise CredentialStoreUnavailable(describe_keyring_error(error)) from error
        if error is not None:
            raise error
        return cast(T, value)
