"""
A scriptable in-memory keyring backend, so no test ever touches the real keychain.

A pytest plugin module: a suite opts in with `pytest_plugins = ["tests.adapters.keyring_fakes"]` and
asks for the `fake_keyring` fixture.
"""

import threading

import keyring
import keyring.backend
import keyring.core
import keyring.errors
import pytest
from jaraco.classes import properties

BLOCK_LIMIT_SECONDS = 30.0
"""How long a blocked call waits for its event before giving up, so a forgotten release cannot hang a run."""


class FakeKeyring(keyring.backend.KeyringBackend):
    """In-memory keyring that can fail, or block like an unanswered OS dialog, on demand."""

    priority = 1

    def __init__(self) -> None:
        super().__init__()
        self.items: dict[tuple[str, str], str] = {}
        self.calls: list[str] = []
        self.fail_with: Exception | None = None
        """Raised by every call when set."""
        self.block: threading.Event | None = None
        """Makes every call wait until the event is set."""
        self.refuse_delete = False
        """Makes a delete fail while leaving the entry in place."""

    def gate(self, operation: str) -> None:
        self.calls.append(operation)
        if self.block is not None:
            self.block.wait(BLOCK_LIMIT_SECONDS)
        if self.fail_with is not None:
            raise self.fail_with

    def get_password(self, service: str, username: str) -> str | None:
        self.gate("get")
        return self.items.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.gate("set")
        self.items[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.gate("delete")
        if self.refuse_delete:
            raise keyring.errors.PasswordDeleteError("delete refused")
        if (service, username) not in self.items:
            raise keyring.errors.PasswordDeleteError("not found")
        del self.items[(service, username)]


class UnstartableKeyring(keyring.backend.KeyringBackend):
    """A backend that cannot start, the way Secret Service cannot without a D-Bus session.

    keyring reads `priority` when a backend is named, and a RuntimeError there means "not viable".
    """

    @properties.classproperty
    def priority(cls) -> float:
        raise RuntimeError("Unable to initialize the fake backend: there is nothing to talk to")

    def get_password(self, service: str, username: str) -> str | None:
        raise NotImplementedError

    def set_password(self, service: str, username: str, password: str) -> None:
        raise NotImplementedError

    def delete_password(self, service: str, username: str) -> None:
        raise NotImplementedError


@pytest.fixture
def fake_keyring():
    """Install a FakeKeyring as the process keyring for one test, then put the real one back."""
    backend = FakeKeyring()
    previous = keyring.get_keyring()
    keyring.set_keyring(backend)
    yield backend
    if backend.block is not None:
        backend.block.set()  # frees any worker still waiting on it
    keyring.set_keyring(previous)


@pytest.fixture
def named_backend(monkeypatch: pytest.MonkeyPatch):
    """Return a function that makes keyring choose the named backend next, as `PYTHON_KEYRING_BACKEND` does."""

    def choose(name: str) -> None:
        monkeypatch.setenv("PYTHON_KEYRING_BACKEND", name)
        monkeypatch.setattr(keyring.core, "_keyring_backend", None)  # forces a fresh choice

    return choose
