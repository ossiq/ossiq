"""Tests for adapters/credential_store.py, run against a scriptable in-memory keyring backend."""

import dataclasses
import json
import logging
import threading

import keyring
import keyring.backends.fail
import keyring.errors
import pytest

from ossiq.adapters.credential_store import (
    CREDENTIALS_ACCOUNT,
    KEYRING_SERVICE,
    KEYRING_TIMEOUT_SECONDS,
    PENDING_ACCOUNT,
    KeyringCredentialStore,
    KeyringHealth,
)
from ossiq.domain.exceptions import CredentialStoreUnavailable
from ossiq.domain.github_auth import DeviceChallenge, GithubCredentials

pytest_plugins = ["tests.adapters.keyring_fakes"]

CREDENTIALS = GithubCredentials(
    access_token="gho_SECRET_ACCESS",
    refresh_token="ghr_SECRET_REFRESH",
    expires_at=1_000_000,
    scope="",
    token_type="bearer",
)
CHALLENGE = DeviceChallenge(
    user_code="WDJB-4729",
    verification_uri="https://github.com/login/device",
    expires_at=1_000_900,
    interval=5,
    device_code="DEVICE_SECRET",
)


@pytest.fixture
def store(fake_keyring) -> KeyringCredentialStore:
    return KeyringCredentialStore(timeout=2.0, health=KeyringHealth())


class TestCredentials:
    def test_round_trip_keeps_every_field(self, store):
        store.write_credentials(CREDENTIALS)

        assert store.read_credentials() == CREDENTIALS

    def test_round_trip_of_a_token_with_no_expiry_or_refresh_token(self, store):
        plain = GithubCredentials(access_token="gho_plain")

        store.write_credentials(plain)

        assert store.read_credentials() == plain

    def test_absent_entry_reads_as_none(self, store):
        assert store.read_credentials() is None

    def test_lives_under_the_documented_service_and_account(self, store, fake_keyring):
        store.write_credentials(CREDENTIALS)

        assert list(fake_keyring.items) == [("dev.ossiq.github", "oauth_tokens")]
        assert (KEYRING_SERVICE, CREDENTIALS_ACCOUNT) == ("dev.ossiq.github", "oauth_tokens")

    def test_stored_payload_has_the_adr_shape(self, store, fake_keyring):
        store.write_credentials(CREDENTIALS)

        stored = json.loads(fake_keyring.items[(KEYRING_SERVICE, CREDENTIALS_ACCOUNT)])

        assert set(stored) == {"access_token", "refresh_token", "expires_at", "scope", "token_type"}

    def test_writing_again_replaces_the_entry_in_one_call(self, store, fake_keyring):
        store.write_credentials(CREDENTIALS)
        fake_keyring.calls.clear()

        store.write_credentials(dataclasses.replace(CREDENTIALS, access_token="gho_NEW"))

        assert fake_keyring.calls == ["set"]
        stored = store.read_credentials()
        assert stored is not None
        assert stored.access_token == "gho_NEW"

    def test_delete_removes_the_entry(self, store):
        store.write_credentials(CREDENTIALS)

        store.delete_credentials()

        assert store.read_credentials() is None

    def test_deleting_what_was_never_stored_is_not_an_error(self, store):
        store.delete_credentials()

    def test_a_refused_delete_is_reported_not_swallowed(self, store, fake_keyring):
        store.write_credentials(CREDENTIALS)
        fake_keyring.refuse_delete = True

        with pytest.raises(CredentialStoreUnavailable):
            store.delete_credentials()


class TestPendingLogin:
    def test_round_trip_keeps_the_device_code(self, store):
        store.write_pending(CHALLENGE)

        pending = store.read_pending()

        assert pending == CHALLENGE
        assert pending is not None
        assert pending.device_code == "DEVICE_SECRET"

    def test_lives_in_its_own_account_apart_from_the_tokens(self, store, fake_keyring):
        store.write_pending(CHALLENGE)

        assert list(fake_keyring.items) == [(KEYRING_SERVICE, PENDING_ACCOUNT)]
        assert PENDING_ACCOUNT == "device_pending"

    def test_delete_removes_only_the_pending_entry(self, store):
        store.write_credentials(CREDENTIALS)
        store.write_pending(CHALLENGE)

        store.delete_pending()

        assert store.read_pending() is None
        assert store.read_credentials() == CREDENTIALS

    def test_absent_entry_reads_as_none(self, store):
        assert store.read_pending() is None


class TestUnreadablePayloads:
    BAD = ["not json at all", "[]", "{}", '{"access_token": 5}', '{"access_token": ""}', "null"]

    @pytest.mark.parametrize("raw", BAD)
    def test_a_corrupt_credentials_entry_reads_as_absent(self, store, fake_keyring, raw):
        fake_keyring.items[(KEYRING_SERVICE, CREDENTIALS_ACCOUNT)] = raw

        assert store.read_credentials() is None
        assert store.available() is True

    @pytest.mark.parametrize("raw", [*BAD, '{"user_code": "A", "verification_uri": "u", "device_code": "d"}'])
    def test_a_corrupt_pending_entry_reads_as_absent(self, store, fake_keyring, raw):
        fake_keyring.items[(KEYRING_SERVICE, PENDING_ACCOUNT)] = raw

        assert store.read_pending() is None

    def test_a_corrupt_entry_is_replaced_by_the_next_write(self, store, fake_keyring):
        fake_keyring.items[(KEYRING_SERVICE, CREDENTIALS_ACCOUNT)] = "garbage"

        store.write_credentials(CREDENTIALS)

        assert store.read_credentials() == CREDENTIALS


class TestUnavailableKeyring:
    @pytest.mark.parametrize(
        "error",
        [
            keyring.errors.NoKeyringError("no backend"),
            keyring.errors.KeyringLocked("locked"),
            keyring.errors.InitError("could not create the collection"),
            keyring.errors.PasswordSetError("set failed"),
            keyring.errors.KeyringError("anything else"),
        ],
        ids=lambda error: type(error).__name__,
    )
    def test_every_keyring_error_becomes_credential_store_unavailable(self, store, fake_keyring, error):
        fake_keyring.fail_with = error

        with pytest.raises(CredentialStoreUnavailable) as raised:
            store.read_credentials()

        assert raised.value.__cause__ is error
        assert store.available() is False

    def test_the_message_does_not_advise_installing_a_plaintext_backend(self, store, fake_keyring):
        fake_keyring.fail_with = keyring.errors.NoKeyringError("Install the keyrings.alt package")

        with pytest.raises(CredentialStoreUnavailable) as raised:
            store.read_credentials()

        assert "keyrings.alt" not in str(raised.value)
        assert "No system keyring is available" in str(raised.value)

    def test_the_real_fail_backend_means_unavailable_and_is_named(self, store):
        keyring.set_keyring(keyring.backends.fail.Keyring())

        assert store.available() is False
        backend = store.backend_name()
        assert backend is not None
        assert backend.endswith("fail.Keyring")

    def test_an_unexpected_error_is_not_hidden(self, store, fake_keyring):
        fake_keyring.fail_with = RuntimeError("a bug, not a keyring state")

        with pytest.raises(RuntimeError, match="a bug"):
            store.read_credentials()

    def test_available_makes_a_real_read(self, store, fake_keyring):
        assert store.available() is True
        assert fake_keyring.calls == ["get"]


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("tests.adapters.keyring_fakes.UnstartableKeyring", id="cannot-start"),
        pytest.param("no_such_module_for_ossiq.Keyring", id="module-missing"),
        pytest.param("tests.adapters.keyring_fakes.NoSuchBackend", id="class-missing"),
        pytest.param("NoModuleInTheName", id="no-module-in-the-name"),
    ],
)
class TestNamedBackendThatCannotStart:
    """`PYTHON_KEYRING_BACKEND` or `keyringrc.cfg` can name a backend that cannot start.

    keyring reports that with errors that are not KeyringErrors, so it has to read as an unavailable
    keyring, not a crash.
    """

    @pytest.fixture
    def store(self, name, named_backend) -> KeyringCredentialStore:
        named_backend(name)
        return KeyringCredentialStore(timeout=2.0, health=KeyringHealth())

    def test_every_keyring_call_reads_as_unavailable(self, store):
        calls = [
            store.read_credentials,
            lambda: store.write_credentials(CREDENTIALS),
            store.delete_credentials,
            store.read_pending,
            lambda: store.write_pending(CHALLENGE),
            store.delete_pending,
        ]

        for call in calls:
            with pytest.raises(CredentialStoreUnavailable):
                call()

    def test_the_store_is_unavailable_and_has_no_backend_name(self, store):
        assert store.available() is False
        assert store.backend_name() is None

    def test_the_message_says_the_configured_backend_cannot_start(self, store):
        with pytest.raises(CredentialStoreUnavailable, match="cannot start the configured backend"):
            store.read_credentials()


class TestSilentKeyring:
    def blocked_store(self, fake_keyring, health: KeyringHealth) -> KeyringCredentialStore:
        fake_keyring.block = threading.Event()
        return KeyringCredentialStore(timeout=0.05, health=health)

    def test_a_call_that_never_answers_times_out(self, fake_keyring):
        store = self.blocked_store(fake_keyring, KeyringHealth())

        with pytest.raises(CredentialStoreUnavailable, match="did not answer within 0.05 seconds"):
            store.read_credentials()

    def test_after_one_timeout_later_calls_fail_at_once_without_reaching_the_backend(self, fake_keyring):
        store = self.blocked_store(fake_keyring, KeyringHealth())
        with pytest.raises(CredentialStoreUnavailable):
            store.read_credentials()
        calls_so_far = list(fake_keyring.calls)

        with pytest.raises(CredentialStoreUnavailable, match="earlier in this run"):
            store.write_credentials(CREDENTIALS)

        assert fake_keyring.calls == calls_so_far
        assert store.available() is False
        assert store.backend_name() is None

    def test_the_wait_is_shared_by_every_store_using_the_same_health(self, fake_keyring):
        health = KeyringHealth()
        first = self.blocked_store(fake_keyring, health)
        with pytest.raises(CredentialStoreUnavailable):
            first.read_credentials()
        calls_so_far = list(fake_keyring.calls)

        with pytest.raises(CredentialStoreUnavailable, match="earlier in this run"):
            KeyringCredentialStore(timeout=0.05, health=health).read_credentials()

        assert fake_keyring.calls == calls_so_far

    def test_a_store_with_its_own_health_is_unaffected(self, fake_keyring):
        blocked_health = KeyringHealth()
        with pytest.raises(CredentialStoreUnavailable):
            self.blocked_store(fake_keyring, blocked_health).read_credentials()
        assert fake_keyring.block is not None
        fake_keyring.block.set()

        assert KeyringCredentialStore(timeout=2.0, health=KeyringHealth()).available() is True

    def test_the_stuck_call_cannot_keep_the_process_alive(self, fake_keyring):
        store = self.blocked_store(fake_keyring, KeyringHealth())
        with pytest.raises(CredentialStoreUnavailable):
            store.read_credentials()

        workers = [thread for thread in threading.enumerate() if thread.name == "ossiq-keyring"]

        assert workers
        assert all(worker.daemon for worker in workers)

    def test_the_default_timeout_leaves_a_person_time_to_answer_a_dialog(self):
        assert KEYRING_TIMEOUT_SECONDS == 180.0


class TestBackendName:
    def test_names_the_backend_in_use(self, store):
        assert store.backend_name() == "tests.adapters.keyring_fakes.FakeKeyring"


def test_nothing_secret_is_logged(store, fake_keyring, caplog):
    caplog.set_level(logging.DEBUG)
    store.write_credentials(CREDENTIALS)
    store.write_pending(CHALLENGE)
    store.read_credentials()
    store.read_pending()
    fake_keyring.items[(KEYRING_SERVICE, CREDENTIALS_ACCOUNT)] = "corrupt but holding gho_SECRET_ACCESS"
    store.read_credentials()

    assert "SECRET" not in caplog.text
    assert "unreadable" in caplog.text
