"""Tests for service/github_auth.py, run against a real local HTTP server and an in-memory keyring.

The clock and the sleep are injected, so nothing here really waits, the 15-minute timeout included.
"""

import dataclasses
import json

import keyring.errors
import pytest
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Response

import ossiq.settings
from ossiq.adapters.credential_store import KeyringCredentialStore, KeyringHealth
from ossiq.clients.client_github_oauth import GithubOAuthClient
from ossiq.domain.exceptions import (
    CredentialStoreUnavailable,
    GithubAuthDenied,
    GithubAuthRequired,
    GithubAuthTimeout,
)
from ossiq.domain.github_auth import DeviceChallenge, GithubCredentials, TokenSource
from ossiq.service.github_auth import (
    AuthDeps,
    AuthSkipReason,
    CredentialStore,
    authenticate_github,
    await_login,
    begin_login,
    find_token_source,
    github_auth_status,
    logout_github,
    resume_login,
)
from ossiq.settings import GithubAuthMode, Settings

pytest_plugins = ["tests.adapters.keyring_fakes"]

NOW = 1_000_000.0
DEVICE_PATH = "/login/device/code"
TOKEN_PATH = "/login/oauth/access_token"
DEVICE_BODY = {
    "device_code": "DEVICE-SECRET",
    "user_code": "WDJB-4729",
    "verification_uri": "https://github.com/login/device",
    "expires_in": 900,
    "interval": 5,
}
GRANTED = {"access_token": "gho_login", "refresh_token": "ghr_login", "expires_in": 28800, "scope": ""}
STORED = GithubCredentials(access_token="gho_stored", refresh_token="ghr_stored", expires_at=int(NOW) + 28800)
DUE = GithubCredentials(access_token="gho_due", refresh_token="ghr_due", expires_at=int(NOW) + 100)
SPENT_REFRESH = {"error": "incorrect_client_credentials", "error_description": "The client_id is incorrect."}


class FakeClock:
    def __init__(self) -> None:
        self.time = NOW
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.time

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.time += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def deps(httpserver: HTTPServer, fake_keyring, clock: FakeClock) -> AuthDeps:
    base = httpserver.url_for("")
    return AuthDeps(
        store=KeyringCredentialStore(timeout=2.0, health=KeyringHealth()),
        client=GithubOAuthClient("test-client", oauth_url=base, api_url=base, clock=clock.now, timeout=5),
        now=clock.now,
        sleep=clock.sleep,
        environ={},
        validated={},
    )


def auto(**kwargs) -> Settings:
    """Settings with the login flow on; the autouse fixture turns it off for every other test."""
    return Settings(github_auth=GithubAuthMode.AUTO, **kwargs)


def hits(httpserver: HTTPServer, path: str) -> int:
    return sum(1 for request, _ in httpserver.log if request.path == path)


def serve_user(httpserver: HTTPServer, login: str = "octocat") -> None:
    httpserver.expect_request("/user").respond_with_json({"login": login})


def write_config(path, token: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"OSSIQ_GITHUB_TOKEN={token}\n")


def scan_auth(deps: AuthDeps, settings: Settings | None = None, *, interactive: bool = False, **kwargs):
    return authenticate_github(settings or auto(), deps, interactive=interactive, **kwargs)


def test_the_keyring_store_satisfies_the_protocol_this_module_consumes():
    store: CredentialStore = KeyringCredentialStore()

    assert store is not None


class TestFindTokenSource:
    def test_no_token_has_no_source(self):
        assert find_token_source(Settings(github_token=None), {}) is None

    def test_prefixed_env_var(self):
        assert find_token_source(Settings(github_token="t"), {"OSSIQ_GITHUB_TOKEN": "t"}) is TokenSource.ENV_OSSIQ

    def test_bare_env_var(self):
        assert find_token_source(Settings(github_token="t"), {"GITHUB_TOKEN": "t"}) is TokenSource.ENV_GITHUB_TOKEN

    def test_prefixed_env_var_wins_when_both_hold_the_value(self):
        environ = {"OSSIQ_GITHUB_TOKEN": "t", "GITHUB_TOKEN": "t"}

        assert find_token_source(Settings(github_token="t"), environ) is TokenSource.ENV_OSSIQ

    def test_config_file(self):
        write_config(ossiq.settings.CONFIG_PATH, "t")

        assert find_token_source(Settings(github_token="t"), {}) is TokenSource.CONFIG_FILE

    def test_legacy_config_file(self):
        write_config(ossiq.settings.LEGACY_CONFIG_PATH, "t")

        assert find_token_source(Settings(github_token="t"), {}) is TokenSource.LEGACY_CONFIG_FILE

    def test_new_config_file_wins_over_the_legacy_one(self):
        write_config(ossiq.settings.CONFIG_PATH, "t")
        write_config(ossiq.settings.LEGACY_CONFIG_PATH, "t")

        assert find_token_source(Settings(github_token="t"), {}) is TokenSource.CONFIG_FILE

    def test_a_bare_github_token_line_in_a_config_file_counts(self):
        ossiq.settings.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        ossiq.settings.CONFIG_PATH.write_text("GITHUB_TOKEN=t\n")

        assert find_token_source(Settings(github_token="t"), {}) is TokenSource.CONFIG_FILE

    def test_a_value_found_nowhere_was_passed_on_the_command_line(self):
        assert find_token_source(Settings(github_token="t"), {}) is TokenSource.CLI_FLAG


class TestPrecedence:
    def test_an_explicit_token_beats_the_keyring_and_never_touches_it(self, deps, fake_keyring):
        deps.store.write_credentials(STORED)
        fake_keyring.calls.clear()
        explicit = dataclasses.replace(deps, environ={"OSSIQ_GITHUB_TOKEN": "ghp_env"})

        result = scan_auth(explicit, auto(github_token="ghp_env"))

        assert result.source is TokenSource.ENV_OSSIQ
        assert result.settings.github_token == "ghp_env"
        assert fake_keyring.calls == []

    def test_the_cli_flag_is_explicit_too(self, deps, fake_keyring):
        deps.store.write_credentials(STORED)
        fake_keyring.calls.clear()

        result = scan_auth(deps, auto(github_token="ghp_flag"))

        assert result.source is TokenSource.CLI_FLAG
        assert fake_keyring.calls == []

    def test_the_keyring_login_beats_a_token_in_a_config_file(self, deps, httpserver):
        write_config(ossiq.settings.CONFIG_PATH, "ghp_file")
        deps.store.write_credentials(STORED)
        serve_user(httpserver)

        result = scan_auth(deps, auto(github_token="ghp_file"))

        assert result.source is TokenSource.KEYRING
        assert result.settings.github_token == "gho_stored"

    def test_a_config_file_token_is_enough_so_no_login_is_offered(self, deps, httpserver):
        write_config(ossiq.settings.CONFIG_PATH, "ghp_file")

        result = scan_auth(deps, auto(github_token="ghp_file"))

        assert result.source is TokenSource.CONFIG_FILE
        assert httpserver.log == []

    def test_a_keyring_login_reaches_the_responsiveness_check(self, deps, httpserver):
        deps.store.write_credentials(STORED)
        serve_user(httpserver)

        result = scan_auth(deps)

        assert result.settings.responsiveness_enabled() is True


class TestSkippedLogin:
    def test_switched_off_runs_unauthenticated_and_leaves_the_keyring_alone(self, deps, fake_keyring, httpserver):
        result = scan_auth(deps, Settings(github_auth=GithubAuthMode.OFF))

        assert (result.source, result.skipped) == (None, AuthSkipReason.DISABLED)
        assert fake_keyring.calls == []
        assert httpserver.log == []

    def test_switched_off_still_uses_a_config_file_token(self, deps):
        write_config(ossiq.settings.CONFIG_PATH, "ghp_file")

        result = scan_auth(deps, Settings(github_auth=GithubAuthMode.OFF, github_token="ghp_file"))

        assert (result.source, result.skipped) == (TokenSource.CONFIG_FILE, None)

    @pytest.mark.parametrize("value", ["true", "1", "yes"])
    def test_ci_skips_the_login_and_leaves_the_keyring_alone(self, deps, fake_keyring, value):
        ci = dataclasses.replace(deps, environ={"CI": value})

        result = scan_auth(ci)

        assert (result.source, result.skipped) == (None, AuthSkipReason.CI)
        assert fake_keyring.calls == []

    @pytest.mark.parametrize("value", ["", "0", "false", "False"])
    def test_a_falsy_ci_value_is_not_ci(self, deps, httpserver, value):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)
        ci = dataclasses.replace(deps, environ={"CI": value})

        with pytest.raises(GithubAuthRequired):  # the login is offered, so CI did not skip it
            scan_auth(ci)

    def test_an_unavailable_keyring_skips_with_a_diagnostic_instead_of_failing(self, deps, fake_keyring, httpserver):
        fake_keyring.fail_with = keyring.errors.NoKeyringError("none")

        result = scan_auth(deps)

        assert (result.source, result.skipped) == (None, AuthSkipReason.STORE_UNAVAILABLE)
        assert "No system keyring" in result.detail
        assert httpserver.log == []

    def test_an_unavailable_keyring_still_uses_a_config_file_token(self, deps, fake_keyring):
        write_config(ossiq.settings.CONFIG_PATH, "ghp_file")
        fake_keyring.fail_with = keyring.errors.KeyringLocked("locked")

        result = scan_auth(deps, auto(github_token="ghp_file"))

        assert (result.source, result.skipped) == (TokenSource.CONFIG_FILE, None)

    def test_the_caller_can_skip_the_login_after_a_denial(self, deps, httpserver):
        result = scan_auth(deps, skip_login=AuthSkipReason.LOGIN_DENIED)

        assert (result.source, result.skipped) == (None, AuthSkipReason.LOGIN_DENIED)
        assert hits(httpserver, DEVICE_PATH) == 0


class TestStoredLogin:
    def test_a_login_due_for_refresh_is_refreshed_and_saved(self, deps, httpserver):
        deps.store.write_credentials(DUE)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json(
            {**GRANTED, "access_token": "gho_new", "refresh_token": "ghr_new"}
        )

        result = scan_auth(deps)

        assert result.settings.github_token == "gho_new"
        saved = deps.store.read_credentials()
        assert saved is not None
        assert (saved.access_token, saved.refresh_token) == ("gho_new", "ghr_new")
        assert hits(httpserver, "/user") == 0  # a token GitHub just issued needs no second opinion

    def test_a_refusal_with_the_store_unchanged_discards_the_login_and_asks_for_a_new_one(self, deps, httpserver):
        deps.store.write_credentials(DUE)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json(SPENT_REFRESH)
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)

        with pytest.raises(GithubAuthRequired):
            scan_auth(deps)

        assert deps.store.read_credentials() is None

    def test_a_refusal_because_another_process_refreshed_adopts_its_tokens(self, deps, httpserver):
        deps.store.write_credentials(DUE)
        winner = GithubCredentials(access_token="gho_winner", refresh_token="ghr_winner", expires_at=int(NOW) + 28800)

        def other_process_refreshed_first(request):
            deps.store.write_credentials(winner)
            return Response(json.dumps(SPENT_REFRESH), content_type="application/json")

        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_handler(other_process_refreshed_first)
        serve_user(httpserver)

        result = scan_auth(deps)

        assert result.settings.github_token == "gho_winner"
        assert deps.store.read_credentials() == winner
        assert hits(httpserver, DEVICE_PATH) == 0

    def test_an_unreachable_github_keeps_a_login_that_has_not_expired_yet(self, deps, httpserver, clock):
        deps.store.write_credentials(DUE)
        offline = dataclasses.replace(
            deps,
            client=GithubOAuthClient(
                "test-client",
                oauth_url="http://127.0.0.1:1",
                api_url=httpserver.url_for(""),
                clock=clock.now,
                timeout=1,
            ),
        )
        serve_user(httpserver)

        result = scan_auth(offline)

        assert result.settings.github_token == "gho_due"
        assert deps.store.read_credentials() == DUE

    def test_a_token_revoked_on_github_is_refreshed_when_the_refresh_token_still_works(self, deps, httpserver):
        deps.store.write_credentials(STORED)
        httpserver.expect_request("/user", headers={"Authorization": "Bearer gho_stored"}).respond_with_json(
            {"message": "Bad credentials"}, status=401
        )
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json(
            {**GRANTED, "access_token": "gho_renewed"}
        )

        result = scan_auth(deps)

        assert result.settings.github_token == "gho_renewed"

    def test_a_token_revoked_on_github_with_nothing_to_refresh_with_asks_for_a_new_login(self, deps, httpserver):
        deps.store.write_credentials(GithubCredentials(access_token="gho_stored"))
        httpserver.expect_request("/user").respond_with_json({"message": "Bad credentials"}, status=401)
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)

        with pytest.raises(GithubAuthRequired):
            scan_auth(deps)

        assert deps.store.read_credentials() is None

    def test_a_revoked_authorization_takes_both_tokens_so_a_fresh_login_follows(self, deps, httpserver):
        deps.store.write_credentials(STORED)
        httpserver.expect_request("/user").respond_with_json({"message": "Bad credentials"}, status=401)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json(SPENT_REFRESH)
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)

        with pytest.raises(GithubAuthRequired):
            scan_auth(deps)

        assert deps.store.read_credentials() is None

    def test_a_token_is_checked_with_github_only_once_per_window(self, deps, httpserver, clock):
        deps.store.write_credentials(STORED)
        serve_user(httpserver)

        scan_auth(deps)
        scan_auth(deps)
        assert hits(httpserver, "/user") == 1

        clock.time += 601
        scan_auth(deps)
        assert hits(httpserver, "/user") == 2

    def test_when_github_cannot_be_asked_the_stored_token_is_trusted(self, deps):
        deps.store.write_credentials(STORED)
        offline_client = GithubOAuthClient(
            "test-client", oauth_url="http://127.0.0.1:1", api_url="http://127.0.0.1:1", timeout=1
        )
        offline = dataclasses.replace(deps, client=offline_client)

        assert scan_auth(offline).settings.github_token == "gho_stored"


class TestBeginLogin:
    def test_requests_a_code_and_keeps_it_pending(self, deps, httpserver):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)

        challenge = begin_login(deps)

        assert isinstance(challenge, DeviceChallenge)
        assert deps.store.read_pending() == challenge

    def test_a_second_call_returns_the_same_challenge_without_a_second_code(self, deps, httpserver):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)

        first = begin_login(deps)
        second = begin_login(deps)

        assert first == second
        assert hits(httpserver, DEVICE_PATH) == 1

    def test_an_expired_pending_login_is_replaced(self, deps, httpserver, clock):
        httpserver.expect_ordered_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)
        httpserver.expect_ordered_request(DEVICE_PATH, method="POST").respond_with_json(
            {**DEVICE_BODY, "device_code": "SECOND", "user_code": "ABCD-1234"}
        )
        first = begin_login(deps)
        clock.time += 901

        second = begin_login(deps)

        assert isinstance(first, DeviceChallenge) and isinstance(second, DeviceChallenge)
        assert second.user_code == "ABCD-1234"

    def test_a_refusal_comes_back_as_a_value_and_stores_nothing(self, deps, httpserver):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(
            {"error": "device_flow_disabled", "error_description": "Device Flow must be enabled"}
        )

        result = begin_login(deps)

        assert not isinstance(result, DeviceChallenge)
        assert deps.store.read_pending() is None

    def test_an_unusable_keyring_is_found_out_before_a_code_is_requested(self, deps, fake_keyring, httpserver):
        fake_keyring.fail_with = keyring.errors.NoKeyringError("none")

        with pytest.raises(CredentialStoreUnavailable):
            begin_login(deps)

        assert httpserver.log == []


class TestAwaitLogin:
    def challenge(self, deps, httpserver, interval: int = 5) -> DeviceChallenge:
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json({**DEVICE_BODY, "interval": interval})
        challenge = begin_login(deps)
        assert isinstance(challenge, DeviceChallenge)
        return challenge

    def test_polls_through_pending_and_slow_down_to_an_approval(self, deps, httpserver, clock):
        challenge = self.challenge(deps, httpserver)
        httpserver.expect_ordered_request(TOKEN_PATH, method="POST").respond_with_json(
            {"error": "authorization_pending"}
        )
        httpserver.expect_ordered_request(TOKEN_PATH, method="POST").respond_with_json(
            {"error": "slow_down", "interval": 10}
        )
        httpserver.expect_ordered_request(TOKEN_PATH, method="POST").respond_with_json(GRANTED)

        credentials = await_login(challenge, deps)

        assert credentials.access_token == "gho_login"
        assert clock.sleeps == [5, 10]
        assert deps.store.read_credentials() == credentials
        assert deps.store.read_pending() is None

    def test_gives_up_when_the_code_expires_after_fifteen_minutes(self, deps, httpserver, clock):
        challenge = self.challenge(deps, httpserver, interval=300)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json({"error": "authorization_pending"})

        with pytest.raises(GithubAuthTimeout):
            await_login(challenge, deps)

        assert clock.sleeps == [300, 300, 300]
        assert hits(httpserver, TOKEN_PATH) == 3
        assert deps.store.read_pending() is None
        assert deps.store.read_credentials() is None

    def test_a_cancelled_login_raises_denied_and_clears_the_pending_entry(self, deps, httpserver):
        challenge = self.challenge(deps, httpserver)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json({"error": "access_denied"})

        with pytest.raises(GithubAuthDenied):
            await_login(challenge, deps)

        assert deps.store.read_pending() is None

    def test_an_expired_token_answer_raises_timeout(self, deps, httpserver):
        challenge = self.challenge(deps, httpserver)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json({"error": "expired_token"})

        with pytest.raises(GithubAuthTimeout, match="expired"):
            await_login(challenge, deps)

    def test_a_code_github_no_longer_recognises_ends_the_login(self, deps, httpserver):
        challenge = self.challenge(deps, httpserver)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json(
            {"error": "incorrect_device_code", "error_description": "The device_code provided is not valid."}
        )

        with pytest.raises(GithubAuthTimeout, match="not valid"):
            await_login(challenge, deps)

        assert deps.store.read_pending() is None

    def test_a_hiccup_does_not_end_the_wait(self, deps, httpserver, clock):
        challenge = self.challenge(deps, httpserver)
        httpserver.expect_ordered_request(TOKEN_PATH, method="POST").respond_with_data(
            "<html>Bad Gateway</html>", status=502, content_type="text/html"
        )
        httpserver.expect_ordered_request(TOKEN_PATH, method="POST").respond_with_json(GRANTED)

        assert await_login(challenge, deps).access_token == "gho_login"
        assert clock.sleeps == [5]


class TestResumeLogin:
    def test_nothing_pending_is_none(self, deps):
        assert resume_login(deps) is None

    def test_an_approved_login_is_saved(self, deps, httpserver):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)
        begin_login(deps)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json(GRANTED)

        result = resume_login(deps)

        assert isinstance(result, GithubCredentials)
        assert deps.store.read_credentials() == result
        assert deps.store.read_pending() is None

    def test_a_login_still_waiting_comes_back_as_the_same_challenge(self, deps, httpserver):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)
        pending = begin_login(deps)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json({"error": "authorization_pending"})

        assert resume_login(deps) == pending

    def test_an_expired_login_raises_timeout_without_asking_github(self, deps, httpserver, clock):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)
        begin_login(deps)
        clock.time += 901

        with pytest.raises(GithubAuthTimeout):
            resume_login(deps)

        assert hits(httpserver, TOKEN_PATH) == 0
        assert deps.store.read_pending() is None


class TestLoginThroughAuthenticate:
    def test_without_a_terminal_the_challenge_is_raised_for_the_front_door(self, deps, httpserver):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)

        with pytest.raises(GithubAuthRequired) as raised:
            scan_auth(deps)

        assert raised.value.challenge.user_code == "WDJB-4729"
        assert deps.store.read_pending() == raised.value.challenge

    def test_the_next_scan_polls_the_same_login_instead_of_requesting_another_code(self, deps, httpserver):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json({"error": "authorization_pending"})
        with pytest.raises(GithubAuthRequired):
            scan_auth(deps)

        with pytest.raises(GithubAuthRequired) as again:
            scan_auth(deps)

        assert again.value.challenge.user_code == "WDJB-4729"
        assert hits(httpserver, DEVICE_PATH) == 1
        assert hits(httpserver, TOKEN_PATH) == 1

    def test_once_approved_the_next_scan_carries_on_with_the_new_token(self, deps, httpserver):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)
        with pytest.raises(GithubAuthRequired):
            scan_auth(deps)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json(GRANTED)

        result = scan_auth(deps)

        assert result.source is TokenSource.KEYRING
        assert result.settings.github_token == "gho_login"
        assert deps.store.read_pending() is None

    def test_a_process_that_polls_elsewhere_does_not_poll_here(self, deps, httpserver):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)
        with pytest.raises(GithubAuthRequired):
            scan_auth(deps)

        with pytest.raises(GithubAuthRequired) as again:
            scan_auth(deps, poll_pending=False)

        assert again.value.challenge.user_code == "WDJB-4729"
        assert hits(httpserver, TOKEN_PATH) == 0

    def test_an_expired_pending_login_is_replaced_by_a_fresh_one(self, deps, httpserver, clock):
        httpserver.expect_ordered_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)
        httpserver.expect_ordered_request(DEVICE_PATH, method="POST").respond_with_json(
            {**DEVICE_BODY, "user_code": "NEWC-0DE1"}
        )
        with pytest.raises(GithubAuthRequired):
            scan_auth(deps)
        clock.time += 901

        with pytest.raises(GithubAuthRequired) as fresh:
            scan_auth(deps)

        assert fresh.value.challenge.user_code == "NEWC-0DE1"

    def test_a_cancelled_pending_login_degrades_instead_of_asking_again(self, deps, httpserver):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)
        with pytest.raises(GithubAuthRequired):
            scan_auth(deps)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json({"error": "access_denied"})

        result = scan_auth(deps)

        assert (result.source, result.skipped) == (None, AuthSkipReason.LOGIN_DENIED)
        assert hits(httpserver, DEVICE_PATH) == 1

    def test_interactive_shows_the_challenge_then_waits_for_the_approval(self, deps, httpserver, clock):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)
        # One-shot, not ordered: an ordered handler would also reject the device-code request above.
        httpserver.expect_oneshot_request(TOKEN_PATH, method="POST").respond_with_json(
            {"error": "authorization_pending"}
        )
        httpserver.expect_oneshot_request(TOKEN_PATH, method="POST").respond_with_json(GRANTED)
        shown: list[DeviceChallenge] = []

        result = scan_auth(deps, interactive=True, on_challenge=shown.append)

        assert [challenge.user_code for challenge in shown] == ["WDJB-4729"]
        assert result.source is TokenSource.KEYRING
        assert result.settings.github_token == "gho_login"
        assert clock.sleeps == [5]

    def test_interactive_denial_runs_unauthenticated_with_a_reason(self, deps, httpserver):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json({"error": "access_denied"})

        result = scan_auth(deps, interactive=True)

        assert (result.source, result.skipped) == (None, AuthSkipReason.LOGIN_DENIED)
        assert deps.store.read_pending() is None

    def test_interactive_expiry_runs_unauthenticated_with_a_reason(self, deps, httpserver):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json({"error": "expired_token"})

        result = scan_auth(deps, interactive=True)

        assert (result.source, result.skipped) == (None, AuthSkipReason.LOGIN_EXPIRED)

    def test_a_login_github_will_not_start_runs_unauthenticated_and_says_why(self, deps, httpserver):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(
            {"error": "device_flow_disabled", "error_description": "Device Flow must be enabled"}
        )

        result = scan_auth(deps)

        assert (result.source, result.skipped) == (None, AuthSkipReason.LOGIN_UNAVAILABLE)
        assert "Device Flow must be enabled" in result.detail

    def test_the_device_code_never_appears_in_what_the_front_door_receives(self, deps, httpserver):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)

        with pytest.raises(GithubAuthRequired) as raised:
            scan_auth(deps)

        error = raised.value
        assert "DEVICE-SECRET" not in f"{error!r} {error} {error.render()} {error.challenge!r}"


class TestStatusAndLogout:
    def test_status_of_a_keyring_login(self, deps, httpserver, fake_keyring):
        deps.store.write_credentials(STORED)
        serve_user(httpserver, "octocat")

        status = github_auth_status(auto(), deps)

        assert status.source is TokenSource.KEYRING
        assert status.login == "octocat"
        assert status.scope == ""
        assert status.expires_at == STORED.expires_at
        assert status.backend == "tests.adapters.keyring_fakes.FakeKeyring"
        assert status.legacy_config_in_use is False

    def test_status_flags_a_token_left_in_the_legacy_config_even_when_it_does_not_win(self, deps, httpserver):
        write_config(ossiq.settings.LEGACY_CONFIG_PATH, "ghp_legacy")
        deps.store.write_credentials(STORED)
        serve_user(httpserver)

        status = github_auth_status(auto(github_token="ghp_legacy"), deps)

        assert status.source is TokenSource.KEYRING
        assert status.legacy_config_in_use is True

    def test_status_of_an_explicit_token_does_not_read_the_keyring(self, deps, httpserver, fake_keyring):
        explicit = dataclasses.replace(deps, environ={"GITHUB_TOKEN": "ghp_env"})
        serve_user(httpserver)

        status = github_auth_status(auto(github_token="ghp_env"), explicit)

        assert status.source is TokenSource.ENV_GITHUB_TOKEN
        assert status.backend is None
        assert fake_keyring.calls == []

    def test_status_with_no_token_at_all(self, deps):
        status = github_auth_status(auto(), deps)

        assert status.source is None
        assert status.login is None

    def test_status_reports_a_rejected_token_as_having_no_known_login(self, deps, httpserver):
        deps.store.write_credentials(STORED)
        httpserver.expect_request("/user").respond_with_json({"message": "Bad credentials"}, status=401)

        assert github_auth_status(auto(), deps).login is None

    def test_logout_deletes_both_entries(self, deps):
        deps.store.write_credentials(STORED)
        deps.store.write_pending(DeviceChallenge("A", "u", int(NOW) + 900, 5, "d"))

        remaining = logout_github(auto(), deps)

        assert remaining is None
        assert deps.store.read_credentials() is None
        assert deps.store.read_pending() is None

    def test_logout_says_which_token_still_applies(self, deps):
        write_config(ossiq.settings.CONFIG_PATH, "ghp_file")
        deps.store.write_credentials(STORED)

        remaining = logout_github(auto(github_token="ghp_file"), deps)

        assert remaining is TokenSource.CONFIG_FILE
        assert deps.store.read_credentials() is None

    def test_logout_with_an_unusable_keyring_raises_rather_than_claiming_success(self, deps, fake_keyring):
        fake_keyring.fail_with = keyring.errors.NoKeyringError("none")

        with pytest.raises(CredentialStoreUnavailable):
            logout_github(auto(), deps)
