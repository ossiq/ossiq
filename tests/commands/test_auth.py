"""Tests for `ossiq auth` and the login that runs ahead of a scan, driven through the real CLI.

The keyring is in memory, GitHub is a local HTTP server and the clock is injected, so nothing here
touches the real keychain, the network or the wall clock.
"""

import dataclasses
import inspect
import threading
import time
from typing import Any, cast

import keyring.errors
import pytest
from pytest_httpserver import HTTPServer
from typer.testing import CliRunner

import ossiq.settings
from ossiq.adapters.credential_store import KeyringCredentialStore, KeyringHealth
from ossiq.cli import app
from ossiq.clients.client_github_oauth import GithubOAuthClient
from ossiq.commands.auth import EXIT_LOGIN_PENDING, keychain_wait_notice
from ossiq.domain.github_auth import GithubCredentials
from ossiq.service.github_auth import AuthDeps

pytest_plugins = ["tests.adapters.keyring_fakes"]

runner = CliRunner()

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
def deps(httpserver: HTTPServer, fake_keyring, clock: FakeClock, monkeypatch) -> AuthDeps:
    """The login flow's dependencies, swapped in for what the commands would build themselves."""
    base = httpserver.url_for("")
    built = AuthDeps(
        store=KeyringCredentialStore(timeout=2.0, health=KeyringHealth()),
        client=GithubOAuthClient("test-client", oauth_url=base, api_url=base, clock=clock.now, timeout=5),
        now=clock.now,
        sleep=clock.sleep,
        environ={},
        validated={},
    )
    use_deps(monkeypatch, built)
    monkeypatch.setenv("OSSIQ_GITHUB_AUTH", "auto")  # the autouse fixture turns it off for other tests
    return built


def use_deps(monkeypatch, built: AuthDeps) -> None:
    monkeypatch.setattr("ossiq.commands.auth.default_deps", lambda settings: built)


@pytest.fixture
def terminal(monkeypatch):
    """Switch between a person at a terminal and an agent or script with none."""

    def set_terminal(present: bool) -> None:
        monkeypatch.setattr("ossiq.commands.auth.is_interactive", lambda: present)

    set_terminal(False)
    return set_terminal


@pytest.fixture
def scan(monkeypatch) -> dict:
    """Replace the status command's body, recording whether it ran and with which token."""
    seen: dict = {"calls": 0, "token": None}

    def fake_status(ctx, options):
        seen["calls"] += 1
        seen["token"] = ctx.obj.github_token

    monkeypatch.setattr("ossiq.cli.command_status", fake_status)
    return seen


def hits(httpserver: HTTPServer, path: str) -> int:
    return sum(1 for request, _ in httpserver.log if request.path == path)


def serve_user(httpserver: HTTPServer, login: str = "octocat") -> None:
    httpserver.expect_request("/user").respond_with_json({"login": login})


def serve_device_code(httpserver: HTTPServer) -> None:
    httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(DEVICE_BODY)


def cli(*args: str):
    return runner.invoke(app, ["--no-cache", *args])


class TestLogin:
    def test_without_a_terminal_it_prints_the_code_and_exits_75(self, deps, terminal, httpserver):
        serve_device_code(httpserver)

        result = cli("auth", "login")

        assert result.exit_code == EXIT_LOGIN_PENDING == 75
        assert "https://github.com/login/device" in result.stdout
        assert "WDJB-4729" in result.stdout
        assert "DEVICE-SECRET" not in result.output
        assert deps.store.read_pending() is not None
        assert hits(httpserver, TOKEN_PATH) == 0

    def test_with_a_terminal_it_waits_for_the_approval(self, deps, terminal, httpserver, clock):
        terminal(True)
        serve_device_code(httpserver)
        serve_user(httpserver)
        httpserver.expect_oneshot_request(TOKEN_PATH, method="POST").respond_with_json(
            {"error": "authorization_pending"}
        )
        httpserver.expect_oneshot_request(TOKEN_PATH, method="POST").respond_with_json(GRANTED)

        result = cli("auth", "login")

        assert result.exit_code == 0
        assert "Waiting for approval" in result.stdout
        assert "Logged in as @octocat" in result.stdout
        assert clock.sleeps == [5]
        stored = deps.store.read_credentials()
        assert stored is not None and stored.access_token == "gho_login"
        assert deps.store.read_pending() is None

    def test_no_wait_prints_the_code_and_exits_even_with_a_terminal(self, deps, terminal, httpserver):
        terminal(True)
        serve_device_code(httpserver)

        result = cli("auth", "login", "--no-wait")

        assert result.exit_code == EXIT_LOGIN_PENDING
        assert hits(httpserver, TOKEN_PATH) == 0

    def test_a_login_that_already_works_is_not_started_again(self, deps, terminal, httpserver):
        deps.store.write_credentials(STORED)
        serve_user(httpserver)

        result = cli("auth", "login")

        assert result.exit_code == 0
        assert "Already logged in to GitHub as @octocat" in result.stdout
        assert hits(httpserver, DEVICE_PATH) == 0

    def test_a_cancelled_login_is_reported_as_an_error(self, deps, terminal, httpserver):
        terminal(True)
        serve_device_code(httpserver)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json({"error": "access_denied"})

        result = cli("auth", "login")

        assert result.exit_code == 1
        assert "GitHub Login Denied" in result.output

    def test_a_login_github_will_not_start_is_reported_with_its_reason(self, deps, terminal, httpserver):
        httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json(
            {"error": "device_flow_disabled", "error_description": "Device Flow must be enabled"}
        )

        result = cli("auth", "login")

        assert result.exit_code == 1
        assert "GitHub Login Unavailable" in result.output
        assert "Device Flow must be enabled" in result.output

    def test_an_unusable_keyring_is_reported_before_any_code_is_requested(
        self, deps, terminal, httpserver, fake_keyring
    ):
        fake_keyring.fail_with = keyring.errors.NoKeyringError("none")

        result = cli("auth", "login")

        assert result.exit_code == 1
        assert "Credential Store Unavailable" in result.output
        assert httpserver.log == []

    def test_login_works_even_when_scans_are_told_not_to_log_in(self, deps, terminal, httpserver, monkeypatch):
        monkeypatch.setenv("OSSIQ_GITHUB_AUTH", "off")
        serve_device_code(httpserver)

        result = cli("auth", "login")

        assert result.exit_code == EXIT_LOGIN_PENDING

    def test_a_token_left_in_the_legacy_config_is_pointed_out_but_never_edited(self, deps, terminal, httpserver):
        legacy = ossiq.settings.LEGACY_CONFIG_PATH
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text("OSSIQ_GITHUB_TOKEN=ghp_legacy\n")
        terminal(True)
        serve_device_code(httpserver)
        serve_user(httpserver)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json(GRANTED)

        result = cli("auth", "login")

        assert "plaintext in ~/.ossiq/config" in result.stdout
        assert legacy.read_text() == "OSSIQ_GITHUB_TOKEN=ghp_legacy\n"


class TestResume:
    def test_with_nothing_started_it_says_so(self, deps, terminal):
        result = cli("auth", "login", "--resume")

        assert result.exit_code == 1
        assert "Nothing To Resume" in result.output

    def test_an_approved_login_is_finished(self, deps, terminal, httpserver):
        serve_device_code(httpserver)
        assert cli("auth", "login").exit_code == EXIT_LOGIN_PENDING
        serve_user(httpserver)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json(GRANTED)

        result = cli("auth", "login", "--resume")

        assert result.exit_code == 0
        assert "Logged in as @octocat" in result.stdout
        assert deps.store.read_pending() is None

    def test_a_login_still_waiting_shows_the_same_code_and_exits_75(self, deps, terminal, httpserver):
        serve_device_code(httpserver)
        cli("auth", "login")
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json({"error": "authorization_pending"})

        result = cli("auth", "login", "--resume")

        assert result.exit_code == EXIT_LOGIN_PENDING
        assert "WDJB-4729" in result.stdout
        assert hits(httpserver, DEVICE_PATH) == 1

    def test_with_a_terminal_a_login_still_waiting_is_waited_for(self, deps, terminal, httpserver, clock):
        serve_device_code(httpserver)
        cli("auth", "login")
        terminal(True)
        serve_user(httpserver)
        httpserver.expect_oneshot_request(TOKEN_PATH, method="POST").respond_with_json(
            {"error": "authorization_pending"}
        )
        httpserver.expect_oneshot_request(TOKEN_PATH, method="POST").respond_with_json(GRANTED)

        result = cli("auth", "login", "--resume")

        assert result.exit_code == 0
        assert clock.sleeps == [5]

    def test_an_expired_login_is_reported_as_an_error(self, deps, terminal, httpserver, clock):
        serve_device_code(httpserver)
        cli("auth", "login")
        clock.time += 901

        result = cli("auth", "login", "--resume")

        assert result.exit_code == 1
        assert "GitHub Login Expired" in result.output
        assert deps.store.read_pending() is None


class TestStatus:
    def test_shows_a_keyring_login(self, deps, httpserver):
        deps.store.write_credentials(STORED)
        serve_user(httpserver)

        result = cli("auth", "status")

        assert result.exit_code == 0
        assert "GitHub login (system keyring)" in result.stdout
        assert "@octocat" in result.stdout
        assert "none (public data only)" in result.stdout

    def test_exits_zero_and_points_at_the_login_when_there_is_no_token(self, deps):
        result = cli("auth", "status")

        assert result.exit_code == 0
        assert "Not logged in" in result.stdout

    def test_exits_zero_even_when_the_keyring_is_unusable(self, deps, fake_keyring):
        fake_keyring.fail_with = keyring.errors.NoKeyringError("none")

        result = cli("auth", "status")

        assert result.exit_code == 0

    def test_flags_a_token_left_in_the_legacy_config(self, deps):
        legacy = ossiq.settings.LEGACY_CONFIG_PATH
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text("OSSIQ_GITHUB_TOKEN=ghp_legacy\n")

        result = cli("auth", "status")

        assert "plaintext in ~/.ossiq/config" in result.stdout

    def test_reports_the_token_from_the_environment_as_such(self, deps, httpserver, monkeypatch):
        monkeypatch.setenv("OSSIQ_GITHUB_TOKEN", "ghp_env")
        use_deps(monkeypatch, dataclasses.replace(deps, environ={"OSSIQ_GITHUB_TOKEN": "ghp_env"}))
        serve_user(httpserver)

        result = cli("auth", "status")

        assert "OSSIQ_GITHUB_TOKEN environment variable" in result.stdout
        assert "ghp_env" not in result.output


class TestLogout:
    def test_removes_the_login_and_says_how_to_revoke_it_on_github(self, deps):
        deps.store.write_credentials(STORED)

        result = cli("auth", "logout")

        assert result.exit_code == 0
        assert deps.store.read_credentials() is None
        assert "https://github.com/settings/applications" in result.stdout

    def test_says_which_token_still_applies(self, deps, monkeypatch):
        deps.store.write_credentials(STORED)
        monkeypatch.setenv("OSSIQ_GITHUB_TOKEN", "ghp_env")
        use_deps(monkeypatch, dataclasses.replace(deps, environ={"OSSIQ_GITHUB_TOKEN": "ghp_env"}))

        result = cli("auth", "logout")

        assert "OSSIQ_GITHUB_TOKEN environment variable" in result.stdout
        assert "still in use" in result.stdout

    def test_an_unusable_keyring_means_nothing_to_remove_not_a_failure(self, deps, fake_keyring):
        fake_keyring.fail_with = keyring.errors.NoKeyringError("none")

        result = cli("auth", "logout")

        assert result.exit_code == 0
        assert "Nothing to remove" in result.stdout


class TestKeychainWaitNotice:
    def test_says_why_after_a_silence(self, capsys):
        with keychain_wait_notice(delay=0.02):
            time.sleep(0.3)

        err = capsys.readouterr().err
        assert "Waiting for the system keyring" in err
        assert "3 minutes" in err

    def test_stays_quiet_when_the_keyring_answers_quickly(self, capsys):
        with keychain_wait_notice(delay=5):
            pass

        assert capsys.readouterr().err == ""

    def test_can_be_cancelled(self, capsys):
        with keychain_wait_notice(delay=0.05) as notice:
            notice.cancel()
            time.sleep(0.3)

        assert capsys.readouterr().err == ""

    def test_a_scan_held_up_by_the_keyring_says_so(self, deps, terminal, scan, fake_keyring, httpserver, monkeypatch):
        monkeypatch.setattr("ossiq.commands.auth.KEYCHAIN_NOTICE_DELAY_SECONDS", 0.02)
        serve_device_code(httpserver)
        fake_keyring.block = threading.Event()  # an unanswered dialog
        threading.Timer(0.4, fake_keyring.block.set).start()  # the person answers it

        result = cli("status")

        assert "Waiting for the system keyring" in result.stderr
        assert result.exit_code == EXIT_LOGIN_PENDING

    def test_the_notice_stops_once_the_wait_is_for_the_persons_approval(
        self, deps, terminal, scan, httpserver, monkeypatch
    ):
        terminal(True)
        monkeypatch.setattr("ossiq.commands.auth.KEYCHAIN_NOTICE_DELAY_SECONDS", 0.4)
        use_deps(monkeypatch, dataclasses.replace(deps, sleep=lambda seconds: time.sleep(0.8)))
        serve_device_code(httpserver)
        serve_user(httpserver)
        httpserver.expect_oneshot_request(TOKEN_PATH, method="POST").respond_with_json(
            {"error": "authorization_pending"}
        )
        httpserver.expect_oneshot_request(TOKEN_PATH, method="POST").respond_with_json(GRANTED)

        result = cli("status")  # the wait for approval outlasts the notice delay

        assert result.exit_code == 0
        assert "Waiting for approval" in result.stderr
        assert "Waiting for the system keyring" not in result.stderr


SCANNING_COMMANDS = {"status", "html", "export", "info", "add", "update-context", "plan", "apply"}
NON_SCANNING_COMMANDS = {"help", "mcp"}


class TestEveryCommandIsClassified:
    """A new command must be put on one side of this line on purpose, not by omission."""

    def commands(self) -> dict:
        found = {}
        for command in app.registered_commands:
            assert command.callback is not None
            found[command.name or cast(Any, command.callback).__name__] = command.callback
        return found

    def test_each_command_is_either_a_scan_or_a_known_non_scan(self):
        assert set(self.commands()) == SCANNING_COMMANDS | NON_SCANNING_COMMANDS

    @pytest.mark.parametrize("name", sorted(SCANNING_COMMANDS))
    def test_a_scanning_command_logs_in_first_and_takes_its_context_by_name(self, name):
        callback = self.commands()[name]

        assert hasattr(callback, "__wrapped__"), f"`{name}` scans but is not decorated with @requires_github_login"
        assert "context" in inspect.signature(callback).parameters

    @pytest.mark.parametrize("name", sorted(NON_SCANNING_COMMANDS))
    def test_a_non_scanning_command_is_left_alone(self, name):
        assert not hasattr(self.commands()[name], "__wrapped__")


class TestLoginAheadOfAScan:
    def test_a_keyring_login_reaches_the_scan(self, deps, terminal, scan, httpserver):
        deps.store.write_credentials(STORED)
        serve_user(httpserver)

        result = cli("status")

        assert result.exit_code == 0
        assert scan["token"] == "gho_stored"

    def test_without_a_terminal_it_prints_the_challenge_on_stderr_and_does_not_scan(
        self, deps, terminal, scan, httpserver
    ):
        serve_device_code(httpserver)

        result = cli("status")

        assert result.exit_code == EXIT_LOGIN_PENDING
        assert scan["calls"] == 0
        assert "WDJB-4729" in result.stderr
        assert "WDJB-4729" not in result.stdout  # piped scan output stays clean
        assert "DEVICE-SECRET" not in result.output

    def test_with_a_terminal_it_waits_and_then_scans_with_the_new_token(self, deps, terminal, scan, httpserver):
        terminal(True)
        serve_device_code(httpserver)
        serve_user(httpserver)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json(GRANTED)

        result = cli("status")

        assert result.exit_code == 0
        assert scan["token"] == "gho_login"
        assert "Logged in as @octocat" in result.stderr

    def test_a_cancelled_login_warns_and_the_scan_runs_without_a_token(self, deps, terminal, scan, httpserver):
        terminal(True)
        serve_device_code(httpserver)
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json({"error": "access_denied"})

        result = cli("status")

        assert result.exit_code == 0
        assert scan["calls"] == 1 and scan["token"] is None
        assert "cancelled" in result.stderr

    def test_an_unusable_keyring_warns_and_the_scan_runs_without_a_token(self, deps, terminal, scan, fake_keyring):
        fake_keyring.fail_with = keyring.errors.NoKeyringError("none")

        result = cli("status")

        assert result.exit_code == 0
        assert scan["calls"] == 1 and scan["token"] is None
        assert "No system keyring" in result.stderr

    def test_an_explicit_token_needs_no_login_and_never_touches_the_keyring(
        self, deps, terminal, scan, fake_keyring, monkeypatch
    ):
        monkeypatch.setenv("OSSIQ_GITHUB_TOKEN", "ghp_env")
        use_deps(monkeypatch, dataclasses.replace(deps, environ={"OSSIQ_GITHUB_TOKEN": "ghp_env"}))

        result = cli("status")

        assert result.exit_code == 0
        assert scan["token"] == "ghp_env"
        assert fake_keyring.calls == []

    def test_switched_off_never_logs_in(self, deps, terminal, scan, fake_keyring, httpserver, monkeypatch):
        monkeypatch.setenv("OSSIQ_GITHUB_AUTH", "off")

        result = cli("status")

        assert result.exit_code == 0
        assert scan["calls"] == 1
        assert fake_keyring.calls == []
        assert httpserver.log == []

    def test_bare_ossiq_logs_in_too(self, deps, terminal, scan, httpserver):
        serve_device_code(httpserver)

        result = runner.invoke(app, ["--no-cache"])

        assert result.exit_code == EXIT_LOGIN_PENDING
        assert scan["calls"] == 0

    @pytest.mark.parametrize(
        "args",
        [["status", "--help"], ["status", "--bogus-flag"], ["plan", "--help"], ["export", "--help"]],
        ids=["status-help", "status-bad-flag", "plan-help", "export-help"],
    )
    def test_help_and_a_mistyped_flag_never_start_a_login(self, deps, terminal, scan, fake_keyring, httpserver, args):
        cli(*args)

        assert fake_keyring.calls == []
        assert httpserver.log == []
        assert scan["calls"] == 0

    @pytest.mark.parametrize("args", [["help"], ["auth", "status"], ["auth", "logout"]], ids=lambda a: " ".join(a))
    def test_commands_that_do_not_scan_never_start_a_login(self, deps, terminal, scan, httpserver, args):
        serve_device_code(httpserver)

        result = cli(*args)

        assert hits(httpserver, DEVICE_PATH) == 0
        assert result.exit_code == 0

    def test_verbose_names_the_source_of_a_token_from_the_environment(self, deps, terminal, scan, monkeypatch):
        monkeypatch.setenv("OSSIQ_GITHUB_TOKEN", "ghp_env")
        use_deps(monkeypatch, dataclasses.replace(deps, environ={"OSSIQ_GITHUB_TOKEN": "ghp_env"}))

        result = cli("--verbose", "status")

        assert "set (OSSIQ_GITHUB_TOKEN environment variable)" in result.stderr
        assert "ghp_env" not in result.output

    def test_verbose_names_a_keyring_login_not_the_environment(self, deps, terminal, scan, httpserver):
        deps.store.write_credentials(STORED)
        serve_user(httpserver)

        result = cli("--verbose", "status")

        assert "github_token: set (GitHub login (system keyring))" in result.stderr
        assert "set from environment" not in result.output
        assert "gho_stored" not in result.output
