"""
Tests for the stdlib MCP server JSON-RPC dispatch (mcp.server).

The tool handlers hit the network, so these tests exercise the protocol layer
with a stubbed handler and verify framing, initialize, tools/list, and errors.

The GitHub login runs against a real local HTTP server and an in-memory keyring. The watcher thread's
sleep is gated on a semaphore, so a test lets it poll exactly when it chooses.
"""

import io
import json
import threading
from collections.abc import Callable, Iterator, Mapping
from unittest.mock import MagicMock, patch

import keyring.errors
import pytest
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Request, Response

from ossiq.adapters.credential_store import KeyringCredentialStore, KeyringHealth
from ossiq.clients.client_github_oauth import GithubOAuthClient
from ossiq.domain.common import DataCompleteness, DataSourceStatus, ScanStep
from ossiq.domain.github_auth import DeviceChallenge
from ossiq.mcp import server
from ossiq.mcp.server import GithubLogin  # bound here, because one test replaces `server.GithubLogin`
from ossiq.service.github_auth import AuthDeps, AuthSkipReason, default_deps
from ossiq.service.project.models import ScanResult
from ossiq.settings import GithubAuthMode, Settings

pytest_plugins = ["tests.adapters.keyring_fakes"]

NOW = 1_000_000.0
STEP_TIMEOUT = 5.0
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
DECISION = {"next_action": "no action needed"}


class SteppedClock:
    """A clock whose sleep blocks until the test releases a step, so the watcher advances on demand."""

    def __init__(self) -> None:
        self.time = NOW
        self.steps = threading.Semaphore(0)
        self.entered = threading.Event()
        """Set when something first sleeps: the watcher has gone as far as it can without a step."""

    def now(self) -> float:
        return self.time

    def sleep(self, seconds: float) -> None:
        self.entered.set()
        # A step the test never releases ends the wait instead of hanging the run.
        if self.steps.acquire(timeout=STEP_TIMEOUT):
            self.time += seconds

    def release(self, count: int = 1) -> None:
        for _ in range(count):
            self.steps.release()


class TokenEndpoint:
    """The token endpoint, with an answer the test can change while the watcher polls it."""

    def __init__(self, httpserver: HTTPServer) -> None:
        self.body: Mapping[str, object] = {"error": "authorization_pending"}
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_handler(self.respond)

    def respond(self, _request: Request) -> Response:
        return Response(json.dumps(self.body), content_type="application/json")


@pytest.fixture
def clock() -> SteppedClock:
    return SteppedClock()


@pytest.fixture
def deps(httpserver: HTTPServer, fake_keyring, clock: SteppedClock) -> AuthDeps:
    base = httpserver.url_for("")
    return AuthDeps(
        store=KeyringCredentialStore(timeout=2.0, health=KeyringHealth()),
        client=GithubOAuthClient("test-client", oauth_url=base, api_url=base, clock=clock.now, timeout=5),
        now=clock.now,
        sleep=clock.sleep,
        environ={},
        validated={},
    )


@pytest.fixture
def make_login(deps: AuthDeps, clock: SteppedClock) -> Iterator[Callable[..., server.GithubLogin]]:
    """Build login states, then end any watcher a test left waiting."""
    built: list[server.GithubLogin] = []

    def make(grace_seconds: float = 0) -> server.GithubLogin:
        state = GithubLogin(deps, grace_seconds=grace_seconds)
        built.append(state)
        return state

    yield make

    clock.time += 10_000  # past any challenge's expiry, so a waiting watcher ends on its next step
    clock.release(len(built))
    for state in built:
        if state.watcher is not None:
            state.watcher.join(STEP_TIMEOUT)
            assert not state.watcher.is_alive(), "the login watcher did not end"


@pytest.fixture
def login(make_login: Callable[..., server.GithubLogin]) -> server.GithubLogin:
    return make_login()


@pytest.fixture
def idle_login() -> server.GithubLogin:
    """Login state for tests that never reach the auth service: the suite's `OSSIQ_GITHUB_AUTH=off` returns first."""
    return server.GithubLogin(default_deps(Settings()))


@pytest.fixture
def scans(monkeypatch: pytest.MonkeyPatch) -> list[Settings]:
    """Replace the update tool with one that records the settings it was handed."""
    seen: list[Settings] = []

    def handler(settings: Settings, _args: dict) -> dict:
        seen.append(settings)
        return DECISION

    monkeypatch.setitem(server.TOOL_HANDLERS, "ossiq_evaluate_updates", handler)
    return seen


def auto(**kwargs) -> Settings:
    """Settings with the login flow on; the autouse fixture turns it off for every other test."""
    return Settings(github_auth=GithubAuthMode.AUTO, **kwargs)


def call(state: server.GithubLogin, settings: Settings | None = None) -> dict:
    params = {"name": "ossiq_evaluate_updates", "arguments": {}}
    return server.handle_tools_call(settings or auto(), params, state)


def hits(httpserver: HTTPServer, path: str) -> int:
    return sum(1 for request, _ in httpserver.log if request.path == path)


def serve_device_code(httpserver: HTTPServer, **overrides: object) -> None:
    httpserver.expect_request(DEVICE_PATH, method="POST").respond_with_json({**DEVICE_BODY, **overrides})


def serve_user(httpserver: HTTPServer) -> None:
    httpserver.expect_request("/user").respond_with_json({"login": "octocat"})


def pending_challenge(*, expires_in: int = 900) -> DeviceChallenge:
    return DeviceChallenge(
        user_code="WDJB-4729",
        verification_uri="https://github.com/login/device",
        expires_at=int(NOW) + expires_in,
        interval=5,
        device_code="DEVICE-SECRET",
    )


def test_scan_is_called_without_a_progress_callback():
    """Regression: stdout is reserved for JSON-RPC, so the MCP front door must never drive the
    progress stepper. It used to pass a hand-rolled `noop_step` whose signature had to track
    scan()'s; now it passes nothing and `ScanProgress`'s own defaults do the swallowing.
    """
    with (
        patch.object(server, "scan") as scan,
        patch.object(server, "project_sources"),
        patch.object(server, "build_update_decide"),
    ):
        server.evaluate_updates(MagicMock(), {"project_path": ".", "runtime": "unknown"})

    assert scan.call_args.kwargs == {}
    assert len(scan.call_args.args) == 1


def test_initialize_echoes_protocol_and_advertises_tools(idle_login):
    response = server.handle_request(
        Settings(), {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, idle_login
    )
    assert response is not None
    assert response["id"] == 1
    assert response["result"]["serverInfo"]["name"] == "ossiq"
    assert "tools" in response["result"]["capabilities"]


def test_tools_list_returns_all_tools(idle_login):
    response = server.handle_request(Settings(), {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, idle_login)
    assert response is not None
    names = {tool["name"] for tool in response["result"]["tools"]}
    assert names == {"ossiq_evaluate_dependency", "ossiq_evaluate_updates", "ossiq_update_context"}


def test_notifications_get_no_response(idle_login):
    response = server.handle_request(Settings(), {"jsonrpc": "2.0", "method": "notifications/initialized"}, idle_login)
    assert response is None


def test_unknown_method_returns_error(idle_login):
    response = server.handle_request(Settings(), {"jsonrpc": "2.0", "id": 3, "method": "does/not/exist"}, idle_login)
    assert response is not None
    assert response["error"]["code"] == -32601


def test_tools_call_serializes_decision(monkeypatch, idle_login):
    monkeypatch.setitem(
        server.TOOL_HANDLERS, "ossiq_evaluate_updates", lambda _s, _a: {"next_action": "no action needed"}
    )
    params = {"name": "ossiq_evaluate_updates", "arguments": {"project_path": "."}}
    response = server.handle_request(
        Settings(), {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": params}, idle_login
    )
    assert response is not None
    assert response["result"]["content"][0]["text"] == '{"next_action": "no action needed"}'
    assert "isError" not in response["result"]


def test_tools_call_update_context_round_trip(monkeypatch, idle_login):
    monkeypatch.setitem(
        server.TOOL_HANDLERS,
        "ossiq_update_context",
        lambda _s, _a: {"package": "chalk", "to_version": "6.0.0", "breaking_change": "ESM-only from 5.0.0"},
    )
    params = {"name": "ossiq_update_context", "arguments": {"package": "chalk", "target_version": "6.0.0"}}
    response = server.handle_request(
        Settings(), {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": params}, idle_login
    )
    assert response is not None
    assert "isError" not in response["result"]
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload == {"package": "chalk", "to_version": "6.0.0", "breaking_change": "ESM-only from 5.0.0"}


def test_tools_call_unknown_tool_is_error(idle_login):
    params = {"name": "nope", "arguments": {}}
    response = server.handle_request(
        Settings(), {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": params}, idle_login
    )
    assert response is not None
    assert response["result"]["isError"] is True


def test_ping_returns_empty_result(idle_login):
    response = server.handle_request(Settings(), {"jsonrpc": "2.0", "id": 7, "method": "ping"}, idle_login)
    assert response == {"jsonrpc": "2.0", "id": 7, "result": {}}


def test_tool_schemas_required_fields_exist_in_properties():
    for tool in server.TOOLS:
        schema = tool["inputSchema"]
        for field in schema.get("required", []):
            assert field in schema["properties"], f"{tool['name']}: required '{field}' missing from properties"
        assert tool["name"] in server.TOOL_HANDLERS


def test_serve_loop_end_to_end(monkeypatch, capsys):
    """Full stdio session: framing, blank lines, garbage JSON, and notifications are handled."""
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}),
        "",
        "not json at all",
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ]
    monkeypatch.setattr("sys.stdin", io.StringIO("\n".join(lines) + "\n"))
    server.serve(Settings())
    output = capsys.readouterr().out
    responses = [json.loads(line) for line in output.strip().splitlines()]
    assert [response["id"] for response in responses] == [1, 2]
    assert responses[0]["result"]["protocolVersion"] == "2025-06-18"
    assert {tool["name"] for tool in responses[1]["result"]["tools"]} == set(server.TOOL_HANDLERS)


def test_tools_call_handler_exception_is_reported(monkeypatch, idle_login):
    def boom(_s, _a):
        raise ValueError("kaboom")

    monkeypatch.setitem(server.TOOL_HANDLERS, "ossiq_evaluate_updates", boom)
    params = {"name": "ossiq_evaluate_updates", "arguments": {}}
    response = server.handle_request(
        Settings(), {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": params}, idle_login
    )
    assert response is not None
    assert response["result"]["isError"] is True
    assert "kaboom" in response["result"]["content"][0]["text"]


def test_tools_call_application_error_includes_title_and_hint(monkeypatch, idle_login):
    """cli.py's error_boundary() already renders title+hint for ApplicationError; the MCP
    handler used to discard both and print only the class name and message, which is the
    direct source of the bare 'UnknownProjectPackageManager: Unable to identify Package
    Manager' text with no remedy that PLAN.md reported."""
    from ossiq.domain.exceptions import UnknownProjectPackageManager

    def boom(_s, _a):
        raise UnknownProjectPackageManager("Unable to identify Package Manager for project at .")

    monkeypatch.setitem(server.TOOL_HANDLERS, "ossiq_evaluate_updates", boom)
    params = {"name": "ossiq_evaluate_updates", "arguments": {}}
    response = server.handle_request(
        Settings(), {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": params}, idle_login
    )
    assert response is not None
    assert response["result"]["isError"] is True
    text = response["result"]["content"][0]["text"]
    assert "Unknown Package Manager" in text  # .title
    assert "ossiq supports" in text  # .hint, not just the exception name + message


def test_evaluate_updates_surfaces_degraded_data_sources(monkeypatch):
    """B4 on the MCP surface: an agent calling ossiq_evaluate_updates while OSV is unreachable
    must see that in the payload. The console gets show_scan_progress's warning; MCP bypasses
    the stepper entirely, so data_completeness inside the document is its only channel.
    """
    scan_result = ScanResult(
        project_name="proj",
        packages_registry="PYPI",
        project_path=".",
        production_packages=[],
        optional_packages=[],
        data_completeness=DataCompleteness(by_step={ScanStep.VULNERABILITIES: DataSourceStatus.UNREACHABLE}),
    )
    monkeypatch.setattr(server, "project_sources", MagicMock())
    monkeypatch.setattr(server, "scan", lambda _sources: scan_result)

    decision = server.evaluate_updates(Settings(), {"project_path": ".", "runtime": "unknown"})

    assert decision["data_completeness"]["overall"] == "unreachable"
    assert {"step": "vulnerabilities", "status": "unreachable"} in decision["data_completeness"]["sources"]


def test_a_missing_runtime_is_a_titled_error_not_a_probe(idle_login):
    """D1-1: the MCP server never falls back to probing its own PATH - that probe answers for the
    wrong shell, and it made identical requests disagree."""
    params = {"name": "ossiq_evaluate_updates", "arguments": {"project_path": "."}}

    response = server.handle_request(
        Settings(), {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": params}, idle_login
    )

    assert response is not None
    assert response["result"]["isError"] is True
    text = response["result"]["content"][0]["text"]
    assert "Runtime Not Provided" in text
    assert "node -v" in text


def test_a_stated_runtime_replaces_the_probe(monkeypatch):
    seen: list[Settings] = []
    monkeypatch.setattr(server, "project_sources", MagicMock())
    monkeypatch.setattr(server, "scan", MagicMock())
    monkeypatch.setattr(server, "build_update_decide", MagicMock(return_value={}))
    monkeypatch.setattr(
        server.project_sources, "build_project_sources", lambda settings, *_a, **_k: seen.append(settings)
    )

    server.evaluate_updates(Settings(), {"project_path": ".", "runtime": {"node": "22.12.0"}})
    server.evaluate_updates(Settings(), {"project_path": ".", "runtime": "unknown"})

    stated, unknown = seen
    assert (stated.probe_runtime, stated.engine_versions, stated.runtime_unknown) == (False, {"node": "22.12.0"}, False)
    assert (unknown.probe_runtime, unknown.engine_versions, unknown.runtime_unknown) == (False, {}, True)


def test_every_scanning_tool_requires_a_runtime():
    assert all("runtime" in tool["inputSchema"]["required"] for tool in server.TOOLS)


def test_every_tool_description_tells_the_agent_about_the_login():
    assert all("login" in tool["description"].lower() for tool in server.TOOLS)


class TestLoginChallenge:
    def test_the_first_call_without_a_token_returns_the_challenge_in_band(self, login, httpserver, scans):
        serve_device_code(httpserver)

        result = call(login)

        text = result["content"][0]["text"]
        assert result["isError"] is False
        assert "https://github.com/login/device" in text
        assert "WDJB-4729" in text
        assert "call this tool again" in text
        assert result["_meta"] == {
            "auth_status": "PENDING_USER_ACTION",
            "verification_uri": "https://github.com/login/device",
            "user_code": "WDJB-4729",
            "expires_in": 900,
            "interval": 5,
        }
        assert "DEVICE-SECRET" not in json.dumps(result)
        assert scans == []
        assert hits(httpserver, DEVICE_PATH) == 1
        assert login.watcher is not None and login.watcher.is_alive() and login.watcher.daemon

    def test_a_second_call_while_pending_returns_the_same_challenge_without_polling(
        self, login, httpserver, clock, scans
    ):
        serve_device_code(httpserver)
        first = call(login)
        watcher = login.watcher
        clock.time += 60

        second = call(login)

        assert second["_meta"]["user_code"] == first["_meta"]["user_code"]
        assert second["_meta"]["expires_in"] == 840
        assert hits(httpserver, DEVICE_PATH) == 1
        assert hits(httpserver, TOKEN_PATH) == 0  # the watcher sleeps first and the caller never polls beside it
        assert login.watcher is watcher
        assert scans == []

    def test_a_valid_pending_login_from_an_earlier_process_is_resumed_not_replaced(
        self, login, deps, httpserver, clock, scans
    ):
        TokenEndpoint(httpserver)
        deps.store.write_pending(pending_challenge())

        result = call(login)
        assert clock.entered.wait(STEP_TIMEOUT)  # the watcher is as far as it gets without a step

        assert result["_meta"]["user_code"] == "WDJB-4729"
        assert hits(httpserver, DEVICE_PATH) == 0
        assert hits(httpserver, TOKEN_PATH) == 1  # the call's own poll: the watcher sleeps before its first
        assert login.watching()

    def test_an_expired_pending_login_from_an_earlier_process_gets_a_fresh_code(self, login, deps, httpserver, scans):
        serve_device_code(httpserver, user_code="NEWC-0DE1")
        deps.store.write_pending(pending_challenge(expires_in=-1))

        result = call(login)

        assert result["_meta"]["user_code"] == "NEWC-0DE1"
        assert hits(httpserver, DEVICE_PATH) == 1
        assert login.watching()

    def test_a_login_approved_while_the_server_was_down_scans_at_once(self, login, deps, httpserver, scans):
        token = TokenEndpoint(httpserver)
        token.body = GRANTED
        deps.store.write_pending(pending_challenge())

        result = call(login)

        assert json.loads(result["content"][0]["text"]) == DECISION
        assert scans[0].github_token == "gho_login"
        assert login.watcher is None


class TestWatching:
    def test_a_finished_watcher_is_not_watching_even_before_its_thread_has_exited(self, login):
        """The event is set after `outcome`, so a call that sees it set also sees the outcome; a thread
        that is merely still alive must not make the call return a challenge the login already ended."""
        release = threading.Event()
        login.watcher = threading.Thread(target=release.wait, args=(STEP_TIMEOUT,), daemon=True)
        login.watcher.start()
        try:
            login.finished.set()

            assert login.watcher.is_alive()
            assert not login.watching()
        finally:
            release.set()
            login.watcher.join(STEP_TIMEOUT)

    def test_nothing_is_watched_before_the_first_challenge(self, login):
        assert not login.watching()


class TestLoginApproval:
    def test_after_approval_the_next_call_scans_with_the_new_token(self, login, deps, httpserver, clock, scans):
        serve_device_code(httpserver)
        serve_user(httpserver)
        token = TokenEndpoint(httpserver)
        call(login)
        token.body = GRANTED

        clock.release()
        assert login.finished.wait(STEP_TIMEOUT)
        result = call(login)

        assert json.loads(result["content"][0]["text"]) == DECISION
        assert scans[0].github_token == "gho_login"
        stored = deps.store.read_credentials()
        assert stored is not None and stored.access_token == "gho_login"
        assert deps.store.read_pending() is None

    def test_a_retry_just_after_the_approval_waits_for_the_watcher(self, make_login, httpserver, clock, scans):
        patient = make_login(grace_seconds=STEP_TIMEOUT)
        serve_device_code(httpserver)
        serve_user(httpserver)
        token = TokenEndpoint(httpserver)
        call(patient)
        token.body = GRANTED
        threading.Timer(0.05, clock.release).start()  # the watcher's next poll lands while the retry waits

        result = call(patient)

        assert json.loads(result["content"][0]["text"]) == DECISION
        assert scans[0].github_token == "gho_login"

    @pytest.mark.parametrize(
        ("error", "reason"),
        [("access_denied", AuthSkipReason.LOGIN_DENIED), ("expired_token", AuthSkipReason.LOGIN_EXPIRED)],
    )
    def test_a_login_that_ended_without_approval_is_not_asked_for_again(
        self, login, httpserver, clock, scans, caplog, error, reason
    ):
        serve_device_code(httpserver)
        token = TokenEndpoint(httpserver)
        call(login)
        token.body = {"error": error}

        clock.release()
        assert login.finished.wait(STEP_TIMEOUT)
        results = [call(login), call(login)]

        assert login.outcome is reason
        assert [json.loads(result["content"][0]["text"]) for result in results] == [DECISION, DECISION]
        assert [seen.github_token for seen in scans] == [None, None]
        assert hits(httpserver, DEVICE_PATH) == 1
        assert reason.value in caplog.text

    def test_a_login_that_cannot_be_saved_degrades_the_next_call(
        self, login, httpserver, clock, fake_keyring, scans, caplog
    ):
        serve_device_code(httpserver)
        token = TokenEndpoint(httpserver)
        call(login)
        token.body = GRANTED
        fake_keyring.fail_with = keyring.errors.KeyringLocked("locked")

        clock.release()
        assert login.finished.wait(STEP_TIMEOUT)
        result = call(login)

        assert json.loads(result["content"][0]["text"]) == DECISION
        assert scans[0].github_token is None
        assert "could not be saved" in caplog.text
        assert AuthSkipReason.STORE_UNAVAILABLE.value in caplog.text


class TestLoginSkipped:
    def test_an_explicit_token_needs_no_login_and_never_touches_the_keyring(
        self, login, httpserver, fake_keyring, scans
    ):
        result = call(login, auto(github_token="gho_explicit"))

        assert json.loads(result["content"][0]["text"]) == DECISION
        assert scans[0].github_token == "gho_explicit"
        assert httpserver.log == []
        assert fake_keyring.calls == []

    def test_an_unknown_tool_never_starts_a_login(self, login, httpserver):
        result = server.handle_tools_call(auto(), {"name": "nope", "arguments": {}}, login)

        assert result["isError"] is True
        assert httpserver.log == []
        assert login.watcher is None

    def test_the_users_own_opt_out_is_not_logged_as_a_warning(self, idle_login, scans, caplog):
        call(idle_login, Settings())

        assert scans != []
        assert caplog.text == ""


def test_the_serve_loop_keeps_stdout_to_one_json_object_per_response(
    monkeypatch, capsys, make_login, deps, httpserver, scans
):
    serve_device_code(httpserver)
    TokenEndpoint(httpserver)
    monkeypatch.setattr(server, "default_deps", lambda _settings: deps)
    monkeypatch.setattr(server, "GithubLogin", lambda _deps: make_login())
    params = {"name": "ossiq_evaluate_updates", "arguments": {}}
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": params}),
        json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": params}),
    ]
    monkeypatch.setattr("sys.stdin", io.StringIO("\n".join(lines) + "\n"))

    server.serve(auto())

    responses = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [response["id"] for response in responses] == [1, 2, 3]
    assert responses[1]["result"]["_meta"]["user_code"] == responses[2]["result"]["_meta"]["user_code"]
    assert hits(httpserver, DEVICE_PATH) == 1
