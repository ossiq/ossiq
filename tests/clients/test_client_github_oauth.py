"""Tests for the GitHub OAuth device-flow client, run against a real local HTTP server."""

import pytest
from pytest_httpserver import HTTPServer

from ossiq.clients.client_github_oauth import DEVICE_GRANT_TYPE, GithubOAuthClient, OAuthErrorCode, OAuthFailure
from ossiq.domain.github_auth import DeviceChallenge, GithubCredentials

NOW = 1_000_000
TOKEN_PATH = "/login/oauth/access_token"
CHALLENGE = DeviceChallenge(
    user_code="WDJB-4729",
    verification_uri="https://github.com/login/device",
    expires_at=NOW + 900,
    interval=5,
    device_code="DEVICE-SECRET",
)
GRANTED = {
    "access_token": "gho_access",
    "refresh_token": "ghr_refresh",
    "expires_in": 28800,
    "refresh_token_expires_in": 15638400,
    "token_type": "bearer",
    "scope": "",
}


@pytest.fixture
def client(httpserver: HTTPServer) -> GithubOAuthClient:
    base = httpserver.url_for("")
    return GithubOAuthClient("test-client", oauth_url=base, api_url=base, clock=lambda: NOW, timeout=5)


def sent_form(httpserver: HTTPServer, index: int = 0) -> dict[str, str]:
    request, _ = httpserver.log[index]
    return request.form.to_dict()


class TestRequestDeviceCode:
    def test_returns_the_challenge_with_an_absolute_expiry(self, client, httpserver):
        httpserver.expect_request("/login/device/code", method="POST").respond_with_json(
            {
                "device_code": "DC",
                "user_code": "WDJB-4729",
                "verification_uri": "https://github.com/login/device",
                "expires_in": 900,
                "interval": 5,
            }
        )

        result = client.request_device_code()

        assert result == DeviceChallenge(
            user_code="WDJB-4729",
            verification_uri="https://github.com/login/device",
            expires_at=NOW + 900,
            interval=5,
            device_code="DC",
        )

    def test_sends_only_the_client_id_so_no_scope_is_requested(self, client, httpserver):
        httpserver.expect_request("/login/device/code", method="POST").respond_with_json({"error": "x"})

        client.request_device_code()

        assert sent_form(httpserver) == {"client_id": "test-client"}
        request, _ = httpserver.log[0]
        assert request.headers["Accept"] == "application/json"

    def test_reports_a_disabled_device_flow(self, client, httpserver):
        httpserver.expect_request("/login/device/code", method="POST").respond_with_json(
            {"error": "device_flow_disabled", "error_description": "Device Flow must be explicitly enabled"}
        )

        result = client.request_device_code()

        assert result == OAuthFailure(
            OAuthErrorCode.DEVICE_FLOW_DISABLED, "device_flow_disabled", "Device Flow must be explicitly enabled"
        )

    def test_rejects_an_incomplete_answer(self, client, httpserver):
        httpserver.expect_request("/login/device/code", method="POST").respond_with_json({"device_code": "DC"})

        result = client.request_device_code()

        assert isinstance(result, OAuthFailure)
        assert result.code is OAuthErrorCode.INVALID_RESPONSE

    @pytest.mark.parametrize(
        "uri",
        [
            "http://github.com/login/device",
            "https://github.example/login/device",
            "https://github.com.evil.example/login/device",
            "https://github.com@evil.example/login/device",
            "https://evil.example@github.com/login/device",
            "https://github.com:8443/login/device",
            "https://github.com:notaport/login/device",
            "javascript:alert(1)",
            "",
        ],
    )
    def test_refuses_a_verification_page_outside_github_without_echoing_it(self, client, httpserver, uri):
        httpserver.expect_request("/login/device/code", method="POST").respond_with_json(
            {
                "device_code": "DC",
                "user_code": "WDJB-4729",
                "verification_uri": uri,
                "expires_in": 900,
                "interval": 5,
            }
        )

        result = client.request_device_code()

        assert result == OAuthFailure(
            OAuthErrorCode.INVALID_RESPONSE, description="device code response names a page outside github.com"
        )

    @pytest.mark.parametrize(
        "uri",
        ["https://GitHub.com/login/device", "https://github.com:443/login/device"],
    )
    def test_accepts_github_in_any_case_and_with_the_default_port(self, client, httpserver, uri):
        httpserver.expect_request("/login/device/code", method="POST").respond_with_json(
            {
                "device_code": "DC",
                "user_code": "WDJB-4729",
                "verification_uri": uri,
                "expires_in": 900,
                "interval": 5,
            }
        )

        result = client.request_device_code()

        assert isinstance(result, DeviceChallenge)
        assert result.verification_uri == uri


class TestPollOnce:
    def test_walks_pending_then_slow_down_then_granted(self, client, httpserver):
        httpserver.expect_ordered_request(TOKEN_PATH, method="POST").respond_with_json(
            {"error": "authorization_pending"}
        )
        httpserver.expect_ordered_request(TOKEN_PATH, method="POST").respond_with_json(
            {"error": "slow_down", "interval": 10}
        )
        httpserver.expect_ordered_request(TOKEN_PATH, method="POST").respond_with_json(GRANTED)

        interval = 5
        results = []
        for _ in range(3):
            result = client.poll_once(CHALLENGE, interval)
            results.append(result)
            if isinstance(result, OAuthFailure) and result.interval is not None:
                interval = result.interval

        pending, slow_down, granted = results
        assert isinstance(pending, OAuthFailure) and pending.code is OAuthErrorCode.AUTHORIZATION_PENDING
        assert pending.interval == 5
        assert isinstance(slow_down, OAuthFailure) and slow_down.code is OAuthErrorCode.SLOW_DOWN
        assert slow_down.interval == 10
        assert granted == GithubCredentials(
            access_token="gho_access",
            refresh_token="ghr_refresh",
            expires_at=NOW + 28800,
            scope="",
            token_type="bearer",
        )

    def test_sends_the_device_grant_and_no_secret(self, client, httpserver):
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json({"error": "authorization_pending"})

        client.poll_once(CHALLENGE, 5)

        assert sent_form(httpserver) == {
            "client_id": "test-client",
            "device_code": "DEVICE-SECRET",
            "grant_type": DEVICE_GRANT_TYPE,
        }

    def test_slow_down_without_an_interval_adds_five_seconds(self, client, httpserver):
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json({"error": "slow_down"})

        result = client.poll_once(CHALLENGE, 7)

        assert isinstance(result, OAuthFailure)
        assert result.interval == 12

    def test_slow_down_trusts_a_named_interval_even_when_it_equals_the_current_one(self, client, httpserver):
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json({"error": "slow_down", "interval": 5})

        result = client.poll_once(CHALLENGE, 5)

        assert isinstance(result, OAuthFailure)
        assert result.interval == 5

    @pytest.mark.parametrize(
        ("error", "code"),
        [
            ("expired_token", OAuthErrorCode.EXPIRED_TOKEN),
            ("access_denied", OAuthErrorCode.ACCESS_DENIED),
            ("device_flow_disabled", OAuthErrorCode.DEVICE_FLOW_DISABLED),
            ("incorrect_device_code", OAuthErrorCode.REJECTED),
        ],
    )
    def test_terminal_errors_keep_no_interval(self, client, httpserver, error, code):
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json(
            {"error": error, "error_description": "why"}
        )

        result = client.poll_once(CHALLENGE, 5)

        assert result == OAuthFailure(code, error, "why", None)

    def test_classifies_by_the_body_not_the_http_status(self, client, httpserver):
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json({"error": "access_denied"}, status=400)

        result = client.poll_once(CHALLENGE, 5)

        assert isinstance(result, OAuthFailure)
        assert result.code is OAuthErrorCode.ACCESS_DENIED

    def test_unreachable_server_is_a_network_error_not_an_exception(self):
        unreachable = GithubOAuthClient("test-client", oauth_url="http://127.0.0.1:1", timeout=1)

        result = unreachable.poll_once(CHALLENGE, 5)

        assert isinstance(result, OAuthFailure)
        assert result.code is OAuthErrorCode.NETWORK_ERROR

    @pytest.mark.parametrize(
        "response",
        [
            {"response_data": "<html>Bad Gateway</html>", "status": 502, "content_type": "text/html"},
            {"response_data": "[1, 2]", "status": 200, "content_type": "application/json"},
            {"response_data": "{}", "status": 200, "content_type": "application/json"},
        ],
        ids=["html", "json-list", "empty-object"],
    )
    def test_anything_that_is_not_credentials_or_an_error_is_an_invalid_response(self, client, httpserver, response):
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_data(**response)

        result = client.poll_once(CHALLENGE, 5)

        assert isinstance(result, OAuthFailure)
        assert result.code is OAuthErrorCode.INVALID_RESPONSE

    def test_a_token_without_expiry_or_refresh_token_is_non_expiring(self, client, httpserver):
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json(
            {"access_token": "gho_plain", "token_type": "bearer", "scope": ""}
        )

        result = client.poll_once(CHALLENGE, 5)

        assert result == GithubCredentials(access_token="gho_plain", refresh_token=None, expires_at=None)


class TestRefresh:
    def test_rotates_both_tokens_with_no_client_secret(self, client, httpserver):
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json(
            {**GRANTED, "access_token": "gho_new", "refresh_token": "ghr_new"}
        )

        result = client.refresh("ghr_refresh")

        assert result == GithubCredentials(
            access_token="gho_new", refresh_token="ghr_new", expires_at=NOW + 28800, scope="", token_type="bearer"
        )
        assert sent_form(httpserver) == {
            "client_id": "test-client",
            "grant_type": "refresh_token",
            "refresh_token": "ghr_refresh",
        }

    def test_an_answer_without_a_refresh_token_yields_none(self, client, httpserver):
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json({"access_token": "gho_new"})

        result = client.refresh("ghr_refresh")

        assert isinstance(result, GithubCredentials)
        assert result.refresh_token is None
        assert result.expires_at is None

    def test_a_spent_refresh_token_is_a_failure_despite_http_200(self, client, httpserver):
        httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json(
            {"error": "incorrect_client_credentials", "error_description": "The client_id is incorrect."}, status=200
        )

        result = client.refresh("ghr_spent")

        assert result == OAuthFailure(
            OAuthErrorCode.REJECTED, "incorrect_client_credentials", "The client_id is incorrect.", None
        )


class TestFetchLogin:
    def test_returns_the_login_and_sends_the_token_as_a_bearer(self, client, httpserver):
        httpserver.expect_request("/user", headers={"Authorization": "Bearer gho_tok"}).respond_with_json(
            {"login": "octocat", "id": 1}
        )

        assert client.fetch_login("gho_tok") == "octocat"

    def test_a_401_means_the_token_is_unauthorized(self, client, httpserver):
        httpserver.expect_request("/user").respond_with_json({"message": "Bad credentials"}, status=401)

        result = client.fetch_login("gho_revoked")

        assert isinstance(result, OAuthFailure)
        assert result.code is OAuthErrorCode.UNAUTHORIZED

    def test_an_answer_without_a_login_is_invalid(self, client, httpserver):
        httpserver.expect_request("/user").respond_with_json({"id": 1})

        result = client.fetch_login("gho_tok")

        assert isinstance(result, OAuthFailure)
        assert result.code is OAuthErrorCode.INVALID_RESPONSE

    def test_unreachable_server_is_a_network_error(self):
        unreachable = GithubOAuthClient("test-client", api_url="http://127.0.0.1:1", timeout=1)

        result = unreachable.fetch_login("gho_tok")

        assert isinstance(result, OAuthFailure)
        assert result.code is OAuthErrorCode.NETWORK_ERROR
