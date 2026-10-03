"""
Tests for install_requests_cache (ossiq.clients).
"""

from unittest.mock import patch

import pytest
import requests
import requests_cache

import ossiq.clients
from ossiq.clients import GITHUB_USER_URL, install_requests_cache, trim_vary_header
from ossiq.clients.client_github import GITHUB_API
from ossiq.clients.client_github_oauth import GithubOAuthClient, OAuthFailure
from ossiq.domain.github_auth import DeviceChallenge, GithubCredentials


def test_install_requests_cache_sets_stability_url_ttls():
    with patch("ossiq.clients.requests_cache.install_cache") as install_cache:
        install_requests_cache("cache.sqlite3", 24, 168)

    install_cache.assert_called_once_with(
        cache_name="cache.sqlite3",
        backend="sqlite",
        expire_after=24 * 3600,
        urls_expire_after={
            # A replayed quota reading is worse than none, so the pre-flight check never caches.
            "*/rate_limit*": requests_cache.DO_NOT_CACHE,
            # A replayed poll never completes a login, and the token response holds the secrets.
            "*/login/*": requests_cache.DO_NOT_CACHE,
            GITHUB_USER_URL: requests_cache.DO_NOT_CACHE,
            "*/commits*": 168 * 3600,
            "*/graphql*": 168 * 3600,
            "*/readme*": 168 * 3600,
        },
        allowable_methods=("GET", "POST"),
        filter_fn=trim_vary_header,
    )


def make_response(vary: str | None) -> requests.Response:
    response = requests.Response()
    if vary is not None:
        response.headers["Vary"] = vary
    return response


def test_trim_vary_header_drops_auth_and_cookie_entries():
    response = make_response("Accept, Authorization, Cookie, X-GitHub-OTP, Accept-Encoding")
    assert trim_vary_header(response) is True
    assert response.headers["Vary"] == "Accept, Accept-Encoding"


def test_trim_vary_header_removes_the_header_when_only_noise_remains():
    response = make_response("Authorization, Cookie")
    trim_vary_header(response)
    assert "Vary" not in response.headers


def test_trim_vary_header_is_a_noop_without_vary():
    response = make_response(None)
    assert trim_vary_header(response) is True
    assert "Vary" not in response.headers


# --- The GitHub login must never be replayed from, or recorded in, the cache ------------------

TOKEN_PATH = "/login/oauth/access_token"
CHALLENGE = DeviceChallenge(
    user_code="WDJB-4729",
    verification_uri="https://github.com/login/device",
    expires_at=2_000_000,
    interval=5,
    device_code="DEVICE-SECRET",
)


@pytest.fixture
def install_cache(tmp_path):
    """Install ossiq's real HTTP cache on a temp file; it is removed again after the test."""
    cache_file = tmp_path / "cache.sqlite3"

    def install():
        install_requests_cache(str(cache_file), 24, 168)
        return cache_file

    yield install
    requests_cache.uninstall_cache()


def cache_file_bytes(cache_file) -> bytes:
    requests_cache.uninstall_cache()  # releases the sqlite file so everything is on disk
    return b"".join(path.read_bytes() for path in cache_file.parent.glob(cache_file.name + "*"))


def test_github_user_url_is_the_api_user_endpoint():
    assert GITHUB_USER_URL == f"{GITHUB_API}/user"


def test_login_polls_are_not_replayed_from_the_cache(install_cache, httpserver):
    install_cache()
    client = GithubOAuthClient("test-client", oauth_url=httpserver.url_for(""), clock=lambda: 1_000_000)
    httpserver.expect_ordered_request(TOKEN_PATH, method="POST").respond_with_json({"error": "authorization_pending"})
    httpserver.expect_ordered_request(TOKEN_PATH, method="POST").respond_with_json({"access_token": "gho_granted"})

    first = client.poll_once(CHALLENGE, 5)
    second = client.poll_once(CHALLENGE, 5)

    assert isinstance(first, OAuthFailure)
    assert isinstance(second, GithubCredentials)
    assert len(httpserver.log) == 2


def test_login_tokens_never_reach_the_cache_file(install_cache, httpserver):
    cache_file = install_cache()
    client = GithubOAuthClient("test-client", oauth_url=httpserver.url_for(""), clock=lambda: 1_000_000)
    granted = {"access_token": "gho_LOGINTOKEN", "refresh_token": "ghr_LOGINREFRESH"}
    httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json(granted)
    # Control: the same kind of answer from a path the cache does store, to prove the scan below can see it.
    httpserver.expect_request("/other/token", method="POST").respond_with_json(
        {"access_token": "gho_CONTROLTOKEN", "refresh_token": "ghr_CONTROLREFRESH"}
    )

    client.poll_once(CHALLENGE, 5)
    client.refresh("ghr_old")
    requests.post(httpserver.url_for("/other/token"), data={"client_id": "x"}, timeout=5)
    stored = cache_file_bytes(cache_file)

    assert b"gho_CONTROLTOKEN" in stored
    assert b"gho_LOGINTOKEN" not in stored
    assert b"ghr_LOGINREFRESH" not in stored


def test_user_lookup_is_not_answered_from_another_tokens_entry(install_cache, httpserver, monkeypatch):
    monkeypatch.setattr(ossiq.clients, "GITHUB_USER_URL", httpserver.url_for("/user"))
    install_cache()
    client = GithubOAuthClient("test-client", api_url=httpserver.url_for(""))
    httpserver.expect_ordered_request("/user").respond_with_json({"login": "alice"})
    httpserver.expect_ordered_request("/user").respond_with_json({"login": "bob"})

    assert client.fetch_login("gho_alice_token") == "alice"
    assert client.fetch_login("gho_bob_token") == "bob"
