"""
Tests for install_requests_cache (ossiq.clients).
"""

from unittest.mock import patch

import requests

from ossiq.clients import install_requests_cache, trim_vary_header


def test_install_requests_cache_sets_stability_url_ttls():
    with patch("ossiq.clients.requests_cache.install_cache") as install_cache:
        install_requests_cache("cache.sqlite3", 24, 168)

    install_cache.assert_called_once_with(
        cache_name="cache.sqlite3",
        backend="sqlite",
        expire_after=24 * 3600,
        urls_expire_after={
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
