"""
Shared fixtures for HTTP-level integration tests against batch.py.

Uses pytest-httpserver (a real Werkzeug HTTP server) to simulate API failure
modes without any mocking — requests.Session makes genuine TCP connections.
"""

import threading

import pytest
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Request, Response


@pytest.fixture
def server_500(httpserver: HTTPServer):
    """Always returns 500 — retries will be exhausted and chunk dropped."""
    for _ in range(4):  # max_retries=3 means up to 3 attempts
        httpserver.expect_ordered_request("/test").respond_with_data("Internal Server Error", status=500)
    yield httpserver
    httpserver.clear()


@pytest.fixture
def server_503_then_200(httpserver: HTTPServer):
    """Fails once with 503, then succeeds — exercises the retry-then-succeed path."""
    httpserver.expect_ordered_request("/test").respond_with_data("Service Unavailable", status=503)
    httpserver.expect_ordered_request("/test").respond_with_data(
        '{"items": []}', status=200, content_type="application/json"
    )
    yield httpserver
    httpserver.clear()


@pytest.fixture
def server_429_retry_after(httpserver: HTTPServer):
    """Returns 429 with Retry-After: 2 on first request, then 200.

    Note: tests should use a patched time.sleep to avoid real waiting.
    """
    httpserver.expect_ordered_request("/test").respond_with_data("", status=429, headers={"Retry-After": "2"})
    httpserver.expect_ordered_request("/test").respond_with_data(
        '{"items": []}', status=200, content_type="application/json"
    )
    yield httpserver
    httpserver.clear()


@pytest.fixture
def server_429_no_header(httpserver: HTTPServer):
    """Returns 429 without Retry-After (tests the 30-second default fallback path).

    Note: tests should use a patched time.sleep to avoid real waiting.
    """
    httpserver.expect_ordered_request("/test").respond_with_data("", status=429)
    httpserver.expect_ordered_request("/test").respond_with_data(
        '{"items": []}', status=200, content_type="application/json"
    )
    yield httpserver
    httpserver.clear()


@pytest.fixture
def server_timeout(httpserver: HTTPServer):
    """Hangs indefinitely — the client's request_timeout should fire.

    Uses threading.Event.wait() instead of time.sleep() so that patching
    time.sleep in tests does NOT accidentally unblock this handler.
    """
    _hang = threading.Event()  # never set — blocks forever (up to 60 s safety cap)

    def slow_handler(request: Request) -> Response:
        _hang.wait(timeout=60)  # blocks without calling time.sleep
        return Response("too late", status=200)

    httpserver.expect_request("/test").respond_with_handler(slow_handler)
    yield httpserver
    _hang.set()  # unblock any lingering handler threads before teardown
    httpserver.clear()


@pytest.fixture
def server_429_zero_remaining(httpserver: HTTPServer):
    """Returns 429 with x-ratelimit-remaining: 0 — hard quota exhaustion.

    Only one request is expected: the abort signal prevents any retry.
    """
    httpserver.expect_ordered_request("/test").respond_with_data("", status=429, headers={"x-ratelimit-remaining": "0"})
    yield httpserver
    httpserver.clear()


@pytest.fixture
def server_connection_error(httpserver: HTTPServer):
    """Stops the server mid-test to simulate a ConnectionError."""
    yield httpserver
    # Caller is responsible for calling httpserver.stop() to trigger the error
