"""
Integration tests for BatchClient against a real HTTP server.

Unlike test_batch.py (which mocks requests.Session), these tests run a real
Werkzeug HTTP server via pytest-httpserver.  requests.Session makes genuine
TCP connections, so the full BatchClient stack — retry logic, gate mechanism,
Retry-After header parsing — executes against real HTTP responses.

Test strategy
-------------
RealHTTPBatchStrategy is a minimal concrete BatchStrategy that points at the
pytest-httpserver URL.  A short request_timeout (0.1 s) keeps timeout tests fast.
time.sleep is patched in rate-limit tests to skip the actual wait without
altering the code path.
"""

import threading
from unittest.mock import patch

import requests
from werkzeug.wrappers import Request, Response

from ossiq.clients.batch import BatchClient, BatchStrategy, BatchStrategySettings, ChunkResult

# ---------------------------------------------------------------------------
# Concrete strategy that uses a real requests.Session
# ---------------------------------------------------------------------------


class RealHTTPBatchStrategy(BatchStrategy):
    """
    Minimal BatchStrategy that hits a configurable URL with a real session.

    No mocking — requests.Session makes genuine TCP connections to the test server.
    """

    def __init__(self, url: str, timeout: float = 10.0, max_retries: int = 3, chunk_size: int = 5):
        self._session = requests.Session()
        self._url = url
        self._timeout = timeout
        self._max_retries = max_retries
        self._config = BatchStrategySettings(
            chunk_size=chunk_size,
            max_retries=max_retries,
            max_workers=3,
            request_timeout=timeout,
            has_pagination=False,
        )

    @property
    def config(self) -> BatchStrategySettings:
        return self._config

    def prepare_item(self, item):
        return item

    def perform_request(self, chunk: list) -> requests.Response:
        # NOTE: Do NOT call raise_for_status() here — BatchClient handles it.
        return self._session.post(self._url, json={"items": chunk}, timeout=self._timeout)

    def process_response(self, source_items: list, response: ChunkResult):
        return response.data[0] if response.data else None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run(url: str, items=None, timeout: float = 10.0, max_retries: int = 3, chunk_size: int = 5) -> list:
    """Execute run_batch and collect all results into a list."""
    if items is None:
        items = list(range(5))
    strategy = RealHTTPBatchStrategy(url, timeout=timeout, max_retries=max_retries, chunk_size=chunk_size)
    client = BatchClient(strategy)
    return list(client.run_batch(items))


# ---------------------------------------------------------------------------
# 500 / 5xx error handling
# ---------------------------------------------------------------------------


class TestBatch5xxRetry:
    def test_permanent_500_drops_chunk(self, server_500, httpserver):
        """All retries exhausted on 500 → chunk silently dropped, no exception raised."""
        results = run(httpserver.url_for("/test"), max_retries=3)
        assert results == []

    def test_single_503_then_200_succeeds(self, server_503_then_200, httpserver):
        """One 503 followed by 200 → BatchClient retries and returns data."""
        with patch("ossiq.clients.batch.time.sleep"):  # skip backoff wait
            results = run(httpserver.url_for("/test"))
        assert len(results) == 1
        assert results[0] == {"items": []}


# ---------------------------------------------------------------------------
# 429 Rate-Limit + Retry-After header
# ---------------------------------------------------------------------------


class TestBatch429RealServer:
    def test_respects_retry_after_header(self, server_429_retry_after, httpserver):
        """Real 429 + Retry-After header → gate closes, thread sleeps, gate reopens."""
        with patch("ossiq.clients.batch.time.sleep"):  # skip the actual wait
            results = run(httpserver.url_for("/test"))
        # Completed without exception; data returned from the second (200) response
        assert len(results) == 1

    def test_defaults_to_30s_without_retry_after(self, server_429_no_header, httpserver):
        """429 with no Retry-After → default 30 s fallback (sleep is patched)."""
        sleep_calls = []

        def record_sleep(seconds):
            sleep_calls.append(seconds)

        with patch("ossiq.clients.batch.time.sleep", side_effect=record_sleep):
            results = run(httpserver.url_for("/test"))

        assert len(results) == 1
        # Each tick in the gate sleep loop is 1 second × 30 iterations
        assert len(sleep_calls) == 30
        assert all(s == 1 for s in sleep_calls)

    def test_zero_remaining_aborts_entire_batch(self, server_429_zero_remaining, httpserver):
        """Real 429 + x-ratelimit-remaining: 0 → batch aborted with no results.

        No sleep patching needed: this path never calls time.sleep.
        Verifies the full stack: real TCP → _handle_rate_limit → _abort → run_batch exits.
        """
        strategy = RealHTTPBatchStrategy(httpserver.url_for("/test"), max_retries=3, chunk_size=5)
        client = BatchClient(strategy)
        results = list(client.run_batch(list(range(5))))

        assert results == []
        assert client._abort.is_set()


# ---------------------------------------------------------------------------
# Timeout handling
# ---------------------------------------------------------------------------


class TestBatchTimeout:
    def test_request_timeout_triggers_retry_then_drop(self, server_timeout, httpserver):
        """Server hangs → requests.Timeout on every attempt → chunk dropped."""
        with patch("ossiq.clients.batch.time.sleep"):  # skip backoff wait
            results = run(httpserver.url_for("/test"), timeout=0.1, max_retries=2)
        assert results == []

    def test_timeout_retried_correct_number_of_times(self, server_timeout, httpserver):
        """Verify the number of actual HTTP attempts equals max_retries."""
        attempt_count = 0

        class CountingStrategy(RealHTTPBatchStrategy):
            def perform_request(self, chunk):
                nonlocal attempt_count
                attempt_count += 1
                return super().perform_request(chunk)

        with patch("ossiq.clients.batch.time.sleep"):
            strategy = CountingStrategy(httpserver.url_for("/test"), timeout=0.1, max_retries=3)
            client = BatchClient(strategy)
            list(client.run_batch(list(range(5))))

        assert attempt_count == 3


# ---------------------------------------------------------------------------
# Connection error (server goes away)
# ---------------------------------------------------------------------------


class TestBatchConnectionError:
    def test_connection_refused_drops_chunk(self):
        """Connecting to a port with nothing listening → ConnectionError → chunk dropped."""
        # Port 19999 should be free; if it happens to be in use the test will still
        # pass because any connection failure produces the same code path.
        with patch("ossiq.clients.batch.time.sleep"):
            results = run("http://127.0.0.1:19999/test", max_retries=2)
        assert results == []


# ---------------------------------------------------------------------------
# 429 gate coordination across multiple concurrent threads
# ---------------------------------------------------------------------------


class TestBatch429MultiThread:
    def test_all_threads_wait_at_gate_then_resume(self, httpserver):
        """Multiple concurrent chunks all hit 429 → gate coordinates the wait → all resume.

        Design:
        - 3 chunks (15 items, chunk_size=5) → 3 worker threads
        - Server returns 429+Retry-After:1 for the first 3 requests (one per chunk)
        - Server returns 200 for all subsequent requests (the retries)
        - After the gate mechanism runs, all three chunks succeed → 3 results returned

        Note on sleep_calls with mocked sleep:
        With time.sleep patched to a no-op, each gate-winner sleep loop runs instantly.
        A thread that arrives at _handle_rate_limit while the gate is already re-open
        (because the previous winner finished its instant sleep) will itself win the next
        election.  So in the worst case all 3 threads become sequential winners, producing
        up to 3 sleep(1) calls.  In production (real sleep) concurrent threads would block
        at _gate.wait() and only one thread would sleep.

        What we can assert reliably: every chunk recovered and returned data, and the
        gate mechanism fired at least once (at least one sleep call).
        """
        NUM_CHUNKS = 3
        request_count = 0
        count_lock = threading.Lock()

        def handler(_: Request) -> Response:
            nonlocal request_count
            with count_lock:
                request_count += 1
                count = request_count
            if count <= NUM_CHUNKS:
                return Response("", status=429, headers={"Retry-After": "1"})
            return Response('{"items": []}', status=200, content_type="application/json")

        httpserver.expect_request("/test").respond_with_handler(handler)

        sleep_calls = []

        with patch("ossiq.clients.batch.time.sleep", side_effect=sleep_calls.append):
            results = run(
                httpserver.url_for("/test"),
                items=list(range(15)),  # 15 items ÷ chunk_size=5 → 3 chunks
                chunk_size=5,
            )

        # All chunks recovered after 429 — the core behavior under test.
        assert len(results) == NUM_CHUNKS

        # Gate mechanism fired: at least one winner slept, at most one per chunk.
        assert 1 <= len(sleep_calls) <= NUM_CHUNKS
        # Every sleep tick was the 1-second increment from Retry-After: 1.
        assert all(s == 1 for s in sleep_calls)


# ---------------------------------------------------------------------------
# Shutdown / abort signal
# ---------------------------------------------------------------------------


class TestBatchShutdown:
    def test_shutdown_stops_retries_mid_batch(self, server_timeout):
        """shutdown() aborts an in-progress batch; threads exit after their current request.

        Without shutdown the batch would spin for timeout × max_retries per chunk.
        With shutdown each thread checks _abort after its first timed-out request and exits.
        """
        strategy = RealHTTPBatchStrategy(
            server_timeout.url_for("/test"),
            timeout=0.3,
            max_retries=10,  # would take ~3 s+ without shutdown
            chunk_size=5,
        )
        client = BatchClient(strategy)
        results = []

        batch_thread = threading.Thread(target=lambda: results.extend(client.run_batch(list(range(15)))))
        batch_thread.start()

        # Give worker threads a moment to start their (hanging) HTTP requests.
        threading.Event().wait(timeout=0.05)

        client.shutdown()
        batch_thread.join(timeout=3.0)

        assert not batch_thread.is_alive(), "run_batch did not terminate after shutdown()"
        assert results == []

    def test_shutdown_unblocks_threads_waiting_at_gate(self, httpserver):
        """shutdown() opens the gate so threads blocked on 429 exit without waiting Retry-After.

        The server returns 429+Retry-After:30 for every request (threads would wait 30 s).
        We patch time.sleep so that the very first gate-winner tick calls shutdown(),
        which sets _abort and opens the gate.  All waiting threads then check _abort and
        exit cleanly — the whole batch finishes in milliseconds.
        """
        httpserver.expect_request("/test").respond_with_handler(
            lambda _: Response("", status=429, headers={"Retry-After": "30"})
        )

        strategy = RealHTTPBatchStrategy(
            httpserver.url_for("/test"),
            max_retries=5,
            chunk_size=5,
        )
        client = BatchClient(strategy)
        shutdown_issued = threading.Event()

        def sleep_that_triggers_shutdown(_):
            # Only the very first tick from the gate winner needs to call shutdown.
            if not shutdown_issued.is_set():
                shutdown_issued.set()
                client.shutdown()

        with patch("ossiq.clients.batch.time.sleep", side_effect=sleep_that_triggers_shutdown):
            results = list(client.run_batch(list(range(15))))

        assert results == []
        assert shutdown_issued.is_set(), "shutdown was never triggered — test setup issue"
