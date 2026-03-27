# pylint: disable=protected-access
"""
Strawman tests for BatchClient in ossiq.clients.batch.

These tests specify the desired behaviour of the batch client's:
  - chunking and parallelism
  - retry with exponential backoff + jitter
  - 429 rate-limit coordination (deadlock-safe Event Gate)
  - ChunkResult success/failure wrapping
  - shutdown / abort signal
  - result mapping and partial-failure resilience
"""

import threading
import time
from unittest.mock import MagicMock, call, patch

import pytest
import requests

from ossiq.clients.batch import BatchClient, BatchStrategy, BatchStrategySettings, ChunkResult

# Capture the real time.sleep before any test patches it on the shared module object.
# patch("ossiq.clients.batch.time.sleep") replaces sleep on the same module object
# that `time` refers to here, so calling time.sleep() inside a mock would recurse.
_real_sleep = time.sleep

# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------

FAKE_URL = "https://fake.api/batch"


class FakeBatchStrategy(BatchStrategy):
    """
    Minimal concrete strategy used across all tests.

    The session is injected so individual tests can control HTTP responses
    via session.post.side_effect / session.post.return_value.
    """

    def __init__(self, session: MagicMock | None = None, chunk_size: int = 3, max_retries: int = 3):
        self.session = session or MagicMock()
        self._config = BatchStrategySettings(
            chunk_size=chunk_size,
            max_retries=max_retries,
            request_timeout=10,
            has_pagination=False,
        )

    @property
    def config(self) -> BatchStrategySettings:
        return self._config

    def prepare_item(self, item):
        return item

    def perform_request(self, chunk: list) -> requests.Response:
        return self.session.post(FAKE_URL, json={"items": chunk}, timeout=self._config.request_timeout)

    def process_response(self, source_items: list, response: ChunkResult):
        # Unwrap so test assertions can use plain dicts, not ChunkResult objects.
        return response.data[0] if response.data else None


def make_response(status: int, body: dict, headers: dict | None = None) -> MagicMock:
    """Build a mock requests.Response with status, json body, and headers."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.json.return_value = body
    resp.headers = headers or {}
    if status >= 400:
        resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
    else:
        resp.raise_for_status.return_value = None
    return resp


def make_strategy(session: MagicMock | None = None, chunk_size: int = 3, max_retries: int = 3) -> FakeBatchStrategy:
    return FakeBatchStrategy(session=session, chunk_size=chunk_size, max_retries=max_retries)


def make_client(strategy: FakeBatchStrategy | None = None) -> BatchClient:
    return BatchClient(strategy or make_strategy())


def collect(generator) -> list:
    """Drain a generator into a list."""
    return list(generator)


# ---------------------------------------------------------------------------
# A. Chunking
# ---------------------------------------------------------------------------


class TestBatchClientChunking:
    def test_empty_input_yields_nothing_and_makes_no_requests(self):
        """run_batch on an empty list must be a no-op."""
        # Arrange
        strategy = make_strategy()
        client = make_client(strategy)

        # Act
        results = collect(client.run_batch([]))

        # Assert
        assert results == []
        strategy.session.post.assert_not_called()

    def test_items_smaller_than_chunk_size_sends_one_request(self):
        """2 items with chunk_size=3 → exactly 1 POST."""
        # Arrange
        session = MagicMock()
        session.post.return_value = make_response(200, {"ok": True})
        client = make_client(make_strategy(session, chunk_size=3))

        # Act
        collect(client.run_batch([1, 2]))

        # Assert
        assert session.post.call_count == 1

    def test_items_equal_to_chunk_size_sends_one_request(self):
        """3 items with chunk_size=3 → exactly 1 POST (no off-by-one)."""
        # Arrange
        session = MagicMock()
        session.post.return_value = make_response(200, {"ok": True})
        client = make_client(make_strategy(session, chunk_size=3))

        # Act
        collect(client.run_batch([1, 2, 3]))

        # Assert
        assert session.post.call_count == 1

    def test_items_larger_than_chunk_size_splits_into_multiple_chunks(self):
        """7 items with chunk_size=3 → 3 POSTs (chunks of 3, 3, 1)."""
        # Arrange
        session = MagicMock()
        session.post.return_value = make_response(200, {})
        client = make_client(make_strategy(session, chunk_size=3))

        # Act
        collect(client.run_batch(list(range(7))))

        # Assert
        assert session.post.call_count == 3

    def test_perform_request_receives_prepared_items(self):
        """prepare_item output (not the original item) must reach perform_request."""
        # Arrange
        session = MagicMock()
        session.post.return_value = make_response(200, {})

        class UpperStrategy(FakeBatchStrategy):
            def prepare_item(self, item):
                return item.upper()

        client = make_client(UpperStrategy(session=session, chunk_size=5))

        # Act
        collect(client.run_batch(["a", "b"]))

        # Assert
        called_body = session.post.call_args[1]["json"]
        assert called_body == {"items": ["A", "B"]}

    def test_original_chunk_passed_to_process_response_is_a_list(self):
        """
        original_chunk stored in future_to_chunk must be a list (not a tuple
        from batched()) so process_response implementors get a consistent type.
        """
        # Arrange
        session = MagicMock()
        session.post.return_value = make_response(200, {"x": 1})
        received_source_items = []

        class TrackingStrategy(FakeBatchStrategy):
            def process_response(self, source_items, response):
                received_source_items.append(type(source_items))
                return super().process_response(source_items, response)

        client = make_client(TrackingStrategy(session=session, chunk_size=10))

        # Act
        collect(client.run_batch([1, 2]))

        # Assert
        assert received_source_items == [list]


# ---------------------------------------------------------------------------
# B. Retry on transient errors
# ---------------------------------------------------------------------------


class TestBatchClientRetry:
    def test_retries_on_timeout_then_succeeds(self):
        """A single Timeout followed by a 200 → result is yielded."""
        # Arrange
        session = MagicMock()
        session.post.side_effect = [requests.Timeout, make_response(200, {"data": 1})]
        client = make_client(make_strategy(session))

        # Act
        with patch("ossiq.clients.batch.time.sleep"):
            results = collect(client.run_batch([1]))

        # Assert
        assert results == [{"data": 1}]
        assert session.post.call_count == 2

    def test_retries_on_connection_error_then_succeeds(self):
        """ConnectionError on first attempt, success on second."""
        # Arrange
        session = MagicMock()
        session.post.side_effect = [requests.ConnectionError, make_response(200, {"data": 2})]
        client = make_client(make_strategy(session))

        # Act
        with patch("ossiq.clients.batch.time.sleep"):
            results = collect(client.run_batch([1]))

        # Assert
        assert results == [{"data": 2}]

    def test_retries_on_5xx_then_succeeds(self):
        """A 500 response (raises HTTPError) retries and eventually succeeds."""
        # Arrange
        session = MagicMock()
        session.post.side_effect = [make_response(500, {}), make_response(200, {"data": 3})]
        client = make_client(make_strategy(session))

        # Act
        with patch("ossiq.clients.batch.time.sleep"):
            results = collect(client.run_batch([1]))

        # Assert
        assert results == [{"data": 3}]

    def test_exhausts_retries_and_yields_nothing(self):
        """Permanent failure yields nothing and does not raise."""
        # Arrange
        session = MagicMock()
        session.post.side_effect = requests.Timeout
        client = make_client(make_strategy(session, max_retries=3))

        # Act
        with patch("ossiq.clients.batch.time.sleep"):
            results = collect(client.run_batch([1]))

        # Assert
        assert results == []
        assert session.post.call_count == 3  # tried max_retries times

    def test_exponential_backoff_sleep_durations_with_jitter(self):
        """
        Sleep durations are 2^attempt + jitter(0..0.5*base).
        For max_retries=3 there are 2 sleeps (last attempt skips sleep).
        Assert ranges rather than exact values since jitter is random.
        """
        # Arrange
        session = MagicMock()
        session.post.side_effect = requests.Timeout
        client = make_client(make_strategy(session, max_retries=3))
        sleep_args = []

        def capture_sleep(duration):
            sleep_args.append(duration)

        # Act
        with patch("ossiq.clients.batch.time.sleep", side_effect=capture_sleep):
            collect(client.run_batch([1]))

        # Assert: 2 sleeps (attempt 0 and 1; attempt 2 is the last, no sleep)
        assert len(sleep_args) == 2
        assert 1.0 <= sleep_args[0] < 1.5   # base=1, jitter up to 0.5
        assert 2.0 <= sleep_args[1] < 3.0   # base=2, jitter up to 1.0

    def test_failed_chunk_does_not_poison_successful_chunk(self):
        """When one chunk always fails, results from other chunks are still yielded."""
        # Arrange
        def post_side_effect(url, json, timeout):
            # The chunk containing item 99 always fails; others succeed.
            if 99 in json["items"]:
                raise requests.Timeout
            return make_response(200, {"items": json["items"]})

        session = MagicMock()
        session.post.side_effect = post_side_effect
        client = make_client(make_strategy(session, chunk_size=3))

        # Act — 7 items, chunk_size=3 → chunks [0,1,2], [3,4,5], [99]
        items = list(range(6)) + [99]
        with patch("ossiq.clients.batch.time.sleep"):
            results = collect(client.run_batch(items))

        # Assert — two successful chunks yielded; the failing one did not
        assert len(results) == 2


# ---------------------------------------------------------------------------
# C. 429 Rate-limit coordination
# ---------------------------------------------------------------------------


class TestBatchClient429:
    def test_429_closes_gate_then_reopens_after_sleep(self):
        """
        After a 429, the gate must be closed (red) for all sleep(1) iterations
        and open (green) once the sleep loop completes.
        """
        # Arrange
        client = make_client()
        gate_during_sleep = []

        def fake_sleep(duration):
            gate_during_sleep.append(client._gate.is_set())

        resp_429 = make_response(429, {}, headers={"Retry-After": "3"})

        with patch("ossiq.clients.batch.time.sleep", side_effect=fake_sleep):
            client._handle_rate_limit(resp_429)

        # Assert: gate was closed throughout the sleep loop, open afterwards
        assert len(gate_during_sleep) == 3
        assert all(v is False for v in gate_during_sleep)
        assert client._gate.is_set()

    def test_retry_after_header_is_respected(self):
        """Retry-After: 45 header → 45 individual sleep(1) calls."""
        # Arrange
        client = make_client()
        resp_429 = make_response(429, {}, headers={"Retry-After": "45"})

        with patch("ossiq.clients.batch.time.sleep") as mock_sleep:
            client._handle_rate_limit(resp_429)

        assert mock_sleep.call_count == 45
        assert all(c == call(1) for c in mock_sleep.call_args_list)

    def test_default_backoff_when_no_retry_after_header(self):
        """No Retry-After header → 30 sleep(1) calls (default fallback)."""
        # Arrange
        client = make_client()
        resp_429 = make_response(429, {}, headers={})

        with patch("ossiq.clients.batch.time.sleep") as mock_sleep:
            client._handle_rate_limit(resp_429)

        assert mock_sleep.call_count == 30
        assert all(c == call(1) for c in mock_sleep.call_args_list)

    def test_lock_is_released_before_sleep(self):
        """
        _lock must NOT be held when time.sleep is called.
        Verifies the "no I/O while holding lock" principle.
        """
        # Arrange
        client = make_client()
        lock_held_during_sleep = []

        def fake_sleep(duration):
            lock_held_during_sleep.append(client._lock.locked())

        resp_429 = make_response(429, {}, headers={"Retry-After": "2"})

        with patch("ossiq.clients.batch.time.sleep", side_effect=fake_sleep):
            client._handle_rate_limit(resp_429)

        assert all(v is False for v in lock_held_during_sleep), "Lock was still held during sleep!"

    def test_only_one_thread_sleeps_on_concurrent_429s(self):
        """
        When two threads receive 429 at the same moment only ONE thread
        should call time.sleep (the election winner).  The loser waits at
        _gate.wait() instead.

        patch is applied at the test level (outside threads) because
        unittest.mock.patch is not thread-safe when used inside thread
        functions — concurrent __enter__/__exit__ calls can corrupt the
        patched attribute.
        """
        # Arrange
        client = make_client()
        sleep_count = []
        sleep_lock = threading.Lock()
        barrier = threading.Barrier(2)

        def fake_sleep(duration):
            # Real delay ensures Thread 1 is still inside the sleep loop when
            # Thread 2 acquires the lock and sees the gate is closed, preventing
            # Thread 2 from starting a second election cycle.
            _real_sleep(0.005)
            with sleep_lock:
                sleep_count.append(1)

        resp_429 = make_response(429, {}, headers={"Retry-After": "1"})

        def call_handle():
            barrier.wait()  # synchronise both threads at the same moment
            client._handle_rate_limit(resp_429)

        with patch("ossiq.clients.batch.time.sleep", side_effect=fake_sleep):
            t1 = threading.Thread(target=call_handle)
            t2 = threading.Thread(target=call_handle)
            t1.start()
            t2.start()
            t1.join(timeout=5)
            t2.join(timeout=5)

        # Assert: exactly one sleep happened
        assert sum(sleep_count) == 1

    def test_lock_timeout_falls_back_to_gate_wait(self):
        """
        If _lock.acquire times out (returns False), the thread must NOT sleep.
        Instead, it must wait on _gate.wait() for whoever holds the lock.

        CPython's _thread.lock.acquire is a C-level slot and cannot be
        patched via patch.object.  We replace client._lock with a pure-Python
        MagicMock that returns False from acquire(), which is equivalent.
        """
        # Arrange
        client = make_client()

        # Replace the real lock with a mock whose acquire always "times out".
        fake_lock = MagicMock()
        fake_lock.acquire.return_value = False
        client._lock = fake_lock

        # Gate is already closed — simulate another thread having won the election.
        client._gate.clear()

        gate_waited = []

        def fake_gate_wait(timeout=None):
            gate_waited.append(True)
            client._gate.set()  # unblock immediately so test doesn't hang
            return True

        client._gate.wait = fake_gate_wait

        resp_429 = make_response(429, {}, headers={})

        with patch("ossiq.clients.batch.time.sleep") as mock_sleep:
            client._handle_rate_limit(resp_429)

        # Assert: no sleep, but gate was waited on
        mock_sleep.assert_not_called()
        assert gate_waited, "Expected _gate.wait() to be called when lock timed out"

    def test_requests_resume_after_gate_reopens(self):
        """
        After a 429 pause, the client must retry the chunk and yield
        the result once the gate is open again.
        """
        # Arrange
        session = MagicMock()
        resp_429 = make_response(429, {}, headers={"Retry-After": "1"})
        resp_ok = make_response(200, {"result": "ok"})
        session.post.side_effect = [resp_429, resp_ok]
        client = make_client(make_strategy(session))

        # Act
        with patch("ossiq.clients.batch.time.sleep"):
            results = collect(client.run_batch([1]))

        # Assert
        assert results == [{"result": "ok"}]
        assert session.post.call_count == 2


# ---------------------------------------------------------------------------
# D. ChunkResult wrapping
# ---------------------------------------------------------------------------


class TestChunkResult:
    def test_success_result_has_correct_fields(self):
        """A 200 response produces ChunkResult(success=True, data=[body])."""
        # Arrange
        session = MagicMock()
        session.post.return_value = make_response(200, {"key": "value"})
        strategy = make_strategy(session)
        client = make_client(strategy)

        # Act
        result = client._fetch_chunk([1], strategy)

        # Assert
        assert isinstance(result, ChunkResult)
        assert result.success is True
        assert result.data == [{"key": "value"}]
        assert result.error is None

    def test_failure_result_has_correct_fields(self):
        """Exhausted retries produce ChunkResult(success=False) with error and message."""
        # Arrange
        session = MagicMock()
        session.post.side_effect = requests.Timeout  # use class so MagicMock raises a fresh instance
        strategy = make_strategy(session, max_retries=2)
        client = make_client(strategy)

        # Act
        with patch("ossiq.clients.batch.time.sleep"):
            result = client._fetch_chunk([1], strategy)

        # Assert
        assert isinstance(result, ChunkResult)
        assert result.success is False
        assert isinstance(result.error, requests.Timeout)
        assert "Max retries" in result.message

    def test_abort_before_first_attempt_returns_empty_list(self):
        """When _abort is set before _fetch_chunk runs, it returns [] immediately."""
        # Arrange
        strategy = make_strategy()
        client = make_client(strategy)
        client._abort.set()

        # Act
        result = client._fetch_chunk([1], strategy)

        # Assert
        assert result == []
        strategy.session.post.assert_not_called()

    def test_zero_max_retries_returns_failure_chunk_result(self):
        """max_retries=0 means the for-loop never executes; returns a failure ChunkResult."""
        # Arrange
        strategy = make_strategy(max_retries=0)
        client = make_client(strategy)

        # Act
        result = client._fetch_chunk([1], strategy)

        # Assert — not None, not [], a proper failure result
        assert isinstance(result, ChunkResult)
        assert result.success is False


# ---------------------------------------------------------------------------
# E. Shutdown / abort
# ---------------------------------------------------------------------------


class TestBatchClientShutdown:
    def test_shutdown_sets_abort_and_opens_gate(self):
        """shutdown() must set _abort and ensure _gate is open (unblocks waiters)."""
        # Arrange
        client = make_client()
        client._gate.clear()  # simulate a closed gate

        # Act
        client.shutdown()

        # Assert
        assert client._abort.is_set()
        assert client._gate.is_set()

    def test_abort_interrupts_rate_limit_sleep(self):
        """
        shutdown() called while the winner thread is sleeping during a rate-limit
        pause must break out of the sleep loop early (fewer than wait_time iterations).
        """
        # Arrange
        client = make_client()
        sleep_count = []
        sleep_started = threading.Event()

        def fake_sleep(duration):
            sleep_count.append(1)
            sleep_started.set()
            # Real delay gives the main thread time to call shutdown() between ticks,
            # since otherwise all 60 iterations complete before Python yields the GIL.
            _real_sleep(0.005)

        resp_429 = make_response(429, {}, headers={"Retry-After": "60"})

        def do_handle():
            client._handle_rate_limit(resp_429)

        with patch("ossiq.clients.batch.time.sleep", side_effect=fake_sleep):
            t = threading.Thread(target=do_handle)
            t.start()
            sleep_started.wait(timeout=2)  # wait until first tick fires
            client.shutdown()              # abort mid-sleep
            t.join(timeout=2)

        # Assert: far fewer than 60 sleep(1) calls happened
        assert len(sleep_count) < 60


# ---------------------------------------------------------------------------
# F. Pagination (placeholder — interface not yet implemented)
# ---------------------------------------------------------------------------


class TestBatchClientPagination:
    @pytest.mark.xfail(reason="Pagination not yet implemented in BatchClient/BatchStrategy")
    def test_follows_next_page_token_until_exhausted(self):
        """
        When a response contains next_page_token, the client must issue a
        follow-up request with the token until no token is returned.
        """
        session = MagicMock()
        page1 = make_response(200, {"results": ["a"], "next_page_token": "tok-1"})
        page2 = make_response(200, {"results": ["b"]})
        session.post.side_effect = [page1, page2]
        client = make_client(make_strategy(session))

        results = collect(client.run_batch([1]))

        assert session.post.call_count == 2
        assert results == [["a", "b"]]

    @pytest.mark.xfail(reason="Pagination not yet implemented in BatchClient/BatchStrategy")
    def test_merges_results_across_pages(self):
        """Results from all pages must be combined before process_response is called."""
        session = MagicMock()
        page1 = make_response(200, {"items": [1], "next_page_token": "tok"})
        page2 = make_response(200, {"items": [2]})
        session.post.side_effect = [page1, page2]
        client = make_client(make_strategy(session))

        results = collect(client.run_batch([1]))

        assert results == [[1, 2]]


# ---------------------------------------------------------------------------
# G. Result mapping
# ---------------------------------------------------------------------------


class TestBatchClientResultMapping:
    def test_process_response_called_with_source_items_and_chunk_result(self):
        """process_response must receive the original_chunk list and a ChunkResult."""
        # Arrange
        session = MagicMock()
        session.post.return_value = make_response(200, {"raw": True})
        received_calls = []

        class TrackingStrategy(FakeBatchStrategy):
            def process_response(self, source_items, response: ChunkResult):
                received_calls.append((source_items, response))
                return response.data[0] if response.data else None

        strategy = TrackingStrategy(session=session, chunk_size=10)
        client = make_client(strategy)

        # Act
        collect(client.run_batch([1, 2]))

        # Assert
        assert len(received_calls) == 1
        source, resp = received_calls[0]
        assert source == [1, 2]
        assert isinstance(resp, ChunkResult)
        assert resp.success is True
        assert resp.data == [{"raw": True}]

    def test_results_from_multiple_chunks_are_all_yielded(self):
        """Results from every chunk must appear in the final output."""
        # Arrange
        session = MagicMock()
        session.post.return_value = make_response(200, {"chunk": True})
        client = make_client(make_strategy(session, chunk_size=2))

        # Act — 6 items with chunk_size=2 → 3 chunks → 3 results
        results = collect(client.run_batch(list(range(6))))

        # Assert
        assert len(results) == 3
        assert all(r == {"chunk": True} for r in results)

    def test_failed_chunks_are_not_passed_to_process_response(self):
        """
        process_response must only be called for successful chunks.
        A permanently failing chunk must produce no output entry.
        """
        # Arrange
        session = MagicMock()
        session.post.side_effect = requests.Timeout
        process_called = []

        class TrackingStrategy(FakeBatchStrategy):
            def process_response(self, source_items, response):
                process_called.append(True)
                return super().process_response(source_items, response)

        client = make_client(TrackingStrategy(session=session, max_retries=2))

        # Act
        with patch("ossiq.clients.batch.time.sleep"):
            results = collect(client.run_batch([1]))

        # Assert
        assert results == []
        assert process_called == []
