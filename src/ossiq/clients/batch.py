"""
Abstraction to perform batched HTTP requests with
correct reporting and handling edge cases like rate limits,
network interruptions etc.
"""

import logging
import random
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Generator, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

import requests


def _chunked(items: Iterable, n: int) -> Generator:
    """Yield successive n-sized chunks from items. Backport of itertools.batched (3.12+)."""
    it = iter(items)
    while True:
        chunk: list = []
        try:
            for _ in range(n):
                chunk.append(next(it))
        except StopIteration:
            if chunk:
                yield chunk
            return
        yield chunk


logger = logging.getLogger(__name__)


@dataclass
class BatchStrategySettings:
    chunk_size: int
    max_retries: int
    max_workers: int
    request_timeout: float
    has_pagination: bool


@dataclass
class ChunkResult:
    data: list[Any]
    success: bool
    error: Exception | None = None
    message: str | None = None


class BatchStrategy(ABC):
    """
    Abstract base for a batching strategy.

    Concrete implementations own the API endpoint, request shape,
    and response mapping.  BatchClient handles concurrency, retries,
    and rate-limit coordination.
    """

    @property
    @abstractmethod
    def config(self) -> BatchStrategySettings:
        """Return settings that control chunking and retry behaviour."""

    @abstractmethod
    def prepare_item(self, item: Any) -> Any:
        """
        Transform a single source item into its request-ready form.
        Called once per item before chunking.
        """

    @abstractmethod
    def perform_request(self, chunk: list) -> requests.Response:
        """
        Perform the HTTP request for this chunk and return the raw response.
        Owns the session, URL, and request body.  Must NOT catch exceptions —
        BatchClient handles retry logic for Timeout, ConnectionError, HTTPError.
        """

    @abstractmethod
    def process_response(self, source_items: list, response: ChunkResult) -> Any:
        """
        Map a ChunkResult back to caller-meaningful results.
        source_items is the original (unprepared) item list passed to run_batch.
        Only called for successful chunks (response.success is True).
        """


class BatchClient:
    """
    Generic batch HTTP client.

    Splits items into chunks, dispatches them concurrently, retries on
    transient errors, and coordinates a global pause when any thread
    receives a 429 (rate-limit) response.

    Thread-safety contract
    ----------------------
    _gate  - threading.Event used as a traffic light.
             set   = green (threads may send requests)
             clear = red   (rate-limit pause in progress)
    _lock  - threading.Lock that guards the gate state transition.
             Held only for microseconds (no I/O inside the lock).
    _abort - threading.Event that signals all threads to exit early.
             Set by shutdown(); checked at the top of each retry loop
             and inside the rate-limit sleep loop.
    """

    def __init__(self, strategy: BatchStrategy):
        self.strategy = strategy

        # Gate starts open (green light).
        self._gate = threading.Event()
        self._gate.set()

        # Protects the gate-close/wait_time election (see _handle_rate_limit).
        self._lock = threading.Lock()

        # Signals worker threads to stop processing and exit.
        self._abort = threading.Event()

    def run_batch(self, items: Iterable[Any]) -> Generator:
        """
        Yield results for all items, processing them in parallel chunks.

        Items that fail permanently after all retries are silently dropped
        (logged at ERROR level) so a bad chunk never blocks good ones.
        """
        if not items:
            return

        chunk_size = self.strategy.config.chunk_size
        prepared_items = (self.strategy.prepare_item(item) for item in items)
        chunks = _chunked(prepared_items, chunk_size)

        t0 = time.perf_counter()
        chunks_ok = chunks_failed = items_yielded = 0

        with ThreadPoolExecutor(max_workers=self.strategy.config.max_workers) as pool:
            future_to_chunk: dict = {}

            for chunk in chunks:
                chunk_list = list(chunk)
                future = pool.submit(self._fetch_chunk, chunk_list, self.strategy)
                future_to_chunk[future] = chunk_list  # store list, same as submitted

            for future in as_completed(future_to_chunk):
                original_chunk = future_to_chunk[future]

                try:
                    response = future.result()
                    if not response:  # [] from abort or max_retries=0
                        chunks_failed += 1
                        continue
                    if not response.success:
                        logger.error("Permanent failure for chunk: %s", response.message)
                        chunks_failed += 1
                        continue

                    chunks_ok += 1
                    items_yielded += 1
                    yield self.strategy.process_response(original_chunk, response)

                except Exception as exc:
                    logger.error("Chunk of %d items failed: %s", len(original_chunk), exc)
                    chunks_failed += 1

        logger.debug(
            "[%s] batch done: chunks_ok=%d chunks_failed=%d items=%d total_time=%.3fs",
            type(self.strategy).__name__,
            chunks_ok,
            chunks_failed,
            items_yielded,
            time.perf_counter() - t0,
        )

    def _fetch_chunk(self, chunk: list, strategy: BatchStrategy) -> ChunkResult | list:
        """
        Worker thread: POST one chunk, retry on transient errors.

        Returns a list containing one ChunkResult on success or permanent failure.
        Returns an empty list if aborted before any attempt.
        """

        error = None

        for attempt in range(strategy.config.max_retries):
            if self._abort.is_set():
                return []  # Graceful exit — no result for this chunk.

            # Block here if the global gate is closed (rate-limit pause).
            self._gate.wait()

            try:
                t0 = time.perf_counter()
                resp = strategy.perform_request(chunk)
                elapsed = time.perf_counter() - t0
                logger.debug(
                    "[%s] chunk=%d attempt=%d status=%d latency=%.3fs",
                    type(strategy).__name__,
                    len(chunk),
                    attempt + 1,
                    resp.status_code,
                    elapsed,
                )

                if resp.status_code == 429:
                    self._handle_rate_limit(resp)
                    continue  # Retry this chunk after the pause.

                resp.raise_for_status()
                return ChunkResult(data=[resp.json()], success=True)

            except (requests.Timeout, requests.ConnectionError, requests.HTTPError) as exc:
                if attempt < strategy.config.max_retries - 1:
                    # Base 3 math: 3^0=1, 3^1=3, 3^2=9, 3^3=27
                    base_wait = 3**attempt
                    # Adding 10-20% jitter to prevent "thundering herd"
                    wait = base_wait + random.uniform(0, 0.2 * base_wait)

                    logger.info("Error: %s. Retrying in %.1fs...", exc, wait)
                    time.sleep(wait)
                else:
                    logger.error("Max retries reached. Final error: %s", exc)

                error = exc

        return ChunkResult(
            data=[],
            success=False,
            message=f"Max retries ({strategy.config.max_retries}) exceeded",
            error=error,
        )

    def _handle_rate_limit(self, response: requests.Response) -> None:
        """
        Coordinate a global pause across all worker threads on a 429.

        Design (deadlock-prevention):
        - Lock scope is minimised: _lock is held only to swap gate state
          and read the wait duration.  It is released BEFORE sleeping.
        - Lock has a timeout: if acquire fails within 5 s the thread falls
          back to _gate.wait(), trusting the winner to reopen the gate.
        - Only ONE thread (the "winner" of the election) sleeps and reopens
          the gate.  All others wait at _gate.wait().
        - No I/O of any kind happens while _lock is held.
        """
        # Fast path: gate is already closed — another thread won the election.
        if not self._gate.is_set():
            self._gate.wait()
            return

        # Try to become the sleeping thread.  Timeout avoids indefinite block.
        acquired = self._lock.acquire(timeout=5)
        if not acquired:
            # Someone else holds the lock and will handle the pause.
            self._gate.wait()
            return

        wait_time = None
        try:
            # Double-check inside the lock: did another thread close the gate
            # while we were waiting to acquire _lock?
            if self._gate.is_set():
                self._gate.clear()  # Close the gate (Red Light).
                retry_after = response.headers.get("Retry-After")
                wait_time = int(retry_after) if retry_after and retry_after.isdigit() else 30
        finally:
            self._lock.release()  # Always release BEFORE sleeping.

        if wait_time is not None:
            # We won the election — sleep outside the lock, then reopen.
            logger.warning("429 Rate Limit! Pausing all threads for %ds", wait_time)

            # Sleep in 1-second increments to allow graceful abort (Ctrl+C / shutdown()).
            for _ in range(wait_time):
                if self._abort.is_set():
                    break
                time.sleep(1)

            self._gate.set()  # Open the gate (Green Light).
            logger.info("Rate limit period over. Resuming...")
        else:
            # Another thread closed the gate while we waited for the lock.
            self._gate.wait()

    def shutdown(self) -> None:
        """Signal all worker threads to stop processing and exit cleanly."""
        self._abort.set()
        self._gate.set()  # Unblock any threads waiting at the gate.
