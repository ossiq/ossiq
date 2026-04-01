"""
Robust HTTP client to handle 429 rate limits and
other response errors.
"""

import logging
import random
import time
from dataclasses import dataclass
from typing import Any

import requests

logger = logging.getLogger(__name__)


@dataclass
class Result:
    data: Any
    success: bool
    error: Exception | None = None
    message: str | None = None


def handle_rate_limit(response: requests.Response, default_wait_time=30) -> None:
    """
    Function to properly handle rate limit response
    """
    retry_after = response.headers.get("Retry-After")
    wait_time = int(retry_after) if retry_after and retry_after.isdigit() else 30

    if wait_time is not None:
        # We won the election — sleep outside the lock, then reopen.
        logger.warning("429 Rate Limit! Pausing all threads for %ds", wait_time)

        # Sleep in 1-second increments to allow graceful abort (Ctrl+C / shutdown()).
        time.sleep(wait_time)
        logger.info("Rate limit period over. Resuming...")
    else:
        time.sleep(default_wait_time)


def request_with_retry(perform_request, *args, max_retries=3, **kwargs) -> Result:
    """
    Worker thread: POST one chunk, retry on transient errors.

    Returns a list containing one ChunkResult on success or permanent failure.
    Returns an empty list if aborted before any attempt.
    """

    error = None

    for attempt in range(max_retries):
        try:
            t0 = time.perf_counter()
            resp = perform_request(*args, **kwargs)
            elapsed = time.perf_counter() - t0
            logger.debug("request attempt=%d status=%d latency=%.3fs", attempt + 1, resp.status_code, elapsed)

            if resp.status_code == 429:
                handle_rate_limit(resp)
                continue  # Retry this chunk after the pause.

            resp.raise_for_status()
            return Result(data=resp.json(), success=True)

        except (requests.Timeout, requests.ConnectionError, requests.HTTPError) as exc:
            error = exc

            # Don't sleep if it's the final attempt
            if attempt < max_retries - 1:
                # Base 3 math: 3^0=1, 3^1=3, 3^2=9, 3^3=27
                base_wait = 3**attempt
                # Adding 10-20% jitter to prevent "thundering herd"
                wait = base_wait + random.uniform(0, 0.2 * base_wait)

                logger.info("Error: %s. Retrying in %.1fs...", exc, wait)
                time.sleep(wait)
            else:
                logger.error("Max retries reached. Final error: %s", exc)

    return Result(
        data=None,
        success=False,
        message=f"Max retries ({max_retries}) exceeded",
        error=error,
    )
