"""
Module to handle HTTP layer and caching
"""

from datetime import timedelta

import requests_cache


def install_requests_cache(cache_destination: str = "./ossiq_cache.sqlite3", cache_ttl_hours: int = 24):
    """
    Configure requets-cache to use cache with SQLite.
    This handles ETags (304 Not Modified) automatically.
    It stores the ETag and only re-downloads if the data changed.
    """

    requests_cache.install_cache(
        cache_name=cache_destination,
        backend="sqlite",
        expire_after=timedelta(hours=cache_ttl_hours),
        allowable_methods=["GET"],
        # 'stale_if_error' returns cached data if GitHub is down or rate-limited
        stale_if_error=True,
    )
