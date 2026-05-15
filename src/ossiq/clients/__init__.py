"""
Module to handle HTTP layer and caching
"""

import requests_cache


def install_requests_cache(cache_destination: str, cache_ttl_hours: int) -> None:
    """Install a persistent sqlite3 HTTP cache for all requests sessions.

    Caches all GET/POST responses for cache_ttl_hours hours. Subsequent scans of
    the same project skip network calls entirely when registry data is still fresh.
    """
    requests_cache.install_cache(
        cache_name=cache_destination,
        backend="sqlite",
        expire_after=cache_ttl_hours * 3600,
        allowable_methods=("GET", "POST"),
    )
