"""
Pre-configured HTTP session for the ClearlyDefined API with POST response caching.
"""

from datetime import timedelta

import requests_cache


class ClearlyDefinedSession(requests_cache.CachedSession):
    """A pre-configured CachedSession for the ClearlyDefined API.

    Uses a dedicated SQLite cache for POST requests, since the global
    install_requests_cache() only covers GET requests.
    """

    def __init__(self, cache_destination: str = "./ossiq_cache.sqlite3", cache_ttl_hours: int = 24):

        super().__init__(
            cache_name=cache_destination,
            backend="sqlite",
            allowable_methods=["POST"],
            expire_after=timedelta(hours=cache_ttl_hours),
            stale_if_error=True,
        )
        self.headers.update({"User-Agent": "ossiq-research-tool"})
