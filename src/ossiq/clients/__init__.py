"""
Module to handle HTTP layer and caching
"""

import requests
import requests_cache

VARY_NOISE = frozenset({"authorization", "cookie", "x-github-otp", "x-requested-with"})
"""`Vary` entries that stop requests-cache reusing a stored response. GitHub answers every
authenticated call with `Vary: Authorization, Cookie, ...`; `Authorization` is redacted into
`ignored_parameters` so it can never be Vary-matched, and requests-cache then treats every hit
as a miss. We send one fixed token and `Accept` per run, so dropping these loses nothing."""


def trim_vary_header(response: requests.Response) -> bool:
    """Strip VARY_NOISE from a response's `Vary` header before requests-cache stores it.

    Wired in as `filter_fn`, which also has to answer "cache this response?" - always yes here
    (the code / method filters still apply on top).
    """
    vary = response.headers.get("Vary")
    if vary:
        kept = [part.strip() for part in vary.split(",") if part.strip().lower() not in VARY_NOISE]
        if kept:
            response.headers["Vary"] = ", ".join(kept)
        else:
            del response.headers["Vary"]
    return True


def install_requests_cache(cache_destination: str, cache_ttl_hours: int, stability_cache_ttl_hours: int) -> None:
    """Install a persistent sqlite3 HTTP cache for all requests sessions.

    Caches all GET/POST responses for cache_ttl_hours hours, except GitHub stability data — commit
    history (`*/commits*`), the batched activity GraphQL job (`*/graphql*`) and the README
    deprecation scan (`*/readme*`) — which gets stability_cache_ttl_hours instead: a repo's commit
    rhythm, issue/PR responsiveness and maintenance status don't change day to day. Subsequent
    scans of the same project skip network calls entirely when data is still fresh. POST is cached
    (GraphQL) and requests-cache keys it by request body, so each unique aliased query caches
    independently.
    """
    requests_cache.install_cache(
        cache_name=cache_destination,
        backend="sqlite",
        expire_after=cache_ttl_hours * 3600,
        urls_expire_after={
            "*/commits*": stability_cache_ttl_hours * 3600,
            "*/graphql*": stability_cache_ttl_hours * 3600,
            "*/readme*": stability_cache_ttl_hours * 3600,
        },
        allowable_methods=("GET", "POST"),
        filter_fn=trim_vary_header,
    )
