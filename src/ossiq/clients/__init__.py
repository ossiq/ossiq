"""
Module to handle HTTP layer and caching
"""

import logging
import sqlite3
import time
import zlib
from contextlib import closing
from pathlib import Path

import requests
import requests_cache

logger = logging.getLogger(__name__)

GITHUB_USER_URL = "https://api.github.com/user"
"""`GET /user` answers per token, but the cache key leaves `Authorization` out, so a second account
would be handed the first one's login. requests-cache matches a pattern without a wildcard as a
prefix, which here covers only GitHub's own `/user...` paths."""

VARY_NOISE = frozenset({"authorization", "cookie", "x-github-otp", "x-requested-with"})
"""`Vary` entries that stop requests-cache reusing a stored response. GitHub answers every
authenticated call with `Vary: Authorization, Cookie, ...`; `Authorization` is redacted into
`ignored_parameters` so it can never be Vary-matched, and requests-cache then treats every hit
as a miss. We send one fixed token and `Accept` per run, so dropping these loses nothing."""

COMPRESSION_LEVEL = 6
"""Registry metadata dominates the cache (one npm packument can run to tens of MB) and, being JSON,
stores at about a fifth of its size at this level."""

CACHE_FORMAT_VERSION = 1
"""Kept in the sqlite `user_version`, which requests-cache leaves alone. Rows in a file below it were
written under another serializer, which is part of every cache key, so none can be read again - and
redirected ones may still carry an `Authorization` header in their stored hops."""

CACHE_RETENTION_SECONDS = 7 * 24 * 3600
"""How long an expired response is kept. Until then requests-cache can revalidate it, so a re-scan gets
a 304 instead of downloading a large packument again; after that it is dead weight."""

VACUUM_MIN_FREE_BYTES = 64 * 1024 * 1024
"""VACUUM rewrites the whole file, so it only runs once at least this much space is free..."""

VACUUM_MIN_FREE_SHARE = 0.25
"""...and that space is at least this share of the file."""

UPKEEP_LOCK_TIMEOUT_SECONDS = 1.0
"""How long the upkeep waits for another process to release the file before leaving it to the next run."""

LEGACY_CACHE_SIDECARS = ("-wal", "-shm", "-journal")
"""Files sqlite may keep next to a database, removed along with it."""


def trim_vary_header(response: requests.Response) -> bool:
    """Strip VARY_NOISE from a response's `Vary` header before requests-cache stores it.

    Returns True: `prepare_for_cache` passes that on as the `filter_fn` answer to "cache this
    response?" (the code / method filters still apply on top).
    """
    vary = response.headers.get("Vary")
    if vary:
        kept = [part.strip() for part in vary.split(",") if part.strip().lower() not in VARY_NOISE]
        if kept:
            response.headers["Vary"] = ", ".join(kept)
        else:
            del response.headers["Vary"]
    return True


def redact_redirect_hops(response: requests.Response) -> None:
    """Strip credentials from the requests behind a response's redirect hops.

    requests-cache redacts its ignored parameters from the final request only, but stores every hop of
    `response.history` with the request as it was sent. A renamed GitHub repository answers 301, so
    without this the token would be written to disk with the hop.
    """
    for hop in response.history:
        for name in requests_cache.DEFAULT_IGNORED_PARAMS:
            hop.request.headers.pop(name, None)


def prepare_for_cache(response: requests.Response) -> bool:
    """Ready a response for storage; wired in as `filter_fn`, so it also says whether to cache it.

    Returns:
        Always True: which responses get cached is decided by the method, status and URL rules.
    """
    redact_redirect_hops(response)
    return trim_vary_header(response)


def compress_payload(data: bytes) -> bytes:
    """Compress a pickled response for storage."""
    return zlib.compress(data, COMPRESSION_LEVEL)


def decompress_payload(data: bytes) -> bytes:
    """Undo `compress_payload`.

    Raises:
        ValueError: The row is not compressed, which requests-cache treats as a cache miss.
    """
    try:
        return zlib.decompress(data)
    except zlib.error as error:
        raise ValueError(f"unreadable cache entry: {error}") from error


CACHE_SERIALIZER = requests_cache.SerializerPipeline(
    [*requests_cache.pickle_serializer.stages, requests_cache.Stage(dumps=compress_payload, loads=decompress_payload)],
    name="pickle+zlib",
    is_binary=True,
)
"""requests-cache's own pickle format, zlib-compressed on top. Its name and stage count are part of
every cache key: changing either starts the cache over, so bump CACHE_FORMAT_VERSION with it."""


def maintain_cache(cache: requests_cache.SQLiteCache, now: float) -> None:
    """Keep the cache file from growing without bound, and scrub rows an older format left unsafe.

    Drops responses that expired more than CACHE_RETENTION_SECONDS ago, with their redirect aliases, and
    VACUUMs once enough space is free. A file below CACHE_FORMAT_VERSION is emptied first, since none of
    its rows can be read again. Another process holding the file only postpones the work to the next run.

    Args:
        cache: The cache about to be installed.
        now: The current time, in epoch seconds.
    """
    responses, redirects = cache.responses.table_name, cache.redirects.table_name
    try:
        # A connection of our own: requests-cache's write path retries a lock forever.
        with closing(sqlite3.connect(cache.db_path, timeout=UPKEEP_LOCK_TIMEOUT_SECONDS)) as con:
            with con:
                if con.execute("PRAGMA user_version").fetchone()[0] < CACHE_FORMAT_VERSION:
                    con.execute(f"DELETE FROM {responses}")
                    con.execute(f"DELETE FROM {redirects}")
                    con.execute(f"PRAGMA user_version = {CACHE_FORMAT_VERSION}")
                con.execute(f"DELETE FROM {responses} WHERE expires <= ?", (round(now - CACHE_RETENTION_SECONDS),))
                con.execute(f"DELETE FROM {redirects} WHERE value NOT IN (SELECT key FROM {responses})")
            page_size, pages, free_pages = (
                con.execute(f"PRAGMA {name}").fetchone()[0] for name in ("page_size", "page_count", "freelist_count")
            )
            if free_pages * page_size >= VACUUM_MIN_FREE_BYTES and free_pages >= pages * VACUUM_MIN_FREE_SHARE:
                con.execute("VACUUM")
    except sqlite3.OperationalError as error:
        logger.debug("HTTP cache upkeep skipped: %s", error)


def remove_legacy_cache(legacy: Path, active: Path) -> int:
    """Delete the cache file an earlier version kept, unless it is the one in use.

    Args:
        legacy: The old cache file.
        active: The cache file this run uses.

    Returns:
        Bytes freed; 0 when there was nothing to remove.
    """
    if not legacy.exists() or legacy.resolve() == active.resolve():
        return 0
    freed = 0
    for path in (legacy, *(legacy.with_name(legacy.name + suffix) for suffix in LEGACY_CACHE_SIDECARS)):
        try:
            size = path.stat().st_size
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError as error:
            logger.warning("Could not remove the old HTTP cache file %s: %s", path, error)
            continue
        freed += size
    return freed


def install_requests_cache(cache_destination: str, cache_ttl_hours: int, stability_cache_ttl_hours: int) -> Path:
    """Install a persistent sqlite3 HTTP cache for all requests sessions.

    Caches all GET/POST responses for cache_ttl_hours hours, except GitHub stability data — commit
    history (`*/commits*`), the batched activity GraphQL job (`*/graphql*`) and the README
    deprecation scan (`*/readme*`) — which gets stability_cache_ttl_hours instead: a repo's commit
    rhythm, issue/PR responsiveness and maintenance status don't change day to day. Subsequent
    scans of the same project skip network calls entirely when data is still fresh. POST is cached
    (GraphQL) and requests-cache keys it by request body, so each unique aliased query caches
    independently. The GitHub login endpoints, `GET /user` and the quota check are never cached.
    Responses are stored compressed, without credentials, and `maintain_cache` prunes the file first.

    Returns:
        The sqlite file the cache lives in.
    """
    cache = requests_cache.SQLiteCache(cache_destination, serializer=CACHE_SERIALIZER)
    maintain_cache(cache, time.time())
    requests_cache.install_cache(
        backend=cache,
        expire_after=cache_ttl_hours * 3600,
        urls_expire_after={
            # The quota pre-flight check reports a number that only means anything live - a
            # replayed reading would claim yesterday's budget and is worse than no reading.
            "*/rate_limit*": requests_cache.DO_NOT_CACHE,
            # A replayed poll never completes a login, and the token response holds the secrets.
            "*/login/*": requests_cache.DO_NOT_CACHE,
            GITHUB_USER_URL: requests_cache.DO_NOT_CACHE,
            "*/commits*": stability_cache_ttl_hours * 3600,
            "*/graphql*": stability_cache_ttl_hours * 3600,
            "*/readme*": stability_cache_ttl_hours * 3600,
        },
        allowable_methods=("GET", "POST"),
        # 206 is what PyPI answers the ranged PEP 792 status request with; unlisted, every warm scan
        # would repeat it for every package. That request is the only one that sends `Range`, and the
        # only one to `/simple/`, so nothing else is cached as a fragment.
        allowable_codes=(200, 206),
        filter_fn=prepare_for_cache,
    )
    return Path(cache.db_path)
