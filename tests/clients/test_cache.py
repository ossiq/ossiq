"""
Tests for install_requests_cache (ossiq.clients).
"""

import sqlite3
import zlib
from contextlib import closing
from pathlib import Path
from unittest.mock import ANY, patch

import pytest
import requests
import requests_cache

import ossiq.clients
from ossiq.clients import (
    CACHE_FORMAT_VERSION,
    CACHE_RETENTION_SECONDS,
    CACHE_SERIALIZER,
    GITHUB_USER_URL,
    decompress_payload,
    install_requests_cache,
    maintain_cache,
    prepare_for_cache,
    remove_legacy_cache,
    trim_vary_header,
)
from ossiq.clients.client_github import GITHUB_API
from ossiq.clients.client_github_oauth import GithubOAuthClient, OAuthFailure
from ossiq.domain.github_auth import DeviceChallenge, GithubCredentials


def test_install_requests_cache_sets_stability_url_ttls(tmp_path):
    cache_file = tmp_path / "cache.sqlite3"
    with patch("ossiq.clients.requests_cache.install_cache") as install_cache:
        installed = install_requests_cache(str(cache_file), 24, 168)

    install_cache.assert_called_once_with(
        backend=ANY,
        expire_after=24 * 3600,
        urls_expire_after={
            # A replayed quota reading is worse than none, so the pre-flight check never caches.
            "*/rate_limit*": requests_cache.DO_NOT_CACHE,
            # A replayed poll never completes a login, and the token response holds the secrets.
            "*/login/*": requests_cache.DO_NOT_CACHE,
            GITHUB_USER_URL: requests_cache.DO_NOT_CACHE,
            "*/commits*": 168 * 3600,
            "*/graphql*": 168 * 3600,
            "*/readme*": 168 * 3600,
        },
        allowable_methods=("GET", "POST"),
        # The ranged PEP 792 status request is answered 206; unlisted, it would never be reused.
        allowable_codes=(200, 206),
        filter_fn=prepare_for_cache,
    )
    backend = install_cache.call_args.kwargs["backend"]
    assert Path(backend.db_path) == cache_file == installed
    # requests-cache stores a copy of the pipeline, so compare by name.
    assert backend.responses.serializer.name == CACHE_SERIALIZER.name


def make_response(vary: str | None) -> requests.Response:
    response = requests.Response()
    if vary is not None:
        response.headers["Vary"] = vary
    return response


def test_trim_vary_header_drops_auth_and_cookie_entries():
    response = make_response("Accept, Authorization, Cookie, X-GitHub-OTP, Accept-Encoding")
    assert trim_vary_header(response) is True
    assert response.headers["Vary"] == "Accept, Accept-Encoding"


def test_trim_vary_header_removes_the_header_when_only_noise_remains():
    response = make_response("Authorization, Cookie")
    trim_vary_header(response)
    assert "Vary" not in response.headers


def test_trim_vary_header_is_a_noop_without_vary():
    response = make_response(None)
    assert trim_vary_header(response) is True
    assert "Vary" not in response.headers


# --- The GitHub login must never be replayed from, or recorded in, the cache ------------------

TOKEN_PATH = "/login/oauth/access_token"
CHALLENGE = DeviceChallenge(
    user_code="WDJB-4729",
    verification_uri="https://github.com/login/device",
    expires_at=2_000_000,
    interval=5,
    device_code="DEVICE-SECRET",
)


@pytest.fixture
def install_cache(tmp_path):
    """Install ossiq's real HTTP cache on a temp file; it is removed again after the test."""
    cache_file = tmp_path / "cache.sqlite3"

    def install():
        install_requests_cache(str(cache_file), 24, 168)
        return cache_file

    yield install
    requests_cache.uninstall_cache()


def cached_payloads(cache_file) -> bytes:
    """Every stored response, decompressed: a scan of the raw file cannot see into compressed rows."""
    requests_cache.uninstall_cache()  # releases the sqlite file so everything is on disk
    with closing(sqlite3.connect(cache_file)) as con:
        rows = con.execute("SELECT value FROM responses").fetchall()
    return b"".join(decompress_payload(value) for (value,) in rows)


def test_github_user_url_is_the_api_user_endpoint():
    assert GITHUB_USER_URL == f"{GITHUB_API}/user"


def test_login_polls_are_not_replayed_from_the_cache(install_cache, httpserver):
    install_cache()
    client = GithubOAuthClient("test-client", oauth_url=httpserver.url_for(""), clock=lambda: 1_000_000)
    httpserver.expect_ordered_request(TOKEN_PATH, method="POST").respond_with_json({"error": "authorization_pending"})
    httpserver.expect_ordered_request(TOKEN_PATH, method="POST").respond_with_json({"access_token": "gho_granted"})

    first = client.poll_once(CHALLENGE, 5)
    second = client.poll_once(CHALLENGE, 5)

    assert isinstance(first, OAuthFailure)
    assert isinstance(second, GithubCredentials)
    assert len(httpserver.log) == 2


def test_login_tokens_never_reach_the_cache_file(install_cache, httpserver):
    cache_file = install_cache()
    client = GithubOAuthClient("test-client", oauth_url=httpserver.url_for(""), clock=lambda: 1_000_000)
    granted = {"access_token": "gho_LOGINTOKEN", "refresh_token": "ghr_LOGINREFRESH"}
    httpserver.expect_request(TOKEN_PATH, method="POST").respond_with_json(granted)
    # Control: the same kind of answer from a path the cache does store, to prove the scan below can see it.
    httpserver.expect_request("/other/token", method="POST").respond_with_json(
        {"access_token": "gho_CONTROLTOKEN", "refresh_token": "ghr_CONTROLREFRESH"}
    )

    client.poll_once(CHALLENGE, 5)
    client.refresh("ghr_old")
    requests.post(httpserver.url_for("/other/token"), data={"client_id": "x"}, timeout=5)
    stored = cached_payloads(cache_file)

    assert b"gho_CONTROLTOKEN" in stored
    assert b"gho_LOGINTOKEN" not in stored
    assert b"ghr_LOGINREFRESH" not in stored


def test_user_lookup_is_not_answered_from_another_tokens_entry(install_cache, httpserver, monkeypatch):
    monkeypatch.setattr(ossiq.clients, "GITHUB_USER_URL", httpserver.url_for("/user"))
    install_cache()
    client = GithubOAuthClient("test-client", api_url=httpserver.url_for(""))
    httpserver.expect_ordered_request("/user").respond_with_json({"login": "alice"})
    httpserver.expect_ordered_request("/user").respond_with_json({"login": "bob"})

    assert client.fetch_login("gho_alice_token") == "alice"
    assert client.fetch_login("gho_bob_token") == "bob"


def test_redirect_hops_are_stored_without_the_authorization_header(install_cache, httpserver):
    cache_file = install_cache()
    # A renamed GitHub repository answers 301; requests follows it with the same Authorization header.
    httpserver.expect_request("/repos/a/old").respond_with_data(
        "", status=301, headers={"Location": httpserver.url_for("/repositories/1")}
    )
    httpserver.expect_request("/repositories/1").respond_with_json({"full_name": "a/new"})
    headers = {"Authorization": "Bearer ghp_REDIRECTSECRET"}

    first = requests.get(httpserver.url_for("/repos/a/old"), headers=headers, timeout=5)
    again = requests.get(httpserver.url_for("/repos/a/old"), headers=headers, timeout=5)
    stored = cached_payloads(cache_file)

    assert first.history and not getattr(first, "from_cache", False)
    assert getattr(again, "from_cache", False)
    # Control: the hop itself is stored, so the scan looks where the token used to be.
    assert b"/repos/a/old" in stored
    assert b"ghp_REDIRECTSECRET" not in stored


def test_stored_responses_are_compressed(install_cache, httpserver):
    cache_file = install_cache()
    httpserver.expect_request("/packument").respond_with_json({"versions": {f"1.0.{i}": {} for i in range(500)}})

    requests.get(httpserver.url_for("/packument"), timeout=5)
    requests_cache.uninstall_cache()
    with closing(sqlite3.connect(cache_file)) as con:
        (value,) = con.execute("SELECT value FROM responses").fetchone()

    assert requests_cache.pickle_serializer.loads(zlib.decompress(value)).url.endswith("/packument")


def test_a_row_written_before_compression_is_a_cache_miss_not_a_crash(tmp_path):
    cache = sqlite_cache(tmp_path)
    old_row = requests_cache.pickle_serializer.dumps(requests_cache.CachedResponse(url="https://example.org/a"))
    assert isinstance(old_row, bytes)
    put_rows(cache, {"old": None}, value=old_row)

    assert cache.get_response("old") is None


NOW = 2_000_000_000
DAY = 24 * 3600


def sqlite_cache(tmp_path) -> requests_cache.SQLiteCache:
    return requests_cache.SQLiteCache(tmp_path / "cache.sqlite3", serializer=CACHE_SERIALIZER)


def current_cache(tmp_path) -> requests_cache.SQLiteCache:
    """A cache already maintained once, so it is at CACHE_FORMAT_VERSION and only the purge applies."""
    cache = sqlite_cache(tmp_path)
    maintain_cache(cache, NOW)
    return cache


def put_rows(
    cache: requests_cache.SQLiteCache,
    expires: dict[str, int | None],
    redirects: dict[str, str] | None = None,
    value: bytes = b"x",
) -> None:
    with cache.responses.connection(commit=True) as con:
        con.executemany(
            "INSERT INTO responses (key, value, expires) VALUES (?, ?, ?)",
            [(key, value, when) for key, when in expires.items()],
        )
        con.executemany("INSERT INTO redirects (key, value) VALUES (?, ?)", list((redirects or {}).items()))


def stored(cache: requests_cache.SQLiteCache) -> tuple[set[str], dict[str, str]]:
    with cache.responses.connection() as con:
        keys = {key for (key,) in con.execute("SELECT key FROM responses")}
        aliases = dict(con.execute("SELECT key, value FROM redirects").fetchall())
    return keys, aliases


def user_version(cache: requests_cache.SQLiteCache) -> int:
    with cache.responses.connection() as con:
        return con.execute("PRAGMA user_version").fetchone()[0]


def test_maintain_cache_empties_a_file_written_by_an_older_format(tmp_path):
    cache = sqlite_cache(tmp_path)
    put_rows(cache, {"redirected": NOW + DAY, "plain": NOW + DAY}, redirects={"alias": "redirected"})

    maintain_cache(cache, NOW)

    assert stored(cache) == (set(), {})
    assert user_version(cache) == CACHE_FORMAT_VERSION


def test_maintain_cache_keeps_redirected_responses_written_by_the_current_format(tmp_path):
    cache = current_cache(tmp_path)
    put_rows(cache, {"redirected": NOW + DAY}, redirects={"alias": "redirected"})

    maintain_cache(cache, NOW)

    assert stored(cache) == ({"redirected"}, {"alias": "redirected"})


def test_maintain_cache_drops_responses_expired_beyond_the_retention(tmp_path):
    cache = current_cache(tmp_path)
    put_rows(
        cache,
        {
            "past_retention": NOW - CACHE_RETENTION_SECONDS,
            "within_retention": NOW - CACHE_RETENTION_SECONDS + 1,
            "fresh": NOW + DAY,
            "no_expiry": None,
        },
        redirects={"alias_gone": "past_retention", "alias_kept": "fresh"},
    )

    maintain_cache(cache, NOW)

    assert stored(cache) == ({"within_retention", "fresh", "no_expiry"}, {"alias_kept": "fresh"})


def test_maintain_cache_vacuums_once_enough_space_is_free(tmp_path, monkeypatch):
    monkeypatch.setattr(ossiq.clients, "VACUUM_MIN_FREE_BYTES", 0)
    cache = current_cache(tmp_path)
    put_rows(cache, {f"old{i}": NOW - 2 * CACHE_RETENTION_SECONDS for i in range(200)}, value=b"x" * 10_000)
    before = Path(cache.db_path).stat().st_size

    maintain_cache(cache, NOW)

    assert Path(cache.db_path).stat().st_size < before / 10


def test_maintain_cache_leaves_the_file_size_below_the_vacuum_threshold(tmp_path):
    cache = current_cache(tmp_path)
    put_rows(cache, {f"old{i}": NOW - 2 * CACHE_RETENTION_SECONDS for i in range(200)}, value=b"x" * 10_000)
    before = Path(cache.db_path).stat().st_size

    maintain_cache(cache, NOW)

    assert stored(cache) == (set(), {})
    assert Path(cache.db_path).stat().st_size == before


def test_maintain_cache_skips_a_file_another_process_is_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(ossiq.clients, "UPKEEP_LOCK_TIMEOUT_SECONDS", 0.05)
    cache = current_cache(tmp_path)
    put_rows(cache, {"past_retention": NOW - 2 * CACHE_RETENTION_SECONDS})
    with closing(sqlite3.connect(cache.db_path, isolation_level=None)) as other:
        other.execute("BEGIN EXCLUSIVE")
        maintain_cache(cache, NOW)
        other.execute("ROLLBACK")

    assert stored(cache) == ({"past_retention"}, {})


def test_remove_legacy_cache_deletes_the_file_and_its_sqlite_siblings(tmp_path):
    legacy = tmp_path / "old" / "cache.sqlite3"
    legacy.parent.mkdir()
    legacy.write_bytes(b"x" * 100)
    (legacy.parent / "cache.sqlite3-wal").write_bytes(b"x" * 10)
    (legacy.parent / "calibrate-cache.sqlite3").write_bytes(b"x")
    (legacy.parent / "config").write_text("OSSIQ_COOLDOWN_PERIOD=3\n")

    freed = remove_legacy_cache(legacy, tmp_path / "new" / "cache.sqlite3")

    assert freed == 110
    assert sorted(path.name for path in legacy.parent.iterdir()) == ["calibrate-cache.sqlite3", "config"]


def test_remove_legacy_cache_keeps_the_file_in_use(tmp_path):
    legacy = tmp_path / "cache.sqlite3"
    legacy.write_bytes(b"x")

    assert remove_legacy_cache(legacy, tmp_path / "." / "cache.sqlite3") == 0
    assert legacy.exists()


def test_remove_legacy_cache_without_a_file_frees_nothing(tmp_path):
    assert remove_legacy_cache(tmp_path / "cache.sqlite3", tmp_path / "new.sqlite3") == 0
