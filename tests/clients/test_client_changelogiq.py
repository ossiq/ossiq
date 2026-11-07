"""changelog IQ client: the UCS v1 parser against a real response and the spec's example, and the wait loop."""

from __future__ import annotations

from pathlib import Path

import pytest
import requests
from pytest_httpserver import HTTPServer

from ossiq.clients.client_changelogiq import api_url, fetch_range_changelog, parse_ucs, plain_text, web_url
from ossiq.domain.changelog import ChangelogStatus

FIXTURES = Path(__file__).parent / "fixtures"
PATH = "/v1/npm/packages/zod/changelog"

# The example from https://changelogiq.dev/ucs, which the API's own tests render with production code.
UCS_EXAMPLE = """---
package: "example"
ecosystem: "npm"
from_version: "1.5.0"
to_version: "2.0.0"
release_date: "2024-02-01"
risk_level: "HIGH"
breaking_change: true
security_fix: true
cve_references: ["CVE-2024-12345"]
future_key: {"ignored": true}
---

# Migration guides

- 1.6.0: [Upgrading to 1.6](https://example.com/upgrade-1.6)

# Changelog

## [2.0.0] - 2024-02-01 [YANKED]

_Drops the legacy loader and fixes a parser vulnerability._

### Added

- Add a `strict` option ([#50](https://github.com/o/r/issues/50), [#52](https://github.com/o/r/issues/52))

### Removed

- **Breaking:** Remove the Python 3.8 shim ([#47](https://github.com/o/r/issues/47))
- Remove `load_legacy()`

### Security

- Fix a parser denial of service (CVE-2024-12345)

## [1.6.0] - 2024-01-10

_Deprecates the legacy loader._

### Deprecated

- Deprecate `load_legacy()`, use `load()` instead ([#41](https://github.com/o/r/issues/41))

[2.0.0]: https://github.com/o/r/compare/v1.6.0...v2.0.0
[1.6.0]: https://github.com/o/r/compare/v1.5.0...v1.6.0
"""


def fetch(httpserver: HTTPServer, **kwargs):
    waits: list[float] = []
    result = fetch_range_changelog(
        requests.Session(),
        "npm",
        "zod",
        "3.21.0",
        "3.23.8",
        base_url=httpserver.url_for("").rstrip("/"),
        sleep=waits.append,
        **kwargs,
    )
    return result, waits


def test_the_front_matter_becomes_the_summary_and_unknown_keys_are_ignored() -> None:
    changelog = parse_ucs(UCS_EXAMPLE, "api", "web")

    assert changelog.status is ChangelogStatus.OK
    assert (changelog.risk_level, changelog.breaking_change, changelog.security_fix) == ("HIGH", True, True)
    assert changelog.cve_references == ("CVE-2024-12345",)


def test_a_breaking_item_loses_its_prefix_and_keeps_its_version_and_references() -> None:
    (breaking,) = parse_ucs(UCS_EXAMPLE, "api", "web").breaking_items

    assert (breaking.version, breaking.category) == ("2.0.0", "Removed")
    assert breaking.text == "Remove the Python 3.8 shim"
    assert breaking.references == ("https://github.com/o/r/issues/47",)


def test_code_spans_and_item_text_survive_and_every_item_is_read() -> None:
    items = parse_ucs(UCS_EXAMPLE, "api", "web").items

    assert [(i.version, i.category) for i in items] == [
        ("2.0.0", "Added"),
        ("2.0.0", "Removed"),
        ("2.0.0", "Removed"),
        ("2.0.0", "Security"),
        ("1.6.0", "Deprecated"),
    ]
    assert items[2].text == "Remove `load_legacy()`"
    assert items[0].references == ("https://github.com/o/r/issues/50", "https://github.com/o/r/issues/52")


def test_migration_guides_are_read_with_their_version() -> None:
    (guide,) = parse_ucs(UCS_EXAMPLE, "api", "web").guides

    assert (guide.version, guide.title, guide.url) == ("1.6.0", "Upgrading to 1.6", "https://example.com/upgrade-1.6")


def test_a_real_response_is_read_whole() -> None:
    text = (FIXTURES / "changelogiq_zod_3.21.0_3.23.8.md").read_text()

    changelog = parse_ucs(text, "api", "web")

    assert changelog.risk_level == "HIGH"
    assert {i.version for i in changelog.items} >= {"3.21.1", "3.22.0", "3.23.0", "3.23.8"}
    assert any(i.breaking and i.version == "3.23.0" for i in changelog.items)
    assert [g.version for g in changelog.guides] == ["3.22.1", "3.23.0"]
    assert changelog.markdown == text


def test_inert_text_is_restored_outside_code_spans_only() -> None:
    assert plain_text(r"a &lt;b&gt; \[x\]\(y\) `&lt;keep\.`") == r"a <b&gt; [x](y) `&lt;keep\.`"


def test_the_urls_name_the_range_and_encode_a_scoped_package() -> None:
    api = api_url("npm", "@types/node", "20.0.0", "22.1.0")
    web = web_url("npm", "@types/node", "20.0.0", "22.1.0")

    assert api == "https://api.changelogiq.dev/v1/npm/packages/%40types%2Fnode/changelog?from=20.0.0&to=22.1.0"
    assert web == "https://changelogiq.dev/?ecosystem=npm&package=%40types%2Fnode&from=20.0.0&to=22.1.0"


def test_a_ready_changelog_is_fetched_with_the_range(httpserver: HTTPServer) -> None:
    httpserver.expect_request(PATH, query_string={"from": "3.21.0", "to": "3.23.8"}).respond_with_data(
        UCS_EXAMPLE, content_type="text/markdown"
    )

    result, waits = fetch(httpserver)

    assert result.status is ChangelogStatus.OK and waits == []


def test_a_202_is_waited_out_and_its_progress_text_reported(httpserver: HTTPServer) -> None:
    httpserver.expect_ordered_request(PATH).respond_with_data(
        "Generating 3 of 8 versions of zod. Retry in 2 s.", status=202, headers={"Retry-After": "2"}
    )
    httpserver.expect_ordered_request(PATH).respond_with_data(UCS_EXAMPLE, content_type="text/markdown")
    seen: list[str] = []

    result, waits = fetch(httpserver, on_wait=seen.append)

    assert result.status is ChangelogStatus.OK
    assert waits == [2.0]
    assert seen == ["Generating 3 of 8 versions of zod. Retry in 2 s."]


def test_a_changelog_still_generating_when_the_budget_ends_is_pending(httpserver: HTTPServer) -> None:
    httpserver.expect_request(PATH).respond_with_data("Generating.", status=202, headers={"Retry-After": "30"})

    result, _ = fetch(httpserver, budget=10.0)

    assert result.status is ChangelogStatus.PENDING


@pytest.mark.parametrize(
    ("code", "status"),
    [(404, ChangelogStatus.NOT_FOUND), (422, ChangelogStatus.RANGE_TOO_WIDE), (500, ChangelogStatus.UNAVAILABLE)],
)
def test_an_error_is_a_status_not_an_exception(httpserver: HTTPServer, code: int, status: ChangelogStatus) -> None:
    httpserver.expect_request(PATH).respond_with_data("nope", status=code)

    result, _ = fetch(httpserver)

    assert result.status is status
    assert result.web_url.startswith("https://changelogiq.dev/")


def test_an_unreachable_host_is_unavailable() -> None:
    result = fetch_range_changelog(requests.Session(), "npm", "zod", "1.0.0", "2.0.0", base_url="http://127.0.0.1:1")

    assert result.status is ChangelogStatus.UNAVAILABLE
