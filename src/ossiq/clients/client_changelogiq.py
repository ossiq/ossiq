"""Client for changelog IQ (https://changelogiq.dev): the changelog between two versions, as UCS v1 markdown.

The format is specified at https://changelogiq.dev/ucs. A response is generated on first request, so
the API answers `202` with `Retry-After` until it is ready.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from urllib.parse import quote, urlencode

import requests

from ossiq.clients.common import get_user_agent
from ossiq.domain.changelog import ChangelogItem, ChangelogStatus, MigrationGuide, RangeChangelog

API_URL = "https://api.changelogiq.dev"
WEB_URL = "https://changelogiq.dev"
REQUEST_TIMEOUT = 30.0
DEFAULT_RETRY_SECONDS = 10.0
MAX_RETRY_SECONDS = 60.0
# Generating a long range takes a while the first time. shortcut: a fixed 15-minute budget, no setting;
# add one if anyone's range genuinely takes longer.
WAIT_BUDGET_SECONDS = 900.0
RETRY_STATUSES = (202, 429, 503)

BREAKING_PREFIX = "**Breaking:** "
FRONT_MATTER_KEY = re.compile(r"^(\w+): (.*)$")
VERSION_HEADING = re.compile(r"^## \[(.+?)\] - (\S+)( \[YANKED\])?$")
CATEGORY = re.compile(r"^### (\w+)$")
GUIDE = re.compile(r"^- (.+?): \[(.+)\]\((.+)\)$")
REFERENCES = re.compile(r" \((\[#\d+\]\(https?://[^)\s]+\)(?:, \[#\d+\]\(https?://[^)\s]+\))*)\)$")
REFERENCE_URL = re.compile(r"\]\((https?://[^)\s]+)\)")
# Escapes first, so an escaped backtick is not taken for the start of a code span, which is verbatim.
INERT_TEXT = re.compile(r"(?P<escaped>\\[!-/:-@\[-`{-~])|(?P<code>`[^`]*`)|(?P<lt>&lt;)")


def plain_text(text: str) -> str:
    """Undo the escaping UCS puts on text to make it inert, outside code spans."""

    def restore(match: re.Match[str]) -> str:
        if match["escaped"]:
            return match["escaped"][1]
        if match["lt"]:
            return "<"
        return match["code"]

    return INERT_TEXT.sub(restore, text)


def api_url(ecosystem: str, package: str, from_version: str, to_version: str, base_url: str = API_URL) -> str:
    query = urlencode({"from": from_version, "to": to_version})
    return f"{base_url}/v1/{ecosystem}/packages/{quote(package, safe='')}/changelog?{query}"


def web_url(ecosystem: str, package: str, from_version: str, to_version: str) -> str:
    """The changelogiq.dev page where a person reads the same range."""
    query = urlencode({"ecosystem": ecosystem, "package": package, "from": from_version, "to": to_version})
    return f"{WEB_URL}/?{query}"


def parse_front_matter(lines: list[str]) -> tuple[dict[str, object], int]:
    """The `---` block's keys, and the index of the first line after it. Values are JSON."""
    if not lines or lines[0] != "---":
        return {}, 0
    try:
        end = lines.index("---", 1)
    except ValueError:
        end = len(lines)
    front: dict[str, object] = {}
    for line in lines[1:end]:
        if match := FRONT_MATTER_KEY.match(line):
            try:
                front[match.group(1)] = json.loads(match.group(2))
            except json.JSONDecodeError:
                continue
    return front, end + 1


def parse_item(line: str, version: str, category: str) -> ChangelogItem:
    """One `- ` line of a changelog section: the breaking prefix, the text and the trailing references."""
    body = line.removeprefix("- ")
    breaking = body.startswith(BREAKING_PREFIX)
    body = body.removeprefix(BREAKING_PREFIX)
    references: tuple[str, ...] = ()
    if refs := REFERENCES.search(body):
        references = tuple(REFERENCE_URL.findall(refs.group(1)))
        body = body[: refs.start()]
    return ChangelogItem(version, category, plain_text(body), breaking, references)


def parse_ucs(text: str, source_url: str, page_url: str) -> RangeChangelog:
    """Read a UCS v1 document. Unknown front-matter keys are ignored, as the format requires."""
    lines = text.splitlines()
    front, start = parse_front_matter(lines)

    guides: list[MigrationGuide] = []
    items: list[ChangelogItem] = []
    section, version, category = "", "", ""
    for line in lines[start:]:
        if line == "# Migration guides":
            section = "guides"
        elif line == "# Changelog":
            section = "changelog"
        elif section == "guides" and (match := GUIDE.match(line)):
            guides.append(MigrationGuide(match.group(1), plain_text(match.group(2)), match.group(3)))
        elif section == "changelog":
            if match := VERSION_HEADING.match(line):
                version, category = match.group(1), ""
            elif match := CATEGORY.match(line):
                category = match.group(1)
            elif category and line.startswith("- "):
                items.append(parse_item(line, version, category))

    cves = front.get("cve_references")
    risk = front.get("risk_level")
    return RangeChangelog(
        status=ChangelogStatus.OK,
        source_url=source_url,
        web_url=page_url,
        risk_level=risk if isinstance(risk, str) else None,
        breaking_change=front.get("breaking_change") is True,
        security_fix=front.get("security_fix") is True,
        cve_references=tuple(str(cve) for cve in cves) if isinstance(cves, list) else (),
        items=tuple(items),
        guides=tuple(guides),
        markdown=text,
    )


def retry_delay(response: requests.Response) -> float:
    try:
        seconds = float(response.headers.get("Retry-After", DEFAULT_RETRY_SECONDS))
    except ValueError:
        seconds = DEFAULT_RETRY_SECONDS
    return min(max(seconds, 1.0), MAX_RETRY_SECONDS)


def fetch_range_changelog(
    session: requests.Session,
    ecosystem: str,
    package: str,
    from_version: str,
    to_version: str,
    *,
    base_url: str = API_URL,
    on_wait: Callable[[str], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    budget: float = WAIT_BUDGET_SECONDS,
) -> RangeChangelog:
    """Fetch the changelog of the versions after *from_version* up to *to_version*.

    Waits while the API generates it. Every failure comes back as a status on the result: a
    changelog that cannot be had must not stop an upgrade, only be shown as missing.

    Args:
        session: The HTTP session to use.
        ecosystem: "npm" or "pypi".
        package: The registry name.
        from_version: The installed version, which the range starts after.
        to_version: The target version.
        base_url: The API root; replaced in tests.
        on_wait: Receives the API's progress text each time it asks for a retry.
        sleep: How to wait; replaced in tests.
        clock: A monotonic clock; replaced in tests.
        budget: Seconds to wait for generation before giving up as PENDING.

    Returns:
        The changelog, or a result whose status says why there is none.
    """
    source_url = api_url(ecosystem, package, from_version, to_version, base_url)
    page_url = web_url(ecosystem, package, from_version, to_version)

    def missing(status: ChangelogStatus, detail: str) -> RangeChangelog:
        return RangeChangelog(status=status, source_url=source_url, web_url=page_url, detail=detail)

    deadline = clock() + budget
    while True:
        try:
            response = session.get(
                source_url,
                headers={"Accept": "text/markdown", "User-Agent": get_user_agent()},
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as exc:
            return missing(ChangelogStatus.UNAVAILABLE, f"{type(exc).__name__}: {exc}")
        if response.status_code == 200:
            return parse_ucs(response.text, source_url, page_url)
        text = response.text.strip()
        if response.status_code in RETRY_STATUSES:
            delay = retry_delay(response)
            if clock() + delay > deadline:
                return missing(ChangelogStatus.PENDING, text or "still generating")
            if on_wait is not None and text:
                on_wait(text)
            sleep(delay)
            continue
        if response.status_code == 404:
            return missing(ChangelogStatus.NOT_FOUND, "changelog IQ does not know this package or version")
        if response.status_code == 422:
            return missing(ChangelogStatus.RANGE_TOO_WIDE, text or "range not accepted")
        return missing(ChangelogStatus.UNAVAILABLE, f"changelog IQ answered {response.status_code}")
