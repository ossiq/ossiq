"""
Pre-configured batch strategies for the GitHub repository info and statistics APIs.
"""

import base64
import logging
import re
from datetime import UTC, datetime

import requests

from ossiq.clients.batch import BatchClient, BatchStrategy, BatchStrategySettings, ChunkResult

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
GITHUB_URL_RE = re.compile(r"github\.com[:/](?P<owner>[^/]+)/(?P<name>[^/.]+)")

FIRST_PAGE = "\x00first"
"""Sentinel `after` value for the first request of a repo/stream, before any GraphQL cursor exists."""

RESPONSIVENESS_PAGE_CAP = 6
"""Max GraphQL pages per stream per repo (~600 issues or PRs). A 180-day window rarely needs more;
the cap bounds a very busy repo before it trips GitHub's secondary rate limit. Undersampling a
hot repo biases the flow trend only mildly - it feeds a naive-Bayes observation, not a score."""

README_HEAD_BYTES = 4096
"""How much of a README to keep for the deprecation-banner scan - a banner is at the very top or
it is not a banner."""

ACTIVITY_CHUNK_SIZE = 1
"""Repos per GraphQL query. Issues and PRs are fetched in separate requests (one stream per query);
one repo per query on top of that keeps each query cheap. Budget is fine (~2-6 requests per direct
dependency over the 180-day window, cached 7 days)."""


def repo_owner_name(url: str) -> tuple[str, str]:
    """(owner, name) for a GitHub URL in any form a registry reports it."""
    stripped = url.strip().removeprefix("git+").removeprefix("https://")
    match = GITHUB_URL_RE.search(stripped)
    if not match:
        raise ValueError(f"Invalid GitHub URL: {url}")
    return match.group("owner"), match.group("name")


def repo_api_path(url: str) -> str:
    """Build the `repos/owner/name` API path for a GitHub URL in any form a registry reports it."""
    owner, name = repo_owner_name(url)
    return f"repos/{owner}/{name}"


class GithubRepoBatchStrategy(BatchStrategy):
    """
    BatchStrategy implementation for fetching GitHub repository metadata.

    Since the GitHub REST API has no bulk /repos endpoint, chunk_size=1
    fetches repos individually but in parallel across max_workers threads.

    prepare_item   : url str -> (original_url, "repos/owner/name")
    perform_request: GET /repos/owner/name
    process_response: {original_url: raw_repo_dict}
    """

    def __init__(self, session: requests.Session):
        self.session = session

    @property
    def config(self) -> BatchStrategySettings:
        return BatchStrategySettings(
            chunk_size=1,
            max_retries=3,
            max_workers=5,
            request_timeout=15.0,
        )

    def prepare_item(self, item: str) -> tuple[str, str]:
        return (item, repo_api_path(item))

    def perform_request(self, chunk: list) -> requests.Response:
        _, api_path = chunk[0]
        return self.session.get(f"{GITHUB_API}/{api_path}", timeout=self.config.request_timeout)

    def process_response(self, source_items: list, response: ChunkResult) -> dict[str, dict]:
        original_url, _ = source_items[0]
        return {original_url: response.data[0]}


class GithubCommitsBatchStrategy(BatchStrategy):
    """
    BatchStrategy for the last 100 commits, newest-first as GitHub returns them.

    GET /repos/{owner}/{repo}/commits?per_page=100[&until=<iso>] - event-censored sampling.
    Never defers (no 202/204), unlike the retired stats/commit_activity endpoint.
    """

    def __init__(self, session: requests.Session, until: str | None = None):
        self.session = session
        self.until = until

    @property
    def config(self) -> BatchStrategySettings:
        return BatchStrategySettings(
            chunk_size=1,
            max_retries=3,
            max_workers=5,
            request_timeout=15.0,
        )

    def prepare_item(self, item: str) -> tuple[str, str]:
        path = f"{repo_api_path(item)}/commits?per_page=100"
        if self.until:
            path += f"&until={self.until}"
        return (item, path)

    def perform_request(self, chunk: list) -> requests.Response:
        _, api_path = chunk[0]
        return self.session.get(f"{GITHUB_API}/{api_path}", timeout=self.config.request_timeout)

    def process_response(self, source_items: list, response: ChunkResult) -> dict[str, list]:
        original_url, _ = source_items[0]
        commits = response.data[0] if response.data else None
        return {original_url: commits if isinstance(commits, list) else []}


def graphql_payload(response: ChunkResult) -> dict:
    """`data` map from a GraphQL response, logging the node cost. `{}` when the query wholly failed."""
    body = response.data[0] if response.data else {}
    data = body.get("data") or {}
    errors = body.get("errors") or []
    rate = data.get("rateLimit")
    if rate:
        logger.debug(
            "GraphQL activity: cost=%s remaining=%s nodes=%s",
            rate.get("cost"),
            rate.get("remaining"),
            rate.get("nodeCount"),
        )
    if any(error.get("type") == "RESOURCE_LIMITS_EXCEEDED" for error in errors):
        logger.warning(
            "GraphQL activity query hit GitHub's per-query resource limit - lower ACTIVITY_CHUNK_SIZE "
            "or the issue/PR page size. Some repos in this chunk will be under-sampled."
        )
    elif not data and errors:
        logger.warning("GraphQL activity query returned no data: %s", errors[0].get("message"))
    return data


def to_datetime(value: str | None) -> datetime:
    """Parse a GraphQL ISO-8601 timestamp; `datetime.min` (UTC) for a missing one."""
    return datetime.fromisoformat(value) if value else datetime.min.replace(tzinfo=UTC)


def build_activity_query(chunk: list, since: str) -> str:
    """One aliased GraphQL query body for a chunk of `(url, owner, name, stream, after, page)`.

    Each item covers exactly one stream - "issues" or "pulls" - of one repo; issues and PRs are
    fetched in separate requests to keep each query cheap (GitHub's secondary rate limit is CPU-
    time based, so per-node subqueries are avoided). An `after` of FIRST_PAGE requests the first
    page, a cursor string continues. `pinnedIssues` rides the first issues page - a pinned
    deprecation / migration notice is a maintenance signal.
    """
    issue_fields = "createdAt closedAt author { __typename login }"
    pr_fields = "createdAt mergedAt closedAt updatedAt author { __typename login }"
    aliases = []
    for index, item in enumerate(chunk):
        _, owner, name, stream, after, _ = item
        cursor = "" if after == FIRST_PAGE else f', after: "{after}"'
        if stream == "issues":
            selection = (
                "issues(first: 100, orderBy: {field: UPDATED_AT, direction: DESC}, "
                f'filterBy: {{since: "{since}"}}{cursor}) '
                "{ pageInfo { hasNextPage endCursor } nodes { " + issue_fields + " } }"
            )
            if after == FIRST_PAGE:
                selection += " pinnedIssues(first: 3) { nodes { issue { title } } }"
        else:
            selection = (
                f"pullRequests(first: 100, orderBy: {{field: UPDATED_AT, direction: DESC}}{cursor}) "
                "{ pageInfo { hasNextPage endCursor } nodes { " + pr_fields + " } }"
            )
        aliases.append(f'r{index}: repository(owner: "{owner}", name: "{name}") {{ {selection} }}')
    return "{ " + " ".join(aliases) + " rateLimit { cost remaining nodeCount } }"


def parse_activity_alias(node: dict, since: str, stream: str) -> dict:
    """One repository alias -> raw nodes for `stream`, its pinned-issue titles, and its next cursor.

    Only the windowing that decides *how many pages to fetch* happens here (PRs carry no
    server-side date filter). Bot filtering and createdAt/closedAt/mergedAt bucketing for the
    statistics themselves happen in `service/project/stability.py` over the raw nodes.
    """
    if stream == "issues":
        conn = node.get("issues") or {}
        page = conn.get("pageInfo") or {}
        pinned = (node.get("pinnedIssues") or {}).get("nodes") or []
        return {
            "issues": conn.get("nodes") or [],
            "pulls": [],
            "pinned_titles": [(entry.get("issue") or {}).get("title") or "" for entry in pinned],
            "next": page.get("endCursor") if page.get("hasNextPage") else None,
        }

    since_dt = datetime.fromisoformat(since)
    conn = node.get("pullRequests") or {}
    page = conn.get("pageInfo") or {}
    pr_nodes = conn.get("nodes") or []
    # PRs come back UPDATED_AT desc with no `since` filter: once the oldest PR on a page predates
    # the window, every later page is outside it too.
    pr_window_open = bool(pr_nodes) and to_datetime(pr_nodes[-1].get("updatedAt")) >= since_dt
    return {
        "issues": [],
        "pulls": pr_nodes,
        "pinned_titles": [],
        "next": page.get("endCursor") if (page.get("hasNextPage") and pr_window_open) else None,
    }


class GithubGraphQLBatchStrategy(BatchStrategy):
    """Batched GitHub GraphQL job for the engagement-flow stability channel.

    One POST per (repo, stream) pair - issues and PRs are fetched in separate requests to keep each
    query under GitHub's per-query resource limit. Covers a RESPONSIVENESS_WINDOW_DAYS look-back.
    Issues carry a server-side `since` filter; PRs don't, so `pullRequests` (UPDATED_AT desc) is
    paged via `next_items` until the window is covered or RESPONSIVENESS_PAGE_CAP is hit. A per-repo
    GraphQL error (repo renamed/deleted) nulls that alias and yields `{url: None}` for that stream
    rather than failing the whole batch; the other stream is unaffected.

    Source items are `(url, stream)`; prepared and follow-up items share the shape
    `(url, owner, name, stream, after, page)`.
    """

    def __init__(self, session: requests.Session, since: str):
        self.session = session
        self.since = since

    @property
    def config(self) -> BatchStrategySettings:
        # max_workers is deliberately low: GitHub's GraphQL secondary rate limit is CPU-time
        # based, and 5 threads paginating issues in parallel trips it on a corpus-sized run.
        return BatchStrategySettings(
            chunk_size=ACTIVITY_CHUNK_SIZE,
            max_retries=3,
            max_workers=3,
            request_timeout=20.0,
        )

    def prepare_item(self, item: tuple[str, str]) -> tuple | None:
        url, stream = item
        try:
            owner, name = repo_owner_name(url)
        except ValueError:
            return None
        return (url, owner, name, stream, FIRST_PAGE, 0)

    def perform_request(self, chunk: list) -> requests.Response:
        query = build_activity_query(chunk, self.since)
        return self.session.post(
            f"{GITHUB_API}/graphql",
            json={"query": query},
            timeout=self.config.request_timeout,
        )

    def process_response(self, source_items: list, response: ChunkResult) -> dict:
        data = graphql_payload(response)
        result: dict = {}
        for index, item in enumerate(source_items):
            url, _, _, stream, _, _ = item
            node = data.get(f"r{index}")
            if node is None:
                result[url] = None
                continue
            parsed = parse_activity_alias(node, self.since, stream)
            result[url] = {
                "issues": parsed["issues"],
                "pulls": parsed["pulls"],
                "pinned_titles": parsed["pinned_titles"],
            }
        return result

    def next_items(self, source_items: list, response: ChunkResult) -> list:
        data = graphql_payload(response)
        follow_ups: list = []
        for index, item in enumerate(source_items):
            url, owner, name, stream, _, page = item
            node = data.get(f"r{index}")
            if node is None or page + 1 >= RESPONSIVENESS_PAGE_CAP:
                continue
            next_cursor = parse_activity_alias(node, self.since, stream)["next"]
            if next_cursor:
                follow_ups.append((url, owner, name, stream, next_cursor, page + 1))
        return follow_ups


class GithubReadmeBatchStrategy(BatchStrategy):
    """The top of a repository's README, for the deprecation-banner scan.

    GET /repos/{owner}/{repo}/readme returns the default branch README as base64 JSON. One
    request per repo, cached like the commit sample, truncated to README_HEAD_BYTES.
    """

    def __init__(self, session: requests.Session):
        self.session = session

    @property
    def config(self) -> BatchStrategySettings:
        return BatchStrategySettings(
            chunk_size=1,
            max_retries=2,
            max_workers=5,
            request_timeout=15.0,
        )

    def prepare_item(self, item: str) -> tuple[str, str]:
        return (item, f"{repo_api_path(item)}/readme")

    def perform_request(self, chunk: list) -> requests.Response:
        _, api_path = chunk[0]
        return self.session.get(f"{GITHUB_API}/{api_path}", timeout=self.config.request_timeout)

    def process_response(self, source_items: list, response: ChunkResult) -> dict[str, str]:
        original_url, _ = source_items[0]
        body = response.data[0] if response.data else None
        if not isinstance(body, dict) or body.get("encoding") != "base64":
            return {original_url: ""}
        try:
            text = base64.b64decode(body.get("content") or "").decode("utf-8", errors="replace")
        except ValueError:
            return {original_url: ""}
        return {original_url: text[:README_HEAD_BYTES]}


__all__ = (
    "BatchClient",
    "GithubCommitsBatchStrategy",
    "GithubGraphQLBatchStrategy",
    "GithubReadmeBatchStrategy",
    "GithubRepoBatchStrategy",
)
