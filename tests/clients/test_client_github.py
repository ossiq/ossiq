"""Unit tests for the GitHub GraphQL activity batch strategy (ossiq.clients.client_github)."""

from unittest.mock import MagicMock

from ossiq.clients.batch import ChunkResult
from ossiq.clients.client_github import (
    FIRST_PAGE,
    RESPONSIVENESS_PAGE_CAP,
    GithubGraphQLBatchStrategy,
    build_activity_query,
    parse_activity_alias,
)

SINCE = "2026-05-01T00:00:00Z"
IN_WINDOW = "2026-06-01T00:00:00Z"
BEFORE_WINDOW = "2026-01-01T00:00:00Z"


def item(url: str, owner: str, name: str, stream: str, after: str = FIRST_PAGE, page: int = 0) -> tuple:
    return (url, owner, name, stream, after, page)


def chunk_result(body: dict) -> ChunkResult:
    return ChunkResult(data=[body], success=True)


def make_strategy() -> GithubGraphQLBatchStrategy:
    return GithubGraphQLBatchStrategy(session=MagicMock(), since=SINCE)


class TestBuildActivityQuery:
    def test_issues_stream_asks_only_for_issues_plus_pinned_issues(self) -> None:
        query = build_activity_query([item("u0", "astral-sh", "ruff", "issues")], SINCE)
        assert 'r0: repository(owner: "astral-sh", name: "ruff")' in query
        assert "issues(first: 100" in query
        assert f'filterBy: {{since: "{SINCE}"}}' in query
        assert "pinnedIssues(first: 3) { nodes { issue { title } } }" in query
        assert "comments(" not in query  # per-node subqueries trip GitHub's CPU-time secondary limit
        assert "pullRequests(" not in query
        assert "rateLimit { cost remaining nodeCount }" in query

    def test_pulls_stream_asks_only_for_pull_requests(self) -> None:
        query = build_activity_query([item("u0", "pallets", "flask", "pulls")], SINCE)
        assert "pullRequests(first: 100" in query
        assert "issues(" not in query
        assert "pinnedIssues" not in query
        assert "mergedAt" in query

    def test_issues_continuation_uses_the_cursor_and_drops_pinned_issues(self) -> None:
        query = build_activity_query([item("u0", "o", "n", "issues", after="IC", page=1)], SINCE)
        assert "issues(first: 100, orderBy: {field: UPDATED_AT, direction: DESC}, " in query
        assert 'after: "IC"' in query
        assert "pinnedIssues" not in query

    def test_pulls_continuation_uses_the_cursor(self) -> None:
        query = build_activity_query([item("u0", "o", "n", "pulls", after="PRCURSOR", page=2)], SINCE)
        assert 'pullRequests(first: 100, orderBy: {field: UPDATED_AT, direction: DESC}, after: "PRCURSOR")' in query


class TestParseActivityAlias:
    def test_issues_stream_exposes_next_cursor_and_pinned_titles(self) -> None:
        node = {
            "issues": {"pageInfo": {"hasNextPage": True, "endCursor": "IC"}, "nodes": [{"createdAt": IN_WINDOW}]},
            "pinnedIssues": {"nodes": [{"issue": {"title": "Notice: Project Deprecation"}}]},
        }
        parsed = parse_activity_alias(node, SINCE, "issues")
        assert parsed["issues"] == [{"createdAt": IN_WINDOW}]
        assert parsed["pulls"] == []
        assert parsed["next"] == "IC"
        assert parsed["pinned_titles"] == ["Notice: Project Deprecation"]

    def test_pulls_stream_exposes_next_cursor_while_the_window_is_open(self) -> None:
        node = {
            "pullRequests": {
                "pageInfo": {"hasNextPage": True, "endCursor": "PC"},
                "nodes": [{"updatedAt": IN_WINDOW}, {"updatedAt": IN_WINDOW}],
            }
        }
        parsed = parse_activity_alias(node, SINCE, "pulls")
        assert parsed["issues"] == []
        assert parsed["pinned_titles"] == []
        assert parsed["next"] == "PC"

    def test_pulls_stream_stops_paging_once_the_page_predates_the_window(self) -> None:
        node = {
            "pullRequests": {
                "pageInfo": {"hasNextPage": True, "endCursor": "PC"},
                "nodes": [{"updatedAt": IN_WINDOW}, {"updatedAt": BEFORE_WINDOW}],
            }
        }
        assert parse_activity_alias(node, SINCE, "pulls")["next"] is None


class TestProcessResponse:
    def test_maps_aliases_back_to_urls_and_nulls_an_errored_alias(self) -> None:
        strategy = make_strategy()
        source = [item("u0", "o", "a", "issues"), item("u1", "o", "b", "issues")]
        body = {
            "data": {
                "r0": {
                    "issues": {"pageInfo": {"hasNextPage": False}, "nodes": [{"createdAt": IN_WINDOW}]},
                    "pinnedIssues": {"nodes": [{"issue": {"title": "Deprecated"}}]},
                },
                "r1": None,
            }
        }
        result = strategy.process_response(source, chunk_result(body))
        assert result["u0"]["issues"] == [{"createdAt": IN_WINDOW}]
        assert result["u0"]["pinned_titles"] == ["Deprecated"]
        assert result["u1"] is None

    def test_pulls_chunk_yields_pull_nodes_under_the_same_url(self) -> None:
        strategy = make_strategy()
        source = [item("u0", "o", "a", "pulls")]
        body = {
            "data": {"r0": {"pullRequests": {"pageInfo": {"hasNextPage": False}, "nodes": [{"createdAt": IN_WINDOW}]}}}
        }
        result = strategy.process_response(source, chunk_result(body))
        assert result["u0"]["pulls"] == [{"createdAt": IN_WINDOW}]
        assert result["u0"]["issues"] == []


class TestNextItems:
    def test_emits_follow_up_for_an_unfinished_stream(self) -> None:
        strategy = make_strategy()
        source = [item("u0", "o", "a", "issues")]
        body = {"data": {"r0": {"issues": {"pageInfo": {"hasNextPage": True, "endCursor": "IC"}, "nodes": []}}}}
        assert strategy.next_items(source, chunk_result(body)) == [("u0", "o", "a", "issues", "IC", 1)]

    def test_stops_at_the_page_cap(self) -> None:
        strategy = make_strategy()
        source = [item("u0", "o", "a", "issues", after="IC", page=RESPONSIVENESS_PAGE_CAP - 1)]
        body = {"data": {"r0": {"issues": {"pageInfo": {"hasNextPage": True, "endCursor": "IC2"}, "nodes": []}}}}
        assert strategy.next_items(source, chunk_result(body)) == []
