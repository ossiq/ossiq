"""Unit tests for the GitHub GraphQL activity batch strategy (ossiq.clients.client_github)."""

from unittest.mock import MagicMock

import requests

from ossiq.clients.batch import ChunkResult
from ossiq.clients.client_github import (
    FIRST_PAGE,
    RESPONSIVENESS_PAGE_CAP,
    GithubBranchControlsBatchStrategy,
    GithubGraphQLBatchStrategy,
    build_activity_query,
    fetch_rate_limit,
    parse_activity_alias,
)
from ossiq.domain.common import RateLimitBudget

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
        assert "closedAt" in query

    def test_issues_continuation_uses_the_cursor_and_drops_pinned_issues(self) -> None:
        query = build_activity_query([item("u0", "o", "n", "issues", after="IC", page=1)], SINCE)
        assert "issues(first: 100, orderBy: {field: UPDATED_AT, direction: DESC}, " in query
        assert 'after: "IC"' in query
        assert "pinnedIssues" not in query

    def test_pulls_continuation_uses_the_cursor(self) -> None:
        query = build_activity_query([item("u0", "o", "n", "pulls", after="PRCURSOR", page=2)], SINCE)
        assert 'pullRequests(first: 100, orderBy: {field: UPDATED_AT, direction: DESC}, after: "PRCURSOR")' in query


class TestFetchRateLimit:
    """The pre-flight quota check: free to call, and the only reading a fully cached scan gets."""

    def session_returning(self, body: dict) -> MagicMock:
        session = MagicMock()
        session.get.return_value.json.return_value = body
        return session

    def test_reads_core_and_graphql(self) -> None:
        session = self.session_returning(
            {
                "resources": {
                    "core": {"limit": 5000, "remaining": 4537, "reset": 1700000000},
                    "graphql": {"limit": 5000, "remaining": 5000, "reset": 1700000500},
                    "search": {"limit": 30, "remaining": 30, "reset": 1700000000},
                }
            }
        )

        budgets = fetch_rate_limit(session)

        assert budgets == (
            RateLimitBudget(resource="core", limit=5000, remaining=4537, reset_at=1700000000.0),
            RateLimitBudget(resource="graphql", limit=5000, remaining=5000, reset_at=1700000500.0),
        )

    def test_a_failed_check_is_one_less_thing_to_report_not_a_failed_scan(self) -> None:
        session = MagicMock()
        session.get.side_effect = requests.ConnectionError("down")

        assert fetch_rate_limit(session) == ()


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

    def test_null_nodes_from_a_partial_response_are_dropped(self) -> None:
        # GitHub answers a per-node INTERNAL error with HTTP 200 and a null in `nodes`; the
        # response is cached for a week, so one null crashed every later scan of that project.
        node = {
            "pullRequests": {
                "pageInfo": {"hasNextPage": False},
                "nodes": [{"updatedAt": IN_WINDOW}, None, {"updatedAt": IN_WINDOW}],
            }
        }
        assert parse_activity_alias(node, SINCE, "pulls")["pulls"] == [
            {"updatedAt": IN_WINDOW},
            {"updatedAt": IN_WINDOW},
        ]

    def test_null_issue_and_pinned_nodes_are_dropped(self) -> None:
        node = {
            "issues": {"pageInfo": {"hasNextPage": False}, "nodes": [None, {"createdAt": IN_WINDOW}]},
            "pinnedIssues": {"nodes": [None, {"issue": {"title": "Deprecated"}}]},
        }
        parsed = parse_activity_alias(node, SINCE, "issues")
        assert parsed["issues"] == [{"createdAt": IN_WINDOW}]
        assert parsed["pinned_titles"] == ["Deprecated"]


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


class TestBranchControlsRequest:
    URL = "https://github.com/pallets/flask"

    def test_protection_reads_the_branch_endpoint(self) -> None:
        strategy = GithubBranchControlsBatchStrategy(MagicMock(), "protection")

        assert strategy.prepare_item((self.URL, "main")) == (self.URL, "repos/pallets/flask/branches/main")

    def test_rules_read_the_ruleset_endpoint(self) -> None:
        strategy = GithubBranchControlsBatchStrategy(MagicMock(), "rules")

        assert strategy.prepare_item((self.URL, "main")) == (self.URL, "repos/pallets/flask/rules/branches/main")

    def test_a_branch_with_a_slash_keeps_it_and_other_characters_are_quoted(self) -> None:
        strategy = GithubBranchControlsBatchStrategy(MagicMock(), "protection")

        _, path = strategy.prepare_item((self.URL, "release/1.x #beta"))

        assert path.endswith("/branches/release/1.x%20%23beta")

    def test_the_request_goes_to_the_api_host(self) -> None:
        session = MagicMock()
        strategy = GithubBranchControlsBatchStrategy(session, "rules")

        strategy.perform_request([(self.URL, "repos/pallets/flask/rules/branches/main")])

        assert session.get.call_args[0][0] == "https://api.github.com/repos/pallets/flask/rules/branches/main"


class TestBranchControlsResponse:
    URL = "https://github.com/pallets/flask"

    def process(self, kind, body):
        strategy = GithubBranchControlsBatchStrategy(MagicMock(), kind)
        return strategy.process_response([(self.URL, "main")], chunk_result(body))

    def test_classic_protection_enabled(self) -> None:
        assert self.process("protection", {"protected": True, "protection": {"enabled": True}}) == {self.URL: True}

    def test_a_ruleset_only_branch_is_not_classically_protected(self) -> None:
        # GitHub sets the top-level `protected` for a ruleset too, but `protection.enabled` stays false.
        body = {"protected": True, "protection": {"enabled": False}}

        assert self.process("protection", body) == {self.URL: False}

    def test_a_branch_with_no_protection_object_is_unprotected(self) -> None:
        assert self.process("protection", {"name": "main"}) == {self.URL: False}

    def test_an_answer_that_is_not_an_object_says_nothing(self) -> None:
        assert self.process("protection", ["unexpected"]) == {}

    def test_the_rules_are_passed_through(self) -> None:
        rules = [{"type": "deletion"}, {"type": "pull_request", "parameters": {"required_approving_review_count": 1}}]

        assert self.process("rules", rules) == {self.URL: rules}

    def test_an_empty_rule_list_is_an_answer_not_a_gap(self) -> None:
        assert self.process("rules", []) == {self.URL: []}

    def test_junk_among_the_rules_is_dropped(self) -> None:
        assert self.process("rules", [{"type": "deletion"}, "x", 3]) == {self.URL: [{"type": "deletion"}]}

    def test_rules_that_are_not_a_list_say_nothing(self) -> None:
        assert self.process("rules", {"message": "Not Found"}) == {}
