# pylint: disable=protected-access
"""
Tests for PypiBatchStrategy in ossiq.clients.client_pypi module.
"""

from unittest.mock import MagicMock

import pytest
import requests

from ossiq.clients.batch import BatchClient, ChunkResult
from ossiq.clients.client_pypi import (
    PypiBatchStrategy,
    PypiSimpleIndexBatchStrategy,
    SimpleIndex,
    parse_simple_index,
)


def make_chunk_result(data: dict) -> ChunkResult:
    return ChunkResult(data=[data], success=True)


class TestPrepareItem:
    def test_returns_name_unchanged(self):
        """prepare_item is an identity — the name is used as the key in process_response."""
        strategy = PypiBatchStrategy(MagicMock())
        assert strategy.prepare_item("requests") == "requests"


class TestConfig:
    def test_chunk_size_is_one(self):
        """Each package is fetched individually since PyPI has no bulk endpoint."""
        strategy = PypiBatchStrategy(MagicMock())
        assert strategy.config.chunk_size == 1

    def test_has_multiple_workers(self):
        """Multiple workers enable parallel fetches."""
        strategy = PypiBatchStrategy(MagicMock())
        assert strategy.config.max_workers > 1


class TestPerformRequest:
    def test_gets_package_json_endpoint(self):
        """perform_request issues a GET to {BASE_URL}/{name}/json."""
        session = MagicMock()
        strategy = PypiBatchStrategy(session)

        strategy.perform_request(["requests"])

        url = session.get.call_args[0][0]
        assert url == f"{strategy.BASE_URL}/requests/json"

    def test_url_has_json_suffix(self):
        """The /json suffix is required by the PyPI JSON API."""
        session = MagicMock()
        strategy = PypiBatchStrategy(session)

        strategy.perform_request(["Django"])

        url = session.get.call_args[0][0]
        assert url.endswith("/json")

    def test_uses_configured_timeout(self):
        """perform_request uses the configured request_timeout."""
        session = MagicMock()
        strategy = PypiBatchStrategy(session)

        strategy.perform_request(["requests"])

        assert session.get.call_args[1]["timeout"] == strategy.config.request_timeout


class TestProcessResponse:
    def test_maps_name_to_raw_json(self):
        """process_response returns {name: raw_registry_json}."""
        strategy = PypiBatchStrategy(MagicMock())
        raw = {"info": {"name": "requests", "version": "2.31.0"}, "releases": {}}
        response = make_chunk_result(raw)

        result = strategy.process_response(["requests"], response)

        assert result == {"requests": raw}

    def test_key_is_source_item(self):
        """The key in the returned dict is the prepared item (package name)."""
        strategy = PypiBatchStrategy(MagicMock())
        raw = {"info": {"name": "Django", "version": "4.2.0"}, "releases": {}}
        response = make_chunk_result(raw)

        result = strategy.process_response(["Django"], response)

        assert "Django" in result


def simple_index(*files: tuple[str, str | None], status: dict | None = None) -> dict:
    """A `simple.v1+json` project page with the given (filename, provenance URL) files."""
    payload: dict = {
        "meta": {"api-version": "1.4"},
        "name": "demo",
        "files": [{"filename": name, "hashes": {"sha256": "0" * 64}, "provenance": url} for name, url in files],
    }
    if status is not None:
        payload["project-status"] = status
    return payload


class TestParseSimpleIndex:
    def test_reads_the_status_of_an_archived_project(self):
        assert parse_simple_index(simple_index(status={"status": "archived"})).status == {"status": "archived"}

    def test_reads_the_reason_when_the_index_gives_one(self):
        index = parse_simple_index(simple_index(status={"status": "deprecated", "reason": "Use other-lib instead"}))

        assert index.status == {"status": "deprecated", "reason": "Use other-lib instead"}

    def test_a_page_with_no_status_is_an_empty_status(self):
        # PEP 792 lets an index leave the object out for an active project.
        assert parse_simple_index(simple_index()).status == {}

    def test_a_status_that_is_not_text_is_dropped(self):
        assert parse_simple_index(simple_index(status={"status": 7, "reason": None})).status == {}

    @pytest.mark.parametrize("payload", [None, [], "<html></html>", 5])
    def test_a_payload_that_is_not_an_object_is_an_empty_index(self, payload):
        assert parse_simple_index(payload) == SimpleIndex(status={}, provenance={})

    def test_keys_provenance_by_file_name(self):
        url = "https://pypi.org/integrity/demo/1.0/demo-1.0.tar.gz/provenance"
        index = parse_simple_index(simple_index(("demo-1.0.tar.gz", url), ("demo-1.0-py3-none-any.whl", None)))

        assert index.provenance == {"demo-1.0.tar.gz": url, "demo-1.0-py3-none-any.whl": None}

    def test_a_file_without_a_provenance_key_is_unattested(self):
        payload = {"files": [{"filename": "demo-1.0.tar.gz"}]}

        assert parse_simple_index(payload).provenance == {"demo-1.0.tar.gz": None}

    def test_skips_file_entries_that_name_no_file(self):
        payload = {"files": [{"provenance": "https://x"}, "junk", {"filename": 3}]}

        assert parse_simple_index(payload).provenance == {}


class TestSimpleIndexRequest:
    def test_requests_the_canonical_simple_url(self):
        session = MagicMock()
        PypiSimpleIndexBatchStrategy(session).perform_request(["Typed_AST"])

        assert session.get.call_args[0][0] == "https://pypi.org/simple/typed-ast/"

    def test_asks_for_the_whole_json_page(self):
        session = MagicMock()
        PypiSimpleIndexBatchStrategy(session).perform_request(["demo"])

        headers = session.get.call_args.kwargs["headers"]
        assert headers == {"Accept": "application/vnd.pypi.simple.v1+json"}

    def test_process_response_keys_the_index_by_the_requested_name(self):
        strategy = PypiSimpleIndexBatchStrategy(MagicMock())
        page = simple_index(("demo-1.0.tar.gz", "https://x"), status={"status": "archived"})

        result = strategy.process_response(["Typed_AST"], ChunkResult(data=[page], success=True))

        assert result == {
            "Typed_AST": SimpleIndex(status={"status": "archived"}, provenance={"demo-1.0.tar.gz": "https://x"})
        }


class TestSimpleIndexAgainstAServer:
    """The request, end to end over real HTTP."""

    @pytest.fixture
    def strategy(self, httpserver):
        strategy = PypiSimpleIndexBatchStrategy(requests.Session())
        strategy.BASE_URL = httpserver.url_for("/simple")
        return strategy

    def test_reads_status_and_provenance_from_one_response(self, httpserver, strategy):
        page = simple_index(("demo-1.0.tar.gz", "https://x/provenance"), status={"status": "archived"})
        httpserver.expect_request(
            "/simple/typed-ast/", headers={"Accept": "application/vnd.pypi.simple.v1+json"}
        ).respond_with_json(page, content_type="application/vnd.pypi.simple.v1+json")

        (chunk,) = BatchClient(strategy).run_batch(["typed_ast"])

        assert chunk == {
            "typed_ast": SimpleIndex(
                status={"status": "archived"}, provenance={"demo-1.0.tar.gz": "https://x/provenance"}
            )
        }

    def test_a_body_that_is_not_json_is_dropped_rather_than_guessed_active(self, httpserver, strategy):
        httpserver.expect_request("/simple/demo/").respond_with_data("<html></html>", content_type="text/html")

        assert list(BatchClient(strategy).run_batch(["demo"])) == []

    def test_an_unknown_project_is_dropped_rather_than_guessed_active(self, httpserver, strategy):
        httpserver.expect_request("/simple/nope/").respond_with_data("Not Found", status=404)

        assert list(BatchClient(strategy).run_batch(["nope"])) == []
