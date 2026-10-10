# pylint: disable=protected-access
"""
Tests for PypiBatchStrategy in ossiq.clients.client_pypi module.
"""

from unittest.mock import MagicMock

import pytest
import requests

from ossiq.clients.batch import BatchClient, ChunkResult
from ossiq.clients.client_pypi import (
    PROJECT_STATUS_HEAD_BYTES,
    PypiBatchStrategy,
    PypiProjectStatusBatchStrategy,
    parse_project_status,
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


def simple_page(*meta: str, body: str = "") -> str:
    """A Simple API project page (HTML form) with the given <meta> lines in its head."""
    head = "\n".join(meta)
    return (
        '<!DOCTYPE html>\n<html lang="en">\n  <head>\n'
        f"{head}\n    <title>Links for demo</title>\n  </head>\n  <body>\n    <h1>Links for demo</h1>\n{body}"
    )


class TestParseProjectStatus:
    def test_reads_the_status_of_an_archived_project(self):
        page = simple_page(
            '<meta name="pypi:repository-version" content="1.4">',
            '<meta name="pypi:project-status" content="archived">',
        )
        assert parse_project_status(page) == {"status": "archived"}

    def test_reads_the_reason_when_the_index_gives_one(self):
        page = simple_page(
            '<meta name="pypi:project-status" content="deprecated">',
            '<meta name="pypi:project-status-reason" content="Use other-lib instead">',
        )
        assert parse_project_status(page) == {"status": "deprecated", "reason": "Use other-lib instead"}

    def test_a_page_with_no_status_meta_is_an_empty_status(self):
        # PEP 792 lets an index leave the tag out for an active project.
        assert parse_project_status(simple_page('<meta name="pypi:repository-version" content="1.4">')) == {}

    def test_a_page_that_is_not_html_is_an_empty_status(self):
        assert parse_project_status("") == {}
        assert parse_project_status('{"name": "demo"}') == {}

    def test_ignores_status_markup_that_appears_after_the_head(self):
        # A project can name anything in a file link; only the head carries the index's verdict.
        page = simple_page(body='<meta name="pypi:project-status" content="quarantined">')
        assert parse_project_status(page) == {}

    def test_survives_a_head_cut_off_mid_tag(self):
        page = simple_page('<meta name="pypi:project-status" content="archived">')
        assert parse_project_status(page[: page.index("<title>") + 3]) == {"status": "archived"}


class TestProjectStatusRequest:
    def test_requests_the_canonical_simple_url(self):
        session = MagicMock()
        PypiProjectStatusBatchStrategy(session).perform_request(["Typed_AST"])

        assert session.get.call_args[0][0] == "https://pypi.org/simple/typed-ast/"

    def test_asks_for_only_the_start_of_an_html_page(self):
        session = MagicMock()
        PypiProjectStatusBatchStrategy(session).perform_request(["demo"])

        headers = session.get.call_args.kwargs["headers"]
        assert headers["Accept"] == "application/vnd.pypi.simple.v1+html"
        assert headers["Range"] == f"bytes=0-{PROJECT_STATUS_HEAD_BYTES - 1}"
        # A byte range applies to the encoded body; a gzip fragment cannot be parsed.
        assert headers["Accept-Encoding"] == "identity"

    def test_fans_out_wider_than_the_json_strategies(self):
        assert (
            PypiProjectStatusBatchStrategy(MagicMock()).config.max_workers
            > PypiBatchStrategy(MagicMock()).config.max_workers
        )

    def test_keeps_only_the_head_of_a_page_the_server_sent_whole(self):
        # A server that ignores Range answers 200 with every file link of the project.
        response = MagicMock(spec=requests.Response)
        response.content = (simple_page(body="x" * 10_000)).encode()

        decoded = PypiProjectStatusBatchStrategy(MagicMock()).decode_response(response)

        assert len(decoded) == PROJECT_STATUS_HEAD_BYTES

    def test_decodes_a_cut_multibyte_character_without_raising(self):
        response = MagicMock(spec=requests.Response)
        response.content = ("é" * PROJECT_STATUS_HEAD_BYTES).encode()

        PypiProjectStatusBatchStrategy(MagicMock()).decode_response(response)

    def test_process_response_keys_the_status_by_the_requested_name(self):
        strategy = PypiProjectStatusBatchStrategy(MagicMock())
        page = simple_page('<meta name="pypi:project-status" content="archived">')

        result = strategy.process_response(["Typed_AST"], ChunkResult(data=[page], success=True))

        assert result == {"Typed_AST": {"status": "archived"}}


class TestProjectStatusAgainstAServer:
    """The ranged request, end to end over real HTTP."""

    @pytest.fixture
    def strategy(self, httpserver):
        strategy = PypiProjectStatusBatchStrategy(requests.Session())
        strategy.BASE_URL = httpserver.url_for("/simple")
        return strategy

    def test_reads_the_status_out_of_a_partial_response(self, httpserver, strategy):
        page = simple_page('<meta name="pypi:project-status" content="archived">', body="<a>file</a>\n" * 500)
        httpserver.expect_request(
            "/simple/typed-ast/", headers={"Range": f"bytes=0-{PROJECT_STATUS_HEAD_BYTES - 1}"}
        ).respond_with_data(page[:PROJECT_STATUS_HEAD_BYTES], status=206, content_type="text/html")

        (chunk,) = BatchClient(strategy).run_batch(["typed_ast"])

        assert chunk == {"typed_ast": {"status": "archived"}}

    def test_an_unknown_project_is_dropped_rather_than_guessed_active(self, httpserver, strategy):
        httpserver.expect_request("/simple/nope/").respond_with_data("Not Found", status=404)

        assert list(BatchClient(strategy).run_batch(["nope"])) == []
