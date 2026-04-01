# pylint: disable=protected-access
"""
Tests for PypiBatchStrategy in ossiq.clients.client_pypi module.
"""

from unittest.mock import MagicMock

from ossiq.clients.batch import ChunkResult
from ossiq.clients.client_pypi import PypiBatchStrategy


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
