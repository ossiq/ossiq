# pylint: disable=protected-access
"""
Tests for NpmBatchStrategy in ossiq.clients.client_npm module.
"""

from unittest.mock import MagicMock

from ossiq.clients.batch import ChunkResult
from ossiq.clients.client_npm import NpmBatchStrategy


def make_chunk_result(data: dict) -> ChunkResult:
    return ChunkResult(data=[data], success=True)


class TestPrepareItem:
    def test_returns_name_unchanged(self):
        """prepare_item is an identity — the name is used as the key in process_response."""
        strategy = NpmBatchStrategy(MagicMock())
        assert strategy.prepare_item("lodash") == "lodash"

    def test_scoped_package_name_unchanged(self):
        """Scoped NPM packages (@scope/name) pass through unchanged."""
        strategy = NpmBatchStrategy(MagicMock())
        assert strategy.prepare_item("@babel/core") == "@babel/core"


class TestConfig:
    def test_chunk_size_is_one(self):
        """Each package is fetched individually since NPM has no bulk endpoint."""
        strategy = NpmBatchStrategy(MagicMock())
        assert strategy.config.chunk_size == 1

    def test_has_multiple_workers(self):
        """Multiple workers enable parallel fetches."""
        strategy = NpmBatchStrategy(MagicMock())
        assert strategy.config.max_workers > 1


class TestPerformRequest:
    def test_gets_package_by_name(self):
        """perform_request issues a GET to {BASE_URL}/{name}."""
        session = MagicMock()
        strategy = NpmBatchStrategy(session)

        strategy.perform_request(["lodash"])

        url = session.get.call_args[0][0]
        assert url == f"{strategy.BASE_URL}/lodash"

    def test_scoped_package_url(self):
        """Scoped packages (@scope/name) form a valid GET URL."""
        session = MagicMock()
        strategy = NpmBatchStrategy(session)

        strategy.perform_request(["@babel/core"])

        url = session.get.call_args[0][0]
        assert url == f"{strategy.BASE_URL}/@babel/core"

    def test_uses_configured_timeout(self):
        """perform_request uses the configured request_timeout."""
        session = MagicMock()
        strategy = NpmBatchStrategy(session)

        strategy.perform_request(["lodash"])

        assert session.get.call_args[1]["timeout"] == strategy.config.request_timeout


class TestProcessResponse:
    def test_maps_name_to_raw_json(self):
        """process_response returns {name: raw_registry_json}."""
        strategy = NpmBatchStrategy(MagicMock())
        raw = {"name": "lodash", "dist-tags": {"latest": "4.17.21"}}
        response = make_chunk_result(raw)

        result = strategy.process_response(["lodash"], response)

        assert result == {"lodash": raw}

    def test_key_is_source_item(self):
        """The key in the returned dict is the prepared item (package name)."""
        strategy = NpmBatchStrategy(MagicMock())
        raw = {"name": "@babel/core"}
        response = make_chunk_result(raw)

        result = strategy.process_response(["@babel/core"], response)

        assert "@babel/core" in result
