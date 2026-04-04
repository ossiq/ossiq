# pylint: disable=protected-access
"""
Tests for OsvBatchStrategy in ossiq.clients.osv module.
"""

from unittest.mock import MagicMock

import pytest

from ossiq.clients.batch import ChunkResult
from ossiq.clients.client_osv import OsvBatchStrategy
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.package import Package


def make_package(name: str, registry: ProjectPackagesRegistry = ProjectPackagesRegistry.NPM) -> Package:
    return Package(registry=registry, name=name, latest_version="1.0.0", next_version=None, repo_url=None)


def make_chunk_result(results: list[dict]) -> ChunkResult:
    return ChunkResult(data=[{"results": results}], success=True)


class TestPrepareItem:
    def test_npm_package(self):
        """Test that an NPM package produces the correct query dict with 'npm' ecosystem."""
        strategy = OsvBatchStrategy(MagicMock())
        pkg = make_package("lodash", ProjectPackagesRegistry.NPM)

        result = strategy.prepare_item((pkg, "4.17.21"))

        assert result == {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.21"}

    def test_pypi_package(self):
        """Test that a PyPI package produces the correct query dict with 'PyPI' ecosystem."""
        strategy = OsvBatchStrategy(MagicMock())
        pkg = make_package("requests", ProjectPackagesRegistry.PYPI)

        result = strategy.prepare_item((pkg, "2.28.2"))

        assert result == {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.28.2"}


class TestPerformRequest:
    def test_posts_to_querybatch_endpoint(self):
        """Test that perform_request POSTs to /querybatch with the correct payload."""
        session = MagicMock()
        strategy = OsvBatchStrategy(session)
        chunk = [
            {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.21"},
        ]

        strategy.perform_request(chunk)

        call_args = session.post.call_args
        assert call_args[0][0].endswith("/querybatch")
        assert call_args[1]["json"] == {"queries": chunk}

    def test_uses_configured_timeout(self):
        """Test that perform_request uses the configured request_timeout."""
        session = MagicMock()
        strategy = OsvBatchStrategy(session)

        strategy.perform_request([])

        assert session.post.call_args[1]["timeout"] == strategy.config.request_timeout


class TestProcessResponse:
    def test_basic_positional_mapping(self):
        """Test that results[i] is mapped to the key derived from source_items[i]."""
        session = MagicMock()
        strategy = OsvBatchStrategy(session)
        source_items = [
            {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.21"},
            {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.28.2"},
        ]
        vuln_a = {"id": "GHSA-aaaa-0001"}
        vuln_b = {"id": "GHSA-bbbb-0002"}
        response = make_chunk_result([{"vulns": [vuln_a]}, {"vulns": [vuln_b]}])

        result = strategy.process_response(source_items, response)

        assert result == {
            ("lodash", "4.17.21"): [vuln_a],
            ("requests", "2.28.2"): [vuln_b],
        }

    def test_empty_vulns_maps_to_empty_list(self):
        """Test that a result with no 'vulns' key maps to an empty list."""
        strategy = OsvBatchStrategy(MagicMock())
        source_items = [{"package": {"name": "safe-pkg", "ecosystem": "npm"}, "version": "1.0.0"}]
        response = make_chunk_result([{}])

        result = strategy.process_response(source_items, response)

        assert result == {("safe-pkg", "1.0.0"): []}

    def test_pagination_merges_vulns_from_all_pages(self):
        """Test that vulns from follow-up paginated requests are merged into the result."""
        session = MagicMock()
        page2_response = MagicMock()
        page2_response.json.return_value = {"results": [{"vulns": [{"id": "GHSA-page2-002"}]}]}
        session.post.return_value = page2_response

        strategy = OsvBatchStrategy(session)
        source_items = [{"package": {"name": "pkg", "ecosystem": "npm"}, "version": "1.0.0"}]
        response = make_chunk_result([{"vulns": [{"id": "GHSA-page1-001"}], "next_page_token": "token-abc"}])

        result = strategy.process_response(source_items, response)

        vuln_ids = {v["id"] for v in result[("pkg", "1.0.0")]}
        assert vuln_ids == {"GHSA-page1-001", "GHSA-page2-002"}

    def test_pagination_request_includes_page_token(self):
        """Test that the follow-up pagination request includes the correct page_token."""
        session = MagicMock()
        page2_response = MagicMock()
        page2_response.json.return_value = {"results": [{"vulns": []}]}
        session.post.return_value = page2_response

        strategy = OsvBatchStrategy(session)
        source_items = [{"package": {"name": "pkg", "ecosystem": "npm"}, "version": "1.0.0"}]
        response = make_chunk_result([{"vulns": [], "next_page_token": "my-token-xyz"}])

        strategy.process_response(source_items, response)

        payload = session.post.call_args[1]["json"]
        assert payload["queries"][0]["page_token"] == "my-token-xyz"

    def test_pagination_stops_when_no_token(self):
        """Test that no additional requests are made once next_page_token is absent."""
        session = MagicMock()
        strategy = OsvBatchStrategy(session)
        source_items = [{"package": {"name": "pkg", "ecosystem": "npm"}, "version": "1.0.0"}]
        response = make_chunk_result([{"vulns": [{"id": "GHSA-only-001"}]}])

        strategy.process_response(source_items, response)

        session.post.assert_not_called()

    @pytest.mark.parametrize(
        "package_name,version,ecosystem",
        [
            ("lodash", "4.17.21", "npm"),
            ("requests", "2.28.2", "PyPI"),
        ],
    )
    def test_key_format(self, package_name, version, ecosystem):
        """Test that the result key is always (pkg_name, version) tuple."""
        strategy = OsvBatchStrategy(MagicMock())
        source_items = [{"package": {"name": package_name, "ecosystem": ecosystem}, "version": version}]
        response = make_chunk_result([{"vulns": []}])

        result = strategy.process_response(source_items, response)

        assert (package_name, version) in result
