# pylint: disable=protected-access
"""
Tests for OsvBatchStrategy in ossiq.clients.osv module.
"""

from unittest.mock import MagicMock

import pytest

from ossiq.clients.batch import ChunkResult
from ossiq.clients.client_osv import OsvBatchStrategy, OsvDetailsBatchStrategy
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

    def test_process_response_does_not_fetch_next_page_directly(self):
        session = MagicMock()
        strategy = OsvBatchStrategy(session)
        source_items = [{"package": {"name": "pkg", "ecosystem": "npm"}, "version": "1.0.0"}]
        response = make_chunk_result([{"vulns": [{"id": "GHSA-page1-001"}], "next_page_token": "token-abc"}])

        result = strategy.process_response(source_items, response)

        assert result[("pkg", "1.0.0")] == [{"id": "GHSA-page1-001"}]
        session.post.assert_not_called()

    def test_next_items_returns_only_queries_with_page_tokens(self):
        strategy = OsvBatchStrategy(MagicMock())
        source_items = [
            {"package": {"name": "pkg-a", "ecosystem": "npm"}, "version": "1.0.0"},
            {"package": {"name": "pkg-b", "ecosystem": "npm"}, "version": "2.0.0"},
        ]
        response = make_chunk_result(
            [
                {"vulns": [], "next_page_token": "my-token-xyz"},
                {"vulns": []},
            ]
        )

        result = strategy.next_items(source_items, response)

        assert result == [
            {
                "package": {"name": "pkg-a", "ecosystem": "npm"},
                "version": "1.0.0",
                "page_token": "my-token-xyz",
            }
        ]
        assert "page_token" not in source_items[0]

    def test_next_items_is_empty_without_page_token(self):
        strategy = OsvBatchStrategy(MagicMock())
        source_items = [{"package": {"name": "pkg", "ecosystem": "npm"}, "version": "1.0.0"}]
        response = make_chunk_result([{"vulns": [{"id": "GHSA-only-001"}]}])

        assert strategy.next_items(source_items, response) == []

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


class TestOsvDetailsBatchStrategy:
    def test_gets_full_record_by_id_with_configured_timeout(self):
        session = MagicMock()
        strategy = OsvDetailsBatchStrategy(session)

        strategy.perform_request(["GHSA-aaaa-0001"])

        session.get.assert_called_once_with(
            f"{strategy.BASE_URL}/vulns/GHSA-aaaa-0001",
            timeout=strategy.config.request_timeout,
        )

    def test_maps_full_record_to_requested_id(self):
        strategy = OsvDetailsBatchStrategy(MagicMock())
        full_record = {"id": "GHSA-aaaa-0001", "aliases": ["CVE-2024-0001"]}
        response = ChunkResult(data=[full_record], success=True)

        assert strategy.prepare_item("GHSA-aaaa-0001") == "GHSA-aaaa-0001"
        assert strategy.process_response(["GHSA-aaaa-0001"], response) == {
            "GHSA-aaaa-0001": full_record,
        }
