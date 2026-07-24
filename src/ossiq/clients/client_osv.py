"""
Pre-configured HTTP session and batch strategy for the OSV.dev CVE API.
"""

import requests

from ossiq.clients.batch import BatchClient, BatchStrategy, BatchStrategySettings, ChunkResult
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.package import Package

ECOSYSTEM_MAPPING = {
    ProjectPackagesRegistry.NPM: "npm",
    ProjectPackagesRegistry.PYPI: "PyPI",
}


class OsvBatchStrategy(BatchStrategy):
    """
    BatchStrategy implementation for the OSV.dev /v1/querybatch endpoint.

    prepare_item  : (Package, version) -> OSV query dict
    perform_request: POST /querybatch with a list of query dicts
    process_response: returns (pkg_name, version) -> list of lightweight OSV records
    next_items: enqueues only queries that have another page
    """

    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self, session: requests.Session):
        self.session = session

    @property
    def config(self) -> BatchStrategySettings:
        return BatchStrategySettings(
            chunk_size=50,
            max_retries=3,
            max_workers=3,
            request_timeout=30.0,
        )

    def prepare_item(self, item: tuple[Package, str]) -> dict:
        pkg, version = item
        return {
            "package": {"name": pkg.name, "ecosystem": ECOSYSTEM_MAPPING[pkg.registry]},
            "version": version,
        }

    def perform_request(self, chunk: list) -> requests.Response:
        return self.session.post(
            f"{self.BASE_URL}/querybatch",
            json={"queries": chunk},
            timeout=self.config.request_timeout,
        )

    def process_response(self, source_items: list[dict], response: ChunkResult) -> dict[tuple[str, str], list[dict]]:
        return {
            (query["package"]["name"], query["version"]): list(result.get("vulns", []))
            for query, result in zip(source_items, response.data[0].get("results", []), strict=True)
        }

    def next_items(self, source_items: list[dict], response: ChunkResult) -> list[dict]:
        return [
            {**query, "page_token": page_token}
            for query, result in zip(source_items, response.data[0].get("results", []), strict=True)
            if (page_token := result.get("next_page_token"))
        ]


class OsvDetailsBatchStrategy(BatchStrategy):
    """Fetch full OSV records individually by vulnerability ID."""

    BASE_URL = OsvBatchStrategy.BASE_URL

    def __init__(self, session: requests.Session):
        self.session = session

    @property
    def config(self) -> BatchStrategySettings:
        return BatchStrategySettings(
            chunk_size=1,
            max_retries=3,
            max_workers=5,
            request_timeout=30.0,
        )

    def prepare_item(self, item: str) -> str:
        return item

    def perform_request(self, chunk: list[str]) -> requests.Response:
        return self.session.get(
            f"{self.BASE_URL}/vulns/{chunk[0]}",
            timeout=self.config.request_timeout,
        )

    def process_response(self, source_items: list[str], response: ChunkResult) -> dict[str, dict]:
        return {source_items[0]: response.data[0]}


__all__ = (
    "BatchClient",
    "OsvBatchStrategy",
    "OsvDetailsBatchStrategy",
)
