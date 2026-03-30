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

    prepare_item  : (Package, version) → OSV query dict
    perform_request: POST /querybatch with a list of query dicts
    process_response: returns (pkg_name, version) → list of raw OSV vuln dicts,
                      handling pagination via self.session
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
            has_pagination=True,
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
        """
        Map a ChunkResult back to per-package vuln lists.

        source_items are the prepared query dicts for this chunk (output of
        prepare_item). The OSV API returns results[i] positionally for queries[i],
        so we zip source_items with the results array directly.

        Pagination (next_page_token) is handled here since OsvBatchStrategy
        owns the session — it is an OSV-specific concern, not a generic batch one.
        """
        mapping: dict[tuple[str, str], list[dict]] = {}

        for query, result in zip(source_items, response.data[0].get("results", []), strict=True):
            key = (query["package"]["name"], query["version"])
            vulns = list(result.get("vulns", []))

            page_token = result.get("next_page_token")
            while page_token:
                page_resp = self.session.post(
                    f"{self.BASE_URL}/querybatch",
                    json={
                        "queries": [
                            {
                                "package": query["package"],
                                "version": query["version"],
                                "page_token": page_token,
                            }
                        ]
                    },
                    timeout=self.config.request_timeout,
                )
                page_resp.raise_for_status()
                page_result = page_resp.json().get("results", [{}])[0]
                vulns.extend(page_result.get("vulns", []))
                page_token = page_result.get("next_page_token")

            mapping[key] = vulns

        return mapping


__all__ = (
    "BatchClient",
    "OsvBatchStrategy",
)  # "OsvSession"]
