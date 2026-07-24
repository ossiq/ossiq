"""
Pre-configured HTTP session and batch strategy for the api.first.com API.
"""

import requests

from ossiq.clients.batch import BatchClient, BatchStrategy, BatchStrategySettings, ChunkResult
from ossiq.domain.common import ProjectPackagesRegistry

ECOSYSTEM_MAPPING = {
    ProjectPackagesRegistry.NPM: "npm",
    ProjectPackagesRegistry.PYPI: "PyPI",
}


class EpssBatchStrategy(BatchStrategy):
    """
    BatchStrategy implementation for the api.first.org /data/v1/epss endpoint.
    """

    BASE_URL = "https://api.first.org/data/v1/epss"

    def __init__(self, session: requests.Session):
        self.session = session

    @property
    def config(self) -> BatchStrategySettings:
        return BatchStrategySettings(
            chunk_size=100,
            max_retries=3,
            max_workers=2,
            request_timeout=30.0,
        )

    def prepare_item(self, item: str) -> str | None:
        """
        Checking if CVE ID is prefixed with `CVE-` (actually, simplificatin -
        it should be in `CVE-YYYY-NNNNN`, but let's start with this for now).
        """
        # NOTE: first.org doesn't support non CVE-prefixed IDs
        if not item.startswith("CVE-"):
            return None

        return item

    def perform_request(self, chunk: list[str]) -> requests.Response:
        return self.session.get(
            f"{self.BASE_URL}",
            params={"cve": ",".join(chunk)},
            timeout=self.config.request_timeout,
        )

    def process_response(self, source_items: list[str], response: ChunkResult) -> dict[str, float]:  # noqa: ARG002
        """
        Processing single chunk response from the first.org API.
        Response looks like the following snippet:
        ```
          {
            "status": "OK",
            ...
            "data": [
                {
                    "cve": "CVE-2022-26332",
                    "epss": "0.006820000",
                    "percentile": "0.484310000",
                    "date": "2026-07-20"
                }
            ]
        }
        ```
        """
        mapping: dict[str, float] = {}

        for result in response.data[0].get("data", []):
            mapping[result["cve"]] = float(result["epss"])

        return mapping


__all__ = (
    "BatchClient",
    "EpssBatchStrategy",
)
