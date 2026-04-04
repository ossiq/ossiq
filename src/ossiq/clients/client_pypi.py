"""
Pre-configured HTTP session and batch strategy for the PyPI registry API.
"""

import requests

from ossiq.clients.batch import BatchClient, BatchStrategy, BatchStrategySettings, ChunkResult

PYPI_REGISTRY = "https://pypi.org/pypi"


class PypiBatchStrategy(BatchStrategy):
    """
    BatchStrategy implementation for the PyPI registry.

    Since PyPI has no bulk info endpoint, chunk_size=1 fetches packages
    individually but in parallel across max_workers threads.

    prepare_item  : package name string (identity — used as key in process_response)
    perform_request: GET /{name}/json
    process_response: returns {name: raw_registry_json}
    """

    BASE_URL = PYPI_REGISTRY

    def __init__(self, session: requests.Session):
        self.session = session

    @property
    def config(self) -> BatchStrategySettings:
        return BatchStrategySettings(
            chunk_size=1,
            max_retries=3,
            max_workers=5,
            request_timeout=15.0,
            has_pagination=False,
        )

    def prepare_item(self, item: str) -> str:
        return item

    def perform_request(self, chunk: list) -> requests.Response:
        name = chunk[0]
        return self.session.get(f"{self.BASE_URL}/{name}/json", timeout=self.config.request_timeout)

    def process_response(self, source_items: list, response: ChunkResult) -> dict[str, dict]:  # noqa: ARG002
        return {source_items[0]: response.data[0]}


__all__ = ("BatchClient", "PypiBatchStrategy")
