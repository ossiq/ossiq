"""
Pre-configured HTTP session and batch strategy for the ClearlyDefined API.
"""

import requests

from ossiq.clients.batch import BatchClient, BatchStrategy, BatchStrategySettings, ChunkResult
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.package import Package

REGISTRY_MAPPING = {
    ProjectPackagesRegistry.PYPI: ("pypi", "pypi"),
    ProjectPackagesRegistry.NPM: ("npm", "npmjs"),
}


class ClearlyDefinedBatchStrategy(BatchStrategy):
    """
    BatchStrategy implementation for the ClearlyDefined /definitions endpoint.

    prepare_item  : (Package, version) - coordinate string
    perform_request: POST /definitions with a list of coordinates
    process_response: returns the raw coord - definition dict from the response
    """

    BASE_URL = "https://api.clearlydefined.io"

    def __init__(self, session: requests.Session):
        self.session = session

    @property
    def config(self) -> BatchStrategySettings:
        return BatchStrategySettings(
            chunk_size=25,
            max_retries=3,
            request_timeout=60.0,
            max_workers=3,
            has_pagination=False,
        )

    def prepare_item(self, item: tuple[Package, str]) -> str:
        pkg, version = item
        pkg_type, provider = REGISTRY_MAPPING[pkg.registry]

        if pkg.registry == ProjectPackagesRegistry.NPM and pkg.name.startswith("@"):
            scope, name = pkg.name.split("/", 1)
            return f"{pkg_type}/{provider}/{scope}/{name}/{version}"

        return f"{pkg_type}/{provider}/-/{pkg.name}/{version}"

    def perform_request(self, chunk: list) -> requests.Response:
        return self.session.post(
            f"{self.BASE_URL}/definitions",
            json=chunk,
            timeout=self.config.request_timeout,
        )

    def process_response(self, source_items: list, response: ChunkResult) -> dict[str, dict]:  # noqa: ARG002
        return response.data[0]


__all__ = ("BatchClient", "ClearlyDefinedBatchStrategy")
