"""
LicenseApiClearlyDefined: translates between the ossiq Package domain and
the ClearlyDefined batch client.  All HTTP logic lives in ClearlyDefinedBatchStrategy.
"""

import logging

import requests

from ossiq.clients.batch import BatchClient
from ossiq.clients.client_clearlydefined import ClearlyDefinedBatchStrategy
from ossiq.clients.common import get_user_agent
from ossiq.domain.package import Package
from ossiq.settings import Settings

from .api_interfaces import AbstractLicenseDatabaseApi

logger = logging.getLogger(__name__)


class LicenseApiClearlyDefined(AbstractLicenseDatabaseApi):
    """
    AbstractLicenseDatabaseApi implementation backed by ClearlyDefined.
    Translates (Package, version) tuples to SPDX license strings.
    All batching, chunking, retries, and rate-limit handling are delegated
    to BatchClient + ClearlyDefinedBatchStrategy.
    """

    session: requests.Session

    def __init__(self, settings: Settings):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": get_user_agent(),
            }
        )

        self._strategy = ClearlyDefinedBatchStrategy(self.session)
        self._batch_client = BatchClient(self._strategy)

    def __repr__(self):
        return f"LicenseApiClearlyDefined(base_url='{self._strategy.BASE_URL}')"

    def get_licenses_batch(
        self, packages_with_versions: list[tuple[Package, str]]
    ) -> dict[tuple[str, str], str | None]:
        if not packages_with_versions:
            return {}

        merged: dict[str, dict] = {}
        for chunk_data in self._batch_client.run_batch(packages_with_versions):
            merged.update(chunk_data)

        return {
            (pkg.name, version): self._extract_license(merged.get(self._strategy.prepare_item((pkg, version)), {}))
            for pkg, version in packages_with_versions
        }

    def _extract_license(self, definition: dict) -> str | None:
        licensed = definition.get("licensed", {})

        declared = licensed.get("declared")
        if declared:
            return declared

        expressions = licensed.get("facets", {}).get("core", {}).get("discovered", {}).get("expressions", [])
        if expressions:
            return expressions[0]

        return None
