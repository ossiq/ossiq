import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from ossiq.clients.clearlydefined import ClearlyDefinedSession
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.package import Package

from .api_interfaces import AbstractLicenseDatabaseApi

REGISTRY_MAPPING = {
    ProjectPackagesRegistry.PYPI: ("pypi", "pypi"),
    ProjectPackagesRegistry.NPM: ("npm", "npmjs"),
}

CHUNK_SIZE = 25
MAX_WORKERS = 5
MAX_RETRIES = 3
CHUNK_TIMEOUT = 60

logger = logging.getLogger(__name__)


class LicenseApiClearlyDefined(AbstractLicenseDatabaseApi):
    """
    An AbstractLicenseDatabaseApi implementation using ClearlyDefined.
    Uses POST /definitions to fetch normalized SPDX licenses for all packages.
    Large batches are split into chunks of CHUNK_SIZE and dispatched concurrently.
    Each chunk is retried up to MAX_RETRIES times on transient failures.
    """

    def __init__(self, session: ClearlyDefinedSession):
        self.base_url = "https://api.clearlydefined.io"
        self.session = session

    def __repr__(self):
        return f"LicenseApiClearlyDefined(base_url='{self.base_url}')"

    def get_licenses_batch(
        self, packages_with_versions: list[tuple[Package, str]]
    ) -> dict[tuple[str, str], str | None]:
        if not packages_with_versions:
            return {}

        coordinates = [self._build_coordinate(pkg, version) for pkg, version in packages_with_versions]
        chunks = [coordinates[i : i + CHUNK_SIZE] for i in range(0, len(coordinates), CHUNK_SIZE)]

        merged: dict[str, dict] = {}
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {pool.submit(self._fetch_chunk, chunk): chunk for chunk in chunks}
            for future in as_completed(futures):
                merged.update(future.result())

        results: dict[tuple[str, str], str | None] = {}
        for (pkg, version), coord in zip(packages_with_versions, coordinates, strict=True):
            results[(pkg.name, version)] = self._extract_license(merged.get(coord, {}))

        return results

    def _fetch_chunk(self, coordinates: list[str]) -> dict[str, dict]:
        for attempt in range(MAX_RETRIES):
            try:
                resp = self.session.post(f"{self.base_url}/definitions", json=coordinates, timeout=CHUNK_TIMEOUT)
                if (resp.status_code or 0) >= 500:
                    raise requests.HTTPError(response=resp)
                resp.raise_for_status()
                return resp.json()
            except (requests.Timeout, requests.ConnectionError, requests.HTTPError) as exc:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(2**attempt)
                else:
                    logger.warning(
                        "ClearlyDefined chunk of %d packages failed after %d attempts: %s",
                        len(coordinates),
                        MAX_RETRIES,
                        exc,
                    )
                    return {}
        return {}

    def _build_coordinate(self, pkg: Package, version: str) -> str:
        pkg_type, provider = REGISTRY_MAPPING[pkg.registry]

        if pkg.registry == ProjectPackagesRegistry.NPM and pkg.name.startswith("@"):
            # Scoped package: @scope/name → namespace=@scope, name=name
            scope, name = pkg.name.split("/", 1)
            return f"{pkg_type}/{provider}/{scope}/{name}/{version}"

        return f"{pkg_type}/{provider}/-/{pkg.name}/{version}"

    def _extract_license(self, definition: dict) -> str | None:
        licensed = definition.get("licensed", {})

        declared = licensed.get("declared")
        if declared:
            return declared

        expressions = licensed.get("facets", {}).get("core", {}).get("discovered", {}).get("expressions", [])
        if expressions:
            return expressions[0]

        return None
