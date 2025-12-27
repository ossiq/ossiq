"""
Implementation of Package Registry API client for PyPI
"""

from collections.abc import Iterable

import requests
from rich.console import Console

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.package import Package
from ossiq.domain.version import PackageVersion
from ossiq.settings import Settings

console = Console()

PYPI_REGISTRY = "https://pypi.org/pypi"


class PackageRegistryApiPypi(AbstractPackageRegistryApi):
    """
    Implementation of Package Registry API client for PyPI
    """

    package_registry = ProjectPackagesRegistry.PYPI
    settings: Settings

    def __init__(self, settings: Settings):
        super().__init__()
        self.settings = settings

    def __repr__(self):
        return "<PackageRegistryApiPypi instance>"

    def _make_request(self, path: str, headers: dict | None = None, timeout: int = 15) -> dict:
        r = requests.get(f"{PYPI_REGISTRY}{path}", timeout=timeout, headers=headers)
        r.raise_for_status()
        return r.json()

    def package_info(self, package_name: str) -> Package:
        """
        Fetch PyPI info for a given package.
        """
        # TODO: Implement this
        raise NotImplementedError

    def package_versions(self, package_name: str) -> Iterable[PackageVersion]:
        """
        Fetch PyPI versions for a given package.
        """
        # TODO: Implement this
        raise NotImplementedError
