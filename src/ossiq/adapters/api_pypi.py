"""
Implementation of Package Registry API client for PyPI
"""
import os

from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.settings import Settings
try:
    import tomllib
except ImportError:
    # Python < 3.11
    import tomli as tomllib
from collections.abc import Iterable

import requests
from rich.console import Console

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.adapters.detectors import detect_package_manager
from ossiq.domain.ecosystem import UV
from ossiq.domain.package import Package
from ossiq.domain.project import Project
from ossiq.domain.version import PackageVersion

console = Console()

PYPI_REGISTRY = "https://pypi.org/pypi"


class PackageRegistryApiPypi(AbstractPackageRegistryApi):
    """
    Implementation of Package Registry API client for PyPI
    """

    package_registry_ecosystem = ProjectPackagesRegistry.PYPI

    def __init__(self, settings: Settings):
        super().__init__()
        self.settings = settings

    def __repr__(self):
        return "<PackageRegistryApiPypi instance>"

    def _make_request(self, path: str, headers: dict | None = None, timeout: int = 15) -> dict:
        r = requests.get(f"{PYPI_REGISTRY}{path}",
                         timeout=timeout, headers=headers)
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
