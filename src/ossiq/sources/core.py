"""
Abstract project sources: bag of external data providers for a scan run.
"""

import abc

from ossiq.adapters.api_epss import EpssApiFirstOrg
from ossiq.adapters.api_interfaces import (
    AbstractPackageManagerApi,
    AbstractPackageRegistryApi,
    AbstractSourceCodeProviderApi,
)
from ossiq.adapters.api_osv import CveApiOsv
from ossiq.domain.common import ProjectPackagesRegistry, RepositoryProvider
from ossiq.domain.release_cutoff import ReleaseCutoff
from ossiq.settings import Settings
from ossiq.strategy.overrides import StrategyPlan


class AbstractProjectSources(abc.ABC):
    """
    Bundle of external data providers and scan configuration for a single scan run.
    """

    settings: Settings
    project_path: str
    narrow_package_manager: ProjectPackagesRegistry | None
    packages_manager: AbstractPackageManagerApi
    packages_registry: AbstractPackageRegistryApi
    cve_database: CveApiOsv
    epss_score_database: EpssApiFirstOrg
    production: bool
    allow_prerelease: bool
    allow_prerelease_packages: tuple[str, ...]
    strategy: StrategyPlan
    ignore_packages: tuple[str, ...]
    rewrite_versions: bool
    release_cutoff: ReleaseCutoff | None = None
    """The package manager's own limit on how recent a release it will move to, or None when it
    sets none. Read from the project's package-manager config once, when the sources open."""
    warnings: list[str]
    """Non-fatal problems found while assembling the sources, for the scan to carry onto
    ScanResult. A value, not a print: nothing below ui/ decides what the user sees."""

    @abc.abstractmethod
    def get_source_code_provider(self, repository_provider_type: RepositoryProvider) -> AbstractSourceCodeProviderApi:
        """
        Method to get source code provider by its type. The point here is that
        single project has multiple package installed and each package
        might come from different source code providers (Github, Bitbucket, etc.)
        """
        raise NotImplementedError("Source Code Provider getter not implemented")

    def __enter__(self):
        raise NotImplementedError("Enter not implemented")

    def __exit__(self, *args):
        raise NotImplementedError("Exit not implemented")
