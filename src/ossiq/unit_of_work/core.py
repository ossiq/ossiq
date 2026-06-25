"""
Abstract project sources: bag of external data providers for a scan run.
"""

import abc

from ossiq.adapters.api_github import SourceCodeProviderApiGithub
from ossiq.adapters.api_interfaces import AbstractPackageManagerApi, AbstractPackageRegistryApi
from ossiq.adapters.api_osv import CveApiOsv
from ossiq.domain.common import ProjectPackagesRegistry, RepositoryProvider
from ossiq.settings import Settings


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
    production: bool
    allow_prerelease: bool
    allow_prerelease_packages: tuple[str, ...]
    security_only: bool
    ignore_packages: tuple[str, ...]
    rewrite_versions: bool

    @abc.abstractmethod
    def get_source_code_provider(self, repository_provider_type: RepositoryProvider) -> SourceCodeProviderApiGithub:
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
