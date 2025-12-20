"""
Factory to instantiate API clients
"""

from ossiq.adapters.api_npm import PackageRegistryApiNpm
from ossiq.adapters.api_osv import CveApiOsv
from ossiq.domain.common import ProjectPackagesRegistry, RepositoryProvider
from ossiq.settings import Settings

from .api_github import SourceCodeProviderApiGithub
from .api_interfaces import AbstractCveDatabaseApi, AbstractPackageRegistryApi, AbstractSourceCodeProviderApi


def get_source_code_provider(provider_type: RepositoryProvider, settings: Settings) -> AbstractSourceCodeProviderApi:
    """
    Return source code provider (like Github) using factory and respective type
    """
    if provider_type == RepositoryProvider.PROVIDER_GITHUB:
        return SourceCodeProviderApiGithub(settings.github_token)
    else:
        raise ValueError(f"Unknown source code provider type: {provider_type}")


def get_package_registry(registry_type: ProjectPackagesRegistry) -> AbstractPackageRegistryApi:
    """
    Return package registry (like NPM) using factory and respective type
    """
    if registry_type == ProjectPackagesRegistry.NPM:
        return PackageRegistryApiNpm()
    else:
        raise ValueError(f"Unknown package registry type: {registry_type}")


def get_cve_database() -> AbstractCveDatabaseApi:
    """
    Return CVE database (like osv.dev). The purpose is little different from
    Source Code Provider or Packages Registry/Ecosystem: there might be
    more than one CSV database. For externel clients it should look like a
    single database instance still.
    """
    return CveApiOsv()
