"""
Factory to instantiate API clients
"""

from ossiq.adapters.api_npm import PackageRegistryApiNpm
from ossiq.adapters.api_osv import CveApiOsv
from ossiq.adapters.api_pypi import PackageRegistryApiPypi
from ossiq.domain.common import ProjectPackagesRegistry, RepositoryProvider
from ossiq.settings import Settings

from .api_github import SourceCodeProviderApiGithub
from .api_interfaces import AbstractCveDatabaseApi, AbstractPackageRegistryApi, AbstractSourceCodeProviderApi


def create_source_code_provider(provider_type: RepositoryProvider, settings: Settings) -> AbstractSourceCodeProviderApi:
    """
    Return source code provider (like Github) using factory and respective type
    """
    if provider_type == RepositoryProvider.PROVIDER_GITHUB:
        return SourceCodeProviderApiGithub(settings.github_token)
    else:
        raise ValueError(f"Unknown source code provider type: {provider_type}")


def create_package_registry_api(
    package_registry: ProjectPackagesRegistry, settings: Settings = None
) -> AbstractPackageRegistryApi:
    """
    Create insetance of a specific ecosystem's package registry API
    """

    if package_registry == ProjectPackagesRegistry.NPM:
        return PackageRegistryApiNpm(settings)
    elif package_registry == ProjectPackagesRegistry.PYPI:
        return PackageRegistryApiPypi(settings)
    else:
        raise ValueError(f"Unknown package registry: {package_registry}")


def create_cve_database() -> AbstractCveDatabaseApi:
    """
    Return CVE database (like osv.dev). The purpose is little different from
    Source Code Provider or Packages Registry/Ecosystem: there might be
    more than one CSV database. For externel clients it should look like a
    single database instance still.
    """
    return CveApiOsv()
