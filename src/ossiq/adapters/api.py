"""
Factory to instantiate API clients
"""
from ossiq.adapters.api_npm import PackageRegistryApiNpm
from ossiq.settings import Settings
from ossiq.domain.common import ProjectPackagesRegistryKind, RepositoryProviderType
from .api_github import SourceCodeProviderApiGithub
from .api_interfaces import AbstractSourceCodeProviderApi
from .api_interfaces import AbstractPackageRegistryApi


def get_source_code_provider(provider_type: RepositoryProviderType, settings: Settings) -> AbstractSourceCodeProviderApi:
    """
    Return source code provider (like Github) using factory and respective type
    """
    if provider_type == RepositoryProviderType.PROVIDER_GITHUB:
        return SourceCodeProviderApiGithub(settings.github_token)
    else:
        raise ValueError(f"Unknown source code provider type: {provider_type}")


def get_package_registry(registry_type: ProjectPackagesRegistryKind) -> AbstractPackageRegistryApi:
    """
    Return package registry (like NPM) using factory and respective type
    """
    if registry_type == ProjectPackagesRegistryKind.NPM:
        return PackageRegistryApiNpm()
    else:
        raise ValueError(f"Unknown package registry type: {registry_type}")
