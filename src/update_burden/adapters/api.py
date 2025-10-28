"""
Factory to instantiate API clients
"""
from update_burden.adapters.api_npm import PackageRegistryApiNpm
from ..config import Settings
from update_burden.domain.common import ProjectPackagesRegistryKind, RepositoryProviderType
from .api_github import SourceCodeProviderApiGithub
from .api_interfaces import AbstractSourceCodeProviderApi


class SourceCodeProviderApiFactory:
    @staticmethod
    def get_provider(provider_type: str, settings: Settings) -> AbstractSourceCodeProviderApi:
        if provider_type == RepositoryProviderType.PROVIDER_GITHUB:
            return SourceCodeProviderApiGithub(settings.github_token)
        else:
            raise ValueError(
                f"Unknown source code provider type: {provider_type}")


class PackageRegistryApiFactory:
    @staticmethod
    def get_registry(registry_type: str) -> AbstractSourceCodeProviderApi:
        if registry_type == ProjectPackagesRegistryKind.NPM:
            return PackageRegistryApiNpm()
        else:
            raise ValueError(f"Unknown package registry type: {registry_type}")
