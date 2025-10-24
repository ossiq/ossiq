"""
Factory to instantiate API clients
"""
from update_burden.adapters.api_npm import NpmRegistryApiClient
from ..config import Settings
from update_burden.domain.common import PackageRegistryType, RepositoryProviderType
from .api_github import GithubSourceCodeApiClient
from .api_interfaces import AbstractSourceCodeApiClient


class SourceCodeApiClientFactory:
    @staticmethod
    def get_client(provider_type: str, settings: Settings) -> AbstractSourceCodeApiClient:
        if provider_type == RepositoryProviderType.PROVIDER_GITHUB:
            return GithubSourceCodeApiClient(settings.github_token)
        else:
            raise ValueError(
                f"Unknown source code provider type: {provider_type}")


class PackageRegistryApiClientFactory:
    @staticmethod
    def get_client(registry_type: str) -> AbstractSourceCodeApiClient:
        if registry_type == PackageRegistryType.REGISTRY_NPM:
            return NpmRegistryApiClient()
        else:
            raise ValueError(f"Unknown package registry type: {registry_type}")
