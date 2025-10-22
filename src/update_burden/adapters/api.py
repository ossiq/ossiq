"""
Factory to instantiate API clients
"""
from ..config import Settings
from update_burden.domain.common import RepositoryProviderType
from .api_github import GithubSourceCodeApiClient
from .api_interfaces import AbstractSourceCodeApiClient


class SourceCodeApiClientFactory:
    @staticmethod
    def get_client(registry_type: str, settings: Settings) -> AbstractSourceCodeApiClient:
        if registry_type == RepositoryProviderType.PROVIDER_GITHUB:
            return GithubSourceCodeApiClient(settings.github_token)
        else:
            raise ValueError(f"Unknown registry type: {registry_type}")
