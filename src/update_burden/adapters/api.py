"""
Factory to instantiate API clients
"""
from ..config import Settings
from ..domain.common import REPOSITORY_PROVIDER_GITHUB
from .api_github import GithubSourceCodeApiClient
from .api_interfaces import AbstractSourceCodeApiClient


class SourceCodeApiClientFactory:
    @staticmethod
    def get_client(registry_type: str, settings: Settings) -> AbstractSourceCodeApiClient:
        if registry_type == REPOSITORY_PROVIDER_GITHUB:
            return GithubSourceCodeApiClient(settings)
        else:
            raise ValueError(f"Unknown registry type: {registry_type}")
