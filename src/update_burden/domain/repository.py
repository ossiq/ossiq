"""
Module to define abstract code Registryike github
"""

from .common import REPOSITORY_PROVIDER_GITHUB


class Repository:
    """Class for a Repository."""
    provider: str
    name: str
    owner: str
    description: str | None

    def __init__(self, provider: str, name: str, owner: str, description: str):

        assert provider in (
            REPOSITORY_PROVIDER_GITHUB), f"Invalid provider {provider}"

        self.provider = provider
        self.owner = owner
        self.name = name
        self.description = description

    def __repr__(self):
        return f"""{self.provider} Repository(
  name='{self.name}'
  owner='{self.owner}'
  url='{self.html_url}'
)"""

    @property
    def api_url(self):
        if self.provider == REPOSITORY_PROVIDER_GITHUB:
            return f"https://api.github.com/repos/{self.owner}/{self.repo}/releases"

        raise ValueError("Invalid provider")

    @property
    def html_url(self):
        if self.provider == REPOSITORY_PROVIDER_GITHUB:
            return f"https://github.com/{self.owner}/{self.name}"
