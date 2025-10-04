"""
Module to define abstract code Registryike github
"""

PROVIDER_GITHUB = "GITHUB"


class Repository:
    """Class for a Repository."""
    provider: str
    name: str
    owner: str
    description: str

    def __init__(self, provider: str, name: str, owner: str, description: str):

        assert provider in (PROVIDER_GITHUB), "Invalid provider"

        self.provider = provider
        self.owner = owner
        self.name = name
        self.description = description

    def __repr__(self):
        return f"""{self.provider} Repository(
  name='{self.name}'
  owner='{self.owner}'
  url='{self.repo_url}'
)"""

    @property
    def api_url(self):
        if self.registry == PROVIDER_GITHUB:
            return f"https://api.github.com/repos/{self.owner}/{self.repo}/releases"

        raise ValueError("Invalid provider")

    @property
    def repo_url(self):
        if self.registry == PROVIDER_GITHUB:
            return f"https://github.com/{self.owner}/{self.name}"
