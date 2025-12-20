"""
Module to define abstract code Registryike github
"""


class Repository:
    """Class for a Repository."""

    provider: str
    name: str
    owner: str
    description: str | None

    html_url: str | None

    def __init__(self, provider: str, name: str, owner: str, description: str | None, html_url: str | None):
        self.provider = provider
        self.owner = owner
        self.name = name
        self.description = description
        self.html_url = html_url

    def __repr__(self):
        return f"""{self.provider} Repository(
  name='{self.name}'
  owner='{self.owner}'
  url='{self.html_url}'
)"""
