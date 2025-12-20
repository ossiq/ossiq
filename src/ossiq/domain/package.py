"""
Module to define abstract Package
"""

from ossiq.domain.common import ProjectPackagesRegistry

from .repository import Repository
from .version import Version


class Package:
    """Class for a package."""

    registry: ProjectPackagesRegistry
    name: str
    latest_version: str | None
    next_version: str
    repo_url: str
    homepage_url: str | None
    description: str | None
    author: str | None
    package_url: str | None

    _repository: Repository | None
    _versions: list[Version] | None

    def __init__(
        self,
        registry: ProjectPackagesRegistry,
        name: str,
        latest_version: str | None,
        next_version: str,
        repo_url: str,
        author: str | None = None,
        homepage_url: str | None = None,
        description: str | None = None,
        package_url: str | None = None,
    ):
        self.registry = registry
        self.name = name
        self.latest_version = latest_version
        self.next_version = next_version
        self.repo_url = repo_url
        self.author = author
        self.homepage_url = homepage_url
        self.description = description
        self.package_url = package_url

        self._repository = None
        self._versions = None

    def __repr__(self):
        return f"""{self.registry} Package(
  name='{self.name}'
  version='{self.latest_version}'
  author='{self.author}'
  url='{self.package_url}'
)"""

    @property
    def versions(self):
        if self._versions is None:
            raise ValueError("Versions not set yet")
        return self._versions

    @versions.setter
    def versions(self, versions: list[Version]):
        self._versions = versions

    @property
    def repository(self):
        return self._repository

    @repository.setter
    def repository(self, repo: Repository):
        self._repository = repo
