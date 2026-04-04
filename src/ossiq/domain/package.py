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
    # Real registry name when this package was installed under an npm alias.
    # None when name already is the canonical registry name.
    canonical_name: str | None
    latest_version: str | None
    next_version: str | None
    repo_url: str | None
    homepage_url: str | None
    description: str | None
    author: str | None
    package_url: str | None
    license: str | None

    _repository: Repository | None
    _versions: list[Version] | None

    def __init__(
        self,
        registry: ProjectPackagesRegistry,
        name: str,
        latest_version: str | None,
        next_version: str | None,
        # Sometimes, there's no link to source code repository
        repo_url: str | None,
        author: str | None = None,
        homepage_url: str | None = None,
        description: str | None = None,
        package_url: str | None = None,
        canonical_name: str | None = None,
        license: str | None = None,
    ):
        self.registry = registry
        self.name = name
        self.canonical_name = canonical_name
        self.latest_version = latest_version
        self.next_version = next_version
        self.repo_url = repo_url
        self.author = author
        self.homepage_url = homepage_url
        self.description = description
        self.package_url = package_url
        self.license = license

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
