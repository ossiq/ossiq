"""
Module to define abstract Package
"""
import os

REGISTRY_NPM, REGISTRY_PYPI = "NPM", "PYPI"


class Package:
    """Class for a package."""
    registry: str
    name: str
    version: str
    next_version: str
    author: str
    url: str
    repo: str
    description: str
    author: str

    def __init__(self, registry: str, name: str, version: str, next_version: str, repo: str,
                 author: str = None, url: str = None, description: str = None):

        assert registry in (REGISTRY_NPM, REGISTRY_PYPI), "Invalid registry"

        self.registry = registry
        self.name = name
        self.version = version
        self.next_version = next_version
        self.repo = repo
        self.author = author
        self.url = url
        self.description = description

    def __repr__(self):
        return f"""{self.registry} Package(
  name='{self.name}'
  version='{self.version}'
  author='{self.author}'
  url='{self.package_url}'
)"""

    @property
    def package_url(self):
        if self.registry == REGISTRY_NPM:
            return f"https://www.npmjs.com/package/{self.name}/{self.version}"

        if self.registry == REGISTRY_PYPI:
            return f"https://pypi.org/project/{self.name}/{self.version}"

        raise ValueError("Invalid registry")


def id_registry_type(project_file: str):
    """
    Identify Packages registry by typical file name
    """
    name = os.path.basename(project_file)

    if name == "packages.json":
        return REGISTRY_NPM

    if name == "requirements.txt":
        return REGISTRY_PYPI

    if name == "pyproject.toml":
        return REGISTRY_PYPI

    raise ValueError(f"Unknown project file: {project_file}")
