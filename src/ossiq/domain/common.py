"""
Put all the important constants in one place to avoid
mutual dependencies.
"""

import os
from enum import Enum

# Source of versions data within target source code repository
VERSION_DATA_SOURCE_GITHUB_RELEASES = "GITHUB-RELEASES"
VERSION_DATA_SOURCE_GITHUB_TAGS = "GITHUB-TAGS"


class RepositoryProvider(str, Enum):
    PROVIDER_GITHUB = "GITHUB"


class ProjectPackagesRegistry(str, Enum):
    NPM = "NPM"
    PYPI = "PYPI"


class CveDatabase(str, Enum):
    OSV = "OSV"
    GHSA = "GHSA"
    NVD = "NVD"
    SNYK = "SNYK"
    OTHER = "OTHER"


class PresentationType(Enum):
    """
    What kind of presentation methods available. Default likely should be Console,
    potentailly could be HTML and JSON/YAML.
    """

    CONSOLE = "console"
    HTML = "html"


class Command(Enum):
    """
    List of available commands, used by presentation layer to map
    command with respective presentation layer.
    """

    OVERVIEW = "overview"


# Domain-specific Exceptions


class UnsupportedProjectType(Exception):
    pass


class UnsupportedPackageRegistry(Exception):
    pass


class UnsupportedRepositoryProvider(Exception):
    pass


class UnknownCommandException(Exception):
    pass


class UnknownPresentationType(Exception):
    pass


class NoPackageVersionsFound(Exception):
    pass


class PackageNotInstalled(Exception):
    pass


def identify_project_registry_kind(project_path: str) -> ProjectPackagesRegistry:
    """
    Identify Packages registry by typical file name
    """

    projects_kind_map = {
        "package.json": ProjectPackagesRegistry.NPM,
        "requirements.txt": ProjectPackagesRegistry.PYPI,
        "pyproject.toml": ProjectPackagesRegistry.PYPI,
    }

    for dependencies_filename, registry_kind in projects_kind_map.items():
        full_probe_path = os.path.join(project_path, dependencies_filename)
        if os.path.exists(full_probe_path):
            return registry_kind

    raise UnsupportedPackageRegistry(f"Unknown project kind at: {project_path}")


def identify_project_source_code_provider_kind(repo_url: str) -> RepositoryProvider:
    """
    Identify Packages registry by typical file name
    """
    if repo_url("https://github.com/"):
        return RepositoryProvider.PROVIDER_GITHUB

    raise UnsupportedRepositoryProvider(f"Unknown repository provider for the URL: {repo_url}")
