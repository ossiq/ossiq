"""
Put all the important constants in one place to avoid
mutual dependencies.
"""
import os
from enum import Enum

# Source of versions data within target source code repository
VERSION_DATA_SOURCE_GITHUB_RELEASES = "GITHUB-RELEASES"
VERSION_DATA_SOURCE_GITHUB_TAGS = "GITHUB-TAGS"


class RepositoryProviderType(Enum):
    PROVIDER_GITHUB = "GITHUB"


class ProjectPackagesRegistryKind(Enum):
    NPM = "NPM"
    PYPI = "PYPI"


class PresentationType(Enum):
    """
    What kind of presentation methods available. Default likely should be Console,
    potentailly could be HTML and JSON/YAML.
    """
    CONSOLE = "console"


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


class UnknownCommandException(Exception):
    pass


class UnknownPresentationType(Exception):
    pass


def identify_project_registry_kind(project_path: str) -> ProjectPackagesRegistryKind:
    """
    Identify Packages registry by typical file name
    """

    projects_kind_map = {
        "package.json": ProjectPackagesRegistryKind.NPM,
        "requirements.txt": ProjectPackagesRegistryKind.PYPI,
        "pyproject.toml": ProjectPackagesRegistryKind.PYPI
    }

    for dependencies_filename, registry_kind in projects_kind_map.items():
        full_probe_path = os.path.join(project_path, dependencies_filename)
        if os.path.exists(full_probe_path):
            return registry_kind

    raise ValueError(f"Unknown project kind at: {project_path}")
