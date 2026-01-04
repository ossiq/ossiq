"""
Put all the important constants in one place to avoid
mutual dependencies.
"""

from enum import Enum

# Source of versions data within target source code repository
VERSION_DATA_SOURCE_GITHUB_RELEASES = "GITHUB-RELEASES"
VERSION_DATA_SOURCE_GITHUB_TAGS = "GITHUB-TAGS"


class RepositoryProvider(str, Enum):
    PROVIDER_GITHUB = "GITHUB"
    PROVIDER_UNKNOWN = "UNKNOWN"


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

    SCAN = "scan"


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
