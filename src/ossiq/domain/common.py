"""
Put all the important constants in one place to avoid
mutual dependencies.
"""

from enum import Enum, StrEnum

# Source of versions data within target source code repository
VERSION_DATA_SOURCE_GITHUB_RELEASES = "GITHUB-RELEASES"
VERSION_DATA_SOURCE_GITHUB_TAGS = "GITHUB-TAGS"


class RepositoryProvider(StrEnum):
    PROVIDER_GITHUB = "GITHUB"
    PROVIDER_UNKNOWN = "UNKNOWN"


class ProjectPackagesRegistry(StrEnum):
    NPM = "NPM"
    PYPI = "PYPI"


class CveDatabase(StrEnum):
    OSV = "OSV"
    GHSA = "GHSA"
    NVD = "NVD"
    SNYK = "SNYK"
    OTHER = "OTHER"


class UserInterfaceType(Enum):
    """
    What kind of presentation methods available. Default likely should be Console,
    potentailly could be HTML and JSON/YAML.
    """

    CONSOLE = "console"
    HTML = "html"
    JSON = "json"
    CSV = "csv"


class Command(Enum):
    """
    List of available commands, used by presentation layer to map
    command with respective presentation layer.
    """

    SCAN = "scan"
    EXPORT = "export"


class ExportUnknownSchemaVersion(StrEnum):
    """Supported export schema versions."""

    UNKNOWN = "UNKNOWN"


class ExportJsonSchemaVersion(StrEnum):
    """Supported export schema versions."""

    V1_0 = "1.0"


class ExportCsvSchemaVersion(StrEnum):
    """Supported export schema versions."""

    V1_0 = "1.0"


# Domain-specific Exceptions


class UnsupportedProjectType(Exception):
    pass


class UnsupportedPackageRegistry(Exception):
    pass


class UnsupportedRepositoryProvider(Exception):
    pass


class UnknownCommandException(Exception):
    pass


class UnknownUserInterfaceType(Exception):
    pass


class NoPackageVersionsFound(Exception):
    pass


class PackageNotInstalled(Exception):
    pass
