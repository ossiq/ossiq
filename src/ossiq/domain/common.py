"""
Put all the important constants in one place to avoid
mutual dependencies.
"""

import importlib.metadata
import re
from enum import Enum, StrEnum
from urllib.parse import quote

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
    PACKAGE = "package"


class ExportUnknownSchemaVersion(StrEnum):
    """Supported export schema versions."""

    UNKNOWN = "UNKNOWN"


class ExportJsonSchemaVersion(StrEnum):
    """Supported export schema versions."""

    V1_0 = "1.0"
    V1_1 = "1.1"


class ExportCsvSchemaVersion(StrEnum):
    """Supported export schema versions."""

    V1_0 = "1.0"
    V1_1 = "1.1"


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


_PURL_TYPE: dict[str, str] = {
    "NPM": "npm",
    "PYPI": "pypi",
}


def build_purl(registry: "ProjectPackagesRegistry", name: str, version: str) -> str:
    """
    Build a Package URL (PURL) string per the PURL specification (ECMA-386).

    Examples:
        build_purl(ProjectPackagesRegistry.PYPI, "requests", "2.25.1")
        -> "pkg:pypi/requests@2.25.1"

        build_purl(ProjectPackagesRegistry.NPM, "@babel/core", "7.0.0")
        -> "pkg:npm/%40babel%2Fcore@7.0.0"

    Args:
        registry: The package registry enum value.
        name: The canonical package name (may include npm scope like "@scope/pkg").
        version: The resolved package version string.

    Returns:
        A PURL string in the form "pkg:{type}/{encoded_name}@{version}".
    """
    purl_type = _PURL_TYPE[registry.value]
    # Per PURL spec the name component must be percent-encoded.
    # quote() with safe="" encodes "@" and "/" which appear in npm scoped packages.
    encoded_name = quote(name, safe="")
    return f"pkg:{purl_type}/{encoded_name}@{version}"


def parse_spdx_expression(expr: str | None) -> list[str] | None:
    """
    Parse an SPDX license expression into individual license identifiers.

    Splits on AND/OR boolean operators. Preserves WITH clauses (license exceptions)
    as a single token. Filters out NOASSERTION tokens.

    Examples:
        parse_spdx_expression("Apache-2.0")
        -> ["Apache-2.0"]

        parse_spdx_expression("Apache-2.0 AND BSD-2-Clause")
        -> ["Apache-2.0", "BSD-2-Clause"]

        parse_spdx_expression("MIT OR Apache-2.0")
        -> ["MIT", "Apache-2.0"]

        parse_spdx_expression("GPL-2.0-only WITH Classpath-exception-2.0")
        -> ["GPL-2.0-only WITH Classpath-exception-2.0"]

        parse_spdx_expression("Apache-2.0 AND NOASSERTION")
        -> ["Apache-2.0"]
    """
    if not expr:
        return None

    tokens = re.split(r"\s+(?:AND|OR)\s+", expr)
    licenses = [token.strip().strip("()") for token in tokens]
    licenses = [lic for lic in licenses if lic and lic != "NOASSERTION"]

    return licenses if licenses else None


def get_version():
    """
    Get OSS IQ version
    """
    try:
        return importlib.metadata.version("ossiq")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"
