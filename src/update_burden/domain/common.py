"""
Put all the important constants in one place to avoid
mutual dependencies.
"""

from enum import Enum

# Source of versions data within target source code repository
VERSION_DATA_SOURCE_GITHUB_RELEASES = "GITHUB-RELEASES"
VERSION_DATA_SOURCE_GITHUB_TAGS = "GITHUB-TAGS"


class RepositoryProviderType(Enum):
    PROVIDER_GITHUB = "GITHUB"


class PackageRegistryType(Enum):
    REGISTRY_NPM = "NPM"
    REGISTRY_PYPI = "PYPI"


# Domain-specific Exceptions

class UnsupportedProjectType(Exception):
    pass


class UnsupportedPackageRegistry(Exception):
    pass
