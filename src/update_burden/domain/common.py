"""
Put all the important constants in one place to avoid
mutual dependencies.
"""

# Packagve Registries supported
REGISTRY_NPM, REGISTRY_PYPI = "NPM", "PYPI"
PACKAGE_REGISTRIES = (
    REGISTRY_NPM,
    REGISTRY_PYPI
)

# Source code repository providers, could be github, bitbucket etc.
REPOSITORY_PROVIDER_GITHUB = "GITHUB"
REPOSITORY_PROVIDERS = (REPOSITORY_PROVIDER_GITHUB,)

# Source of versions data within target source code repository
VERSION_DATA_SOURCE_GITHUB_RELEASES = "GITHUB-RELEASES"
VERSION_DATA_SOURCE_GITHUB_TAGS = "GITHUB-TAGS"

# Project info types, could be pyproject.toml, packages.json for NPM etc.
PROJECT_TYPE_NPM, PROJECT_TYPE_PYPI = "NPM", "PYPI"
