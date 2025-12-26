"""
Module with various rules to detect different types of data sources
"""

import os
from ossiq.domain.ecosystem import ALL_MANAGERS, PackageManagerType
from ossiq.domain.common import (
    RepositoryProvider,
    UnsupportedProjectType,
    UnsupportedRepositoryProvider
)


def detect_package_manager(project_path: str) -> PackageManagerType:
    """
    Detects the package manager used in a project directory by probing for
    lockfiles first, then manifest files.
    """
    # First pass: check for lockfiles for a definitive match
    for manager in ALL_MANAGERS:
        if manager.lockfile:
            if os.path.exists(os.path.join(project_path, manager.lockfile.name)):
                return manager

    # Second pass: check for primary manifests if no lockfile was found
    for manager in ALL_MANAGERS:
        # pyproject.toml is ambiguous, skip it in this simple check
        if manager.primary_manifest.name == "pyproject.toml":
            continue
        if os.path.exists(os.path.join(project_path, manager.primary_manifest.name)):
            return manager

    # Special handling for ambiguous pyproject.toml
    if os.path.exists(os.path.join(project_path, "pyproject.toml")):
        # In a real scenario, we would parse this file to find the tool.
        # For now, we can't be sure. We can either default to one (e.g. UV)
        # or raise an error. Raising an error is safer.
        raise UnsupportedProjectType(
            "Detected 'pyproject.toml' but no lockfile. Cannot determine a specific package manager (uv, Poetry, PDM)."
        )

    raise UnsupportedProjectType(
        f"Could not determine project type in '{project_path}'. No supported file found."
    )


def detect_source_code_provider(repo_url: str) -> RepositoryProvider:
    """
    Identify Source Code Provider by URL.
    """
    if (repo_url.startswith("https://github.com/") or
            repo_url.startswith("git@github.com:")):
        return RepositoryProvider.PROVIDER_GITHUB

    raise UnsupportedRepositoryProvider(
        f"Unknown repository provider for the URL: {repo_url}")
