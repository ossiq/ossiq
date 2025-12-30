"""
Implementation of Package Registry API client for PyPI
"""

from collections.abc import Iterable

import requests
from packaging.version import InvalidVersion, Version
from rich.console import Console

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.package import Package
from ossiq.domain.version import (
    VERSION_DIFF_BUILD,
    VERSION_DIFF_MAJOR,
    VERSION_DIFF_MINOR,
    VERSION_DIFF_PATCH,
    VERSION_DIFF_PRERELEASE,
    VERSION_INVERSED_DIFF_TYPES_MAP,
    VERSION_LATEST,
    VERSION_NO_DIFF,
    PackageVersion,
    VersionsDifference,
    create_version_difference_no_diff,
)
from ossiq.settings import Settings

console = Console()

PYPI_REGISTRY = "https://pypi.org/pypi"
PYPI_REGISTRY_FRONT = "https://pypi.org"


def is_valid_pep440_version(version_str: str) -> bool:
    """
    Check if a version string is valid PEP 440.

    Returns False for legacy versions like "0.1dev-r1716" that don't
    conform to modern PEP 440 specification.

    Args:
        version_str: Version string to validate

    Returns:
        True if valid PEP 440, False otherwise
    """
    try:
        Version(version_str)
        return True
    except InvalidVersion:
        return False


def get_repo_url(project_urls: dict) -> str | None:
    """Helper to find repo url from project_urls."""
    if not project_urls:
        return None
    for key in ("Repository", "Source", "Source Code"):
        if key in project_urls:
            return project_urls[key]
    return None


class PackageRegistryApiPypi(AbstractPackageRegistryApi):
    """
    Implementation of Package Registry API client for PyPI
    """

    package_registry = ProjectPackagesRegistry.PYPI
    settings: Settings

    @staticmethod
    def compare_versions(v1: str, v2: str) -> int:
        """
        Compare two versions following PEP 440.

        Invalid versions should be filtered out by is_valid_pep440_version() before
        reaching this method. If invalid versions slip through other paths, this will
        raise InvalidVersion to be caught at the view layer.

        Args:
            v1: First version string
            v2: Second version string

        Returns:
            -1 if v1 < v2
             0 if v1 == v2
             1 if v1 > v2

        Raises:
            InvalidVersion: If either version string is not valid PEP 440
        """
        ver1 = Version(v1)
        ver2 = Version(v2)

        if ver1 < ver2:
            return -1
        if ver1 > ver2:
            return 1
        return 0

    @staticmethod
    def _calculate_pep440_diff_index(v1: Version, v2: Version) -> int:
        """
        Calculate the most significant difference between two PEP 440 versions.

        Compares version components in order of significance:
        1. Release tuple (major, minor, patch, ...)
        2. Pre-release (alpha, beta, rc)
        3. Post-release and dev versions

        Args:
            v1: First parsed PEP 440 version
            v2: Second parsed PEP 440 version

        Returns:
            Diff index constant indicating the most significant difference level
        """
        # Guard: ensure both versions have release tuples
        if not (v1.release and v2.release):
            return VERSION_NO_DIFF

        # Compare release components (major.minor.patch...)
        r1, r2 = v1.release, v2.release

        # Major version differs
        if r1[0] != r2[0]:
            return VERSION_DIFF_MAJOR

        # Minor version differs (if both have it)
        if len(r1) > 1 and len(r2) > 1 and r1[1] != r2[1]:
            return VERSION_DIFF_MINOR

        # Patch version differs (if both have it)
        if len(r1) > 2 and len(r2) > 2 and r1[2] != r2[2]:
            return VERSION_DIFF_PATCH

        # Any other release segment differs
        if r1 != r2:
            return VERSION_DIFF_PATCH

        # Pre-release differs (alpha, beta, rc)
        if v1.pre != v2.pre:
            return VERSION_DIFF_PRERELEASE

        # Post-release or dev differs
        if v1.post != v2.post or v1.dev != v2.dev:
            return VERSION_DIFF_BUILD

        # Versions are identical
        return VERSION_NO_DIFF

    @staticmethod
    def difference_versions(v1_str: str | None, v2_str: str | None) -> VersionsDifference:
        """
        Calculate version difference using PEP 440 (Python packaging) semantics.

        PyPI packages follow PEP 440, which supports: epoch, release segments,
        pre-release, post-release, dev, and local versions.

        Invalid versions should be filtered out by is_valid_pep440_version() before
        reaching this method. If invalid versions slip through other paths, this will
        raise InvalidVersion to be caught at the view layer.

        Args:
            v1_str: First version string (e.g., installed version)
            v2_str: Second version string (e.g., latest version)

        Returns:
            VersionsDifference with categorized diff index

        Raises:
            InvalidVersion: If either version string is not valid PEP 440
        """
        # Handle None/empty versions
        if not v1_str or not v2_str:
            return create_version_difference_no_diff(v1_str, v2_str)

        # Optimize: check string equality before parsing
        if v1_str == v2_str:
            return VersionsDifference(
                v1_str, v2_str, VERSION_LATEST, diff_name=VERSION_INVERSED_DIFF_TYPES_MAP[VERSION_LATEST]
            )

        # Parse versions (may raise InvalidVersion for invalid strings)
        v1 = Version(v1_str)
        v2 = Version(v2_str)

        # Calculate the difference
        diff_index = PackageRegistryApiPypi._calculate_pep440_diff_index(v1, v2)

        return VersionsDifference(str(v1), str(v2), diff_index, diff_name=VERSION_INVERSED_DIFF_TYPES_MAP[diff_index])

    def __init__(self, settings: Settings):
        self.settings = settings

    def __repr__(self):
        return "<PackageRegistryApiPypi instance>"

    def _make_request(self, path: str, headers: dict | None = None, timeout: int = 15) -> dict:
        r = requests.get(f"{PYPI_REGISTRY}{path}", timeout=timeout, headers=headers)
        r.raise_for_status()
        return r.json()

    def package_info(self, package_name: str) -> Package:
        """
        Fetch PyPI info for a given package.
        """
        response = self._make_request(f"/{package_name}/json")
        info = response["info"]

        # PyPI API gap: No direct equivalent of NPM's 'dist-tags' like 'next'.
        # 'latest' is just the highest non-prerelease version.
        return Package(
            registry=ProjectPackagesRegistry.PYPI,
            # NOTE: package_name could be uppercase like Jinja2
            name=package_name,
            latest_version=info["version"],
            next_version=None,
            repo_url=get_repo_url(info.get("project_urls", {})),
            author=info.get("author"),
            homepage_url=info.get("home_page"),
            description=info.get("summary"),
            package_url=info.get("package_url"),
        )

    def package_versions(self, package_name: str) -> Iterable[PackageVersion]:
        """
        Fetch PyPI versions for a given package.

        PyPI API gap: The main endpoint does not provide dependency information
        for older versions. A separate request per version is needed to get
        `requires_dist` for each, making it inefficient. This implementation
        only fetches dependencies for the latest version.
        """
        response = self._make_request(f"/{package_name}/json")
        info = response["info"]
        releases = response["releases"]

        latest_version_dependencies = info.get("requires_dist") or []

        for version, release_files in releases.items():
            if not release_files:
                # No files for this version, maybe a yanked/removed version with no trace.
                continue

            # WARNING: Ignoring invalid/legacy versions (pre-PEP 440)
            if not is_valid_pep440_version(version):
                continue

            # Take the upload time of the first file as the published date for the version.
            published_date_iso = release_files[0]["upload_time_iso_8601"]

            # A version is considered yanked if all its files are yanked.
            is_yanked = all(f.get("yanked") for f in release_files)

            # Only the latest version has requires_dist in the main response.
            dependencies = {}
            if version == info["version"]:
                # This is a list of strings, convert it to the dict format like npm's.
                dependencies = {dep: "" for dep in latest_version_dependencies}

            # PyPI API gap: No equivalent for 'unpublished_date_iso'.
            yield PackageVersion(
                version=version,
                published_date_iso=published_date_iso,
                dependencies=dependencies,
                license=info.get("license"),
                description=info.get("summary"),
                package_url=f"{PYPI_REGISTRY_FRONT}/project/{package_name}/{version}/",
                is_published=not is_yanked,
                unpublished_date_iso=None,
            )
