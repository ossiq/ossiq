"""
Implementation of Package Registry API client for NPM
"""

from collections.abc import Iterable

import requests
import semver
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

NPM_REGISTRY = "https://registry.npmjs.org"
NPM_REGISTRY_FRONT = "https://www.npmjs.com"

NPM_DEPENDENCIES_SECTIONS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
    # FIXME: consider pinned versions as well!
)


class PackageRegistryApiNpm(AbstractPackageRegistryApi):
    """
    Implementation of Package Registry API client for NPM
    """

    package_registry = ProjectPackagesRegistry.NPM
    settings: Settings

    @staticmethod
    def compare_versions(v1: str, v2: str) -> int:
        """
        Compare two versions following Semantic Versioning.
        """
        return semver.Version.parse(v1).compare(semver.Version.parse(v2))

    @staticmethod
    def _calculate_semver_diff_index(v1: semver.Version, v2: semver.Version) -> int:
        """
        Calculate the most significant difference between two semver versions.

        Compares version components in order of significance:
        1. Major version
        2. Minor version
        3. Patch version
        4. Prerelease
        5. Build metadata

        Args:
            v1: First parsed semver version
            v2: Second parsed semver version

        Returns:
            Diff index constant indicating the most significant difference level
        """
        if v1.major != v2.major:
            return VERSION_DIFF_MAJOR

        if v1.minor != v2.minor:
            return VERSION_DIFF_MINOR

        if v1.patch != v2.patch:
            return VERSION_DIFF_PATCH

        if v1.prerelease != v2.prerelease:
            return VERSION_DIFF_PRERELEASE

        if v1.build != v2.build:
            return VERSION_DIFF_BUILD

        return VERSION_NO_DIFF

    @staticmethod
    def difference_versions(v1_str: str | None, v2_str: str | None) -> VersionsDifference:
        """
        Calculate version difference using Semantic Versioning (semver) semantics.

        NPM packages follow strict semver, so we parse and compare major, minor,
        patch, prerelease, and build components.

        Args:
            v1_str: First version string (e.g., installed version)
            v2_str: Second version string (e.g., latest version)

        Returns:
            VersionsDifference with categorized diff index
        """
        # Handle None/empty versions
        if not v1_str or not v2_str:
            return create_version_difference_no_diff(v1_str, v2_str)

        # Optimize: check string equality before parsing
        if v1_str == v2_str:
            return VersionsDifference(
                v1_str, v2_str, VERSION_LATEST, diff_name=VERSION_INVERSED_DIFF_TYPES_MAP[VERSION_LATEST]
            )

        # Parse versions
        v1 = semver.Version.parse(v1_str)
        v2 = semver.Version.parse(v2_str)

        # Calculate the difference
        diff_index = PackageRegistryApiNpm._calculate_semver_diff_index(v1, v2)

        return VersionsDifference(str(v1), str(v2), diff_index, diff_name=VERSION_INVERSED_DIFF_TYPES_MAP[diff_index])

    def __init__(self, settings: Settings):
        self.settings = settings

    def __repr__(self):
        return "<PackageRegistryApiNpm instance>"

    def _make_request(self, path: str, headers: dict | None = None, timeout: int = 15) -> dict:
        """
        Make request and handle retries and errors handling.
        """
        r = requests.get(f"{NPM_REGISTRY}{path}", timeout=timeout, headers=headers)
        r.raise_for_status()
        return r.json()

    def package_info(self, package_name: str) -> Package:
        """
        Fetch npm info for a given package.
        FIXME: raise custom exception if not found
        """
        response = self._make_request(f"/{package_name}")
        distribution_tags = response.get("dist-tags", {"latest": None, "next": None})

        return Package(
            registry=ProjectPackagesRegistry.NPM,
            name=response["name"],
            latest_version=distribution_tags.get("latest", None),
            next_version=distribution_tags.get("next", None),
            repo_url=response.get("repository", {}).get("url", None),
            author=response.get("author"),
            homepage_url=response.get("homepage"),
            description=response.get("description"),
            package_url=f"{NPM_REGISTRY_FRONT}/package/{package_name}/",
        )

    def package_versions(self, package_name: str) -> Iterable[PackageVersion]:
        """
        Fetch npm versions for a given package.
        """
        response = self._make_request(f"/{package_name}")
        # FIXME: raise custom exception if not found
        versions = response.get("versions", [])
        timestamp_map = response.get("time", {})
        unpublished_response = timestamp_map.pop("unpublished", {})

        # Package version is either published or unpublished
        if unpublished_response:
            unpublished_date_iso = unpublished_response.get("time", None)
            for version in unpublished_response.get("versions", []):
                yield PackageVersion(
                    version=version,
                    license=None,
                    dependencies={},
                    package_url=f"{NPM_REGISTRY_FRONT}/package/{package_name}/v/{version}",
                    unpublished_date_iso=unpublished_date_iso,
                    is_published=False,
                )
        else:
            for version, details in versions.items():
                yield PackageVersion(
                    version=version,
                    published_date_iso=timestamp_map.get(version, None),
                    dependencies=details.get("dependencies", {}),
                    license=details.get("license", None),
                    runtime_requirements=details.get("engines", None),
                    dev_dependencies=details.get("devDependencies", {}),
                    description=details.get("description", None),
                    package_url=f"{NPM_REGISTRY_FRONT}/package/{package_name}/v/{version}",
                )
