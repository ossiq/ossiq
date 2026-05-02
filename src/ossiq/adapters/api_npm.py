"""
Implementation of Package Registry API client for NPM
"""

import functools
import logging

import requests
import semver
from rich.console import Console

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.clients.batch import BatchClient
from ossiq.clients.client_npm import NpmBatchStrategy
from ossiq.clients.common import get_user_agent
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.exceptions import UnableLoadPackage, UnknownPackageVersion
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

logger = logging.getLogger(__name__)
console = Console()

NPM_REGISTRY_FRONT = "https://www.npmjs.com"


@functools.lru_cache(maxsize=4096)
def parse_semver(v: str) -> semver.Version:
    return semver.Version.parse(v)


@functools.lru_cache(maxsize=4096)
def is_npm_prerelease(version_str: str) -> bool:
    try:
        return semver.Version.parse(version_str).prerelease is not None
    except ValueError:
        return False


def normalize_npm_license(value: str | dict[str, object] | None) -> str | None:
    # Older npm packages use {"type": "MIT", "url": "..."} instead of a plain string.
    # See https://docs.npmjs.com/cli/v8/configuring-npm/package-json#license
    if isinstance(value, dict):
        t = value.get("type")
        return t if isinstance(t, str) else None
    return value or None


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
    session: requests.Session

    _raw_cache: dict[str, dict]

    @staticmethod
    def compare_versions(v1: str, v2: str) -> int:
        """
        Compare two versions following Semantic Versioning.
        """
        try:
            return parse_semver(v1).compare(parse_semver(v2))
        except ValueError as e:
            raise UnknownPackageVersion(str(e))  # noqa: B904

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
        try:
            v1 = parse_semver(v1_str)
            v2 = parse_semver(v2_str)
        except ValueError:
            return VersionsDifference(
                v1_str,
                v2_str,
                VERSION_NO_DIFF,
                diff_name=VERSION_INVERSED_DIFF_TYPES_MAP[VERSION_NO_DIFF],
            )

        # Calculate the difference
        diff_index = PackageRegistryApiNpm._calculate_semver_diff_index(v1, v2)

        return VersionsDifference(str(v1), str(v2), diff_index, diff_name=VERSION_INVERSED_DIFF_TYPES_MAP[diff_index])

    def __init__(self, settings: Settings):
        self.settings = settings
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": get_user_agent()})
        self._raw_cache = {}
        self._versions_list_cache: dict[str, list[PackageVersion]] = {}
        self._strategy = NpmBatchStrategy(self.session)
        self._batch_client = BatchClient(self._strategy)

    def __repr__(self):
        return "<PackageRegistryApiNpm instance>"

    @staticmethod
    def _map_raw_to_package(name: str, data: dict) -> Package:
        distribution_tags = data.get("dist-tags", {"latest": None, "next": None})
        latest_version = distribution_tags.get("latest", None)
        latest_details = data.get("versions", {}).get(latest_version or "", {})
        latest_version_license = normalize_npm_license(latest_details.get("license"))
        return Package(
            registry=ProjectPackagesRegistry.NPM,
            name=data["name"],
            latest_version=latest_version,
            next_version=distribution_tags.get("next", None),
            repo_url=data.get("repository", {}).get("url", None),
            author=data.get("author"),
            homepage_url=data.get("homepage"),
            description=data.get("description"),
            package_url=f"{NPM_REGISTRY_FRONT}/package/{name}/",
            license=latest_version_license,
            is_deprecated=bool(latest_details.get("deprecated")),
            is_unpublished="unpublished" in data.get("time", {}),
        )

    def packages_info_batch(self, names: list[str]) -> dict[str, Package]:
        """
        Fetch NPM info for a list of packages in parallel, returning name → Package.
        Already-cached packages are served from _raw_cache without a network request.
        """
        names_to_fetch = [n for n in names if n not in self._raw_cache]

        for chunk_data in self._batch_client.run_batch(names_to_fetch):
            self._raw_cache.update(chunk_data)

        for name in names:
            if name not in self._raw_cache:
                raise UnableLoadPackage(name)

        return {name: self._map_raw_to_package(name, self._raw_cache[name]) for name in names}

    _META_KEYS = frozenset({"created", "modified"})

    def _build_package_versions(self, package_name: str) -> list[PackageVersion]:
        data = self._raw_cache[package_name]

        # FIXME: raise custom exception if not found
        versions = data.get("versions", {})
        timestamp_map = dict(data.get("time", {}))
        unpublished_response = timestamp_map.pop("unpublished", {})

        # Entire package unpublished path
        if unpublished_response:
            unpublished_date_iso = unpublished_response.get("time", None)
            return [
                PackageVersion(
                    version=version,
                    license=None,
                    declared_dependencies={},
                    package_url=f"{NPM_REGISTRY_FRONT}/package/{package_name}/v/{version}",
                    unpublished_date_iso=unpublished_date_iso,
                    is_unpublished=True,
                )
                for version in unpublished_response.get("versions", [])
            ]

        # Published package — phase 1: existing versions
        result = [
            PackageVersion(
                version=version,
                published_date_iso=timestamp_map.get(version, None),
                declared_dependencies=details.get("dependencies", {}),
                license=normalize_npm_license(details.get("license")),
                runtime_requirements=details.get("engines", None),
                declared_dev_dependencies=details.get("devDependencies", {}),
                description=details.get("description", None),
                package_url=f"{NPM_REGISTRY_FRONT}/package/{package_name}/v/{version}",
                is_prerelease=is_npm_prerelease(version),
                is_deprecated=bool(details.get("deprecated")),
            )
            for version, details in versions.items()
        ]

        # Phase 2: individually deleted versions (in time map but absent from versions)
        published_set = set(versions)
        for ver, timestamp in timestamp_map.items():
            if ver in self._META_KEYS or ver in published_set:
                continue
            try:
                semver.Version.parse(ver)
            except ValueError:
                continue
            result.append(
                PackageVersion(
                    version=ver,
                    license=None,
                    declared_dependencies={},
                    package_url=f"{NPM_REGISTRY_FRONT}/package/{package_name}/v/{ver}",
                    published_date_iso=timestamp,
                    is_unpublished=True,
                )
            )

        return result

    def package_versions(self, package_name: str) -> list[PackageVersion]:
        """
        Fetch npm versions for a given package.
        Uses _raw_cache populated by package_infos_batch; fetches if not cached.
        Result is cached to avoid rebuilding PackageVersion objects on repeated calls.
        """
        if package_name not in self._raw_cache:
            self.packages_info_batch([package_name])

        if package_name not in self._versions_list_cache:
            self._versions_list_cache[package_name] = self._build_package_versions(package_name)

        return self._versions_list_cache[package_name]
