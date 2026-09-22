"""
Implementation of Package Registry API client for PyPI
"""

from collections.abc import Iterable

import requests
from packaging.version import InvalidVersion
from packaging.version import Version as PackagingVersion

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.adapters.detectors import is_repository_root_url
from ossiq.adapters.package_managers.api_pypi import batch_fetch_requires_dist, parse_requires_dist
from ossiq.clients.batch import BatchClient
from ossiq.clients.client_pypi import PypiBatchStrategy
from ossiq.clients.common import get_user_agent
from ossiq.domain.common import ConstraintType, ProjectPackagesRegistry
from ossiq.domain.exceptions import UnableLoadPackage
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
        PackagingVersion(version_str)
        return True
    except InvalidVersion:
        return False


REPO_URL_KEYS: tuple[str, ...] = ("repository", "source", "source code", "sourcecode", "code")
"""project_urls keys that name the repository outright, lowercased, most explicit first. Checked
before any URL-shape guess so a project that says where its source lives is always believed."""


def get_repo_url(project_urls: dict | None) -> str | None:
    """Find the source repository among a PyPI project's declared URLs.

    PyPI has no required key for it, and the three exact-case keys this used to check missed the
    majority of real projects: `rich` and `coverage` file theirs under "Homepage", `pandas` uses a
    lowercase "repository", `semver` calls it "GitHub Homepage". Each miss cost that package every
    maintenance and activity signal, silently — a scan cannot fetch a repository it never found.

    Args:
        project_urls: The `info.project_urls` mapping from the PyPI JSON API.

    Returns:
        The repository URL, or None when no entry names or looks like one.
    """
    if not project_urls:
        return None

    normalized = {str(key).strip().lower(): value for key, value in project_urls.items() if value}

    for key in REPO_URL_KEYS:
        if key in normalized:
            return normalized[key]

    # No key named it, so fall back to shape: any entry pointing at a repository root. Sub-pages
    # (Issues, Releases, Changelog) share the host but carry a third path segment, so they cannot
    # be mistaken for the repository itself.
    for value in normalized.values():
        if is_repository_root_url(value):
            return value

    return None


def detect_pypi_install_execution(release_files: list[dict]) -> tuple[bool | None, str | None]:
    """Return (runs_code_at_install, reason) from a PyPI release's file list.

    A source distribution invokes the build backend during install; a wheel is unpack-only. Both
    present means the resolved artifact depends on interpreter/platform, so the signal is unknown."""

    packagetypes = {f.get("packagetype") for f in release_files}
    has_wheel = "bdist_wheel" in packagetypes
    has_sdist = "sdist" in packagetypes

    if has_sdist and not has_wheel:
        return True, "PyPI source distribution build"
    if has_wheel and not has_sdist:
        return False, None

    return None, None


class PackageRegistryApiPypi(AbstractPackageRegistryApi):
    """Package registry API client for PyPI."""

    package_registry = ProjectPackagesRegistry.PYPI
    settings: Settings

    _raw_cache: dict[str, dict]

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
        ver1 = PackagingVersion(v1)
        ver2 = PackagingVersion(v2)

        if ver1 < ver2:
            return -1
        if ver1 > ver2:
            return 1
        return 0

    @staticmethod
    def calculate_pep440_diff_index(v1: PackagingVersion, v2: PackagingVersion) -> int:
        """
        Calculate the most significant difference between two PEP 440 versions.

        Compares release, pre-release, then post/dev components in that order of
        significance — see the inline comments below for the exact precedence.

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
        v1 = PackagingVersion(v1_str)
        v2 = PackagingVersion(v2_str)

        # Calculate the difference
        diff_index = PackageRegistryApiPypi.calculate_pep440_diff_index(v1, v2)

        return VersionsDifference(str(v1), str(v2), diff_index, diff_name=VERSION_INVERSED_DIFF_TYPES_MAP[diff_index])

    def __init__(self, settings: Settings):
        self.settings = settings
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": get_user_agent()})
        self._raw_cache = {}
        self._version_requires_cache: dict[tuple[str, str], dict[str, str]] = {}
        self._strategy = PypiBatchStrategy(self.session)
        self._batch_client = BatchClient(self._strategy)

    def __repr__(self):
        return "<PackageRegistryApiPypi instance>"

    @staticmethod
    def all_releases_yanked(releases: dict) -> bool:
        """True when every published PyPI release is yanked - a package-wide "do not use"."""
        published = [files for files in releases.values() if files]
        return bool(published) and all(all(file.get("yanked") for file in files) for files in published)

    @staticmethod
    def latest_stable_version(info_version: str, releases: dict) -> str:
        """Return the newest installable stable version, falling back from `info_version` when
        it's a prerelease.

        Args:
            info_version: PyPI's `info.version` — the maintainer's most recent upload, which may
                itself be a prerelease.
            releases: The `releases` mapping from the same PyPI JSON payload.

        Returns:
            The newest non-prerelease, non-yanked version among `releases` (as the exact string
            key PyPI published it under — never a `packaging.Version`-normalized rewrite, since
            callers match this against raw release keys by string equality), or `info_version`
            unchanged if it's already stable, unparseable, or no such stable release exists.
        """
        try:
            if not PackagingVersion(info_version).is_prerelease:
                return info_version
        except InvalidVersion:
            return info_version

        stable: list[tuple[PackagingVersion, str]] = []
        for raw, release_files in (releases or {}).items():
            # Skip versions with no files (removed/traceless) and fully-yanked versions - pip
            # won't silently install either, so neither is a usable "latest".
            if not release_files or all(f.get("yanked") for f in release_files):
                continue
            try:
                parsed = PackagingVersion(raw)
            except InvalidVersion:
                continue
            if not parsed.is_prerelease:
                stable.append((parsed, raw))
        return max(stable)[1] if stable else info_version

    @staticmethod
    def map_raw_to_package(name: str, data: dict) -> Package:
        info = data["info"]
        return Package(
            registry=ProjectPackagesRegistry.PYPI,
            # NOTE: package_name could be uppercase like Jinja2
            name=name,
            # PyPI has no alias support, so canonical_name always equals name
            canonical_name=name,
            latest_version=PackageRegistryApiPypi.latest_stable_version(info["version"], data.get("releases") or {}),
            next_version=None,
            repo_url=get_repo_url(info.get("project_urls", {})),
            author=info.get("author"),
            homepage_url=info.get("home_page"),
            description=info.get("summary"),
            package_url=info.get("package_url"),
            classifiers=info.get("classifiers") or [],
            all_releases_yanked=PackageRegistryApiPypi.all_releases_yanked(data.get("releases") or {}),
            # license intentionally omitted — PyPI classifiers map is unreliable
            # (e.g. "BSD License" → BSD-2-Clause, wrong for BSD-3-Clause packages like Django).
            # ScanRecord falls back to prefetched_repository.license (GitHub) which is accurate.
            # maintainers_count omitted — PyPI only exposes author_email metadata,
            # not actual upload collaborators. npm exposes real accounts; PyPI does not.
        )

    def fetch_downloads_recent(self, package_name: str) -> int | None:
        """Fetch last-month download count from pypistats.org."""
        try:
            resp = self.session.get(
                f"https://pypistats.org/api/packages/{package_name}/recent",
                timeout=5,
            )
            if resp.ok:
                return resp.json().get("data", {}).get("last_month")
        except (requests.RequestException, ValueError):
            pass
        return None

    def packages_info_batch(self, names: list[str]) -> dict[str, Package]:
        """
        Fetch PyPI info for a list of packages in parallel, returning name -> Package.
        Already-cached packages are served from _raw_cache without a network request.
        """
        names_to_fetch = [n for n in names if n not in self._raw_cache]

        for chunk_data in self._batch_client.run_batch(names_to_fetch):
            self._raw_cache.update(chunk_data)

        for name in names:
            if name not in self._raw_cache:
                raise UnableLoadPackage(name)

        return {name: self.map_raw_to_package(name, self._raw_cache[name]) for name in names}

    def package_versions(self, package_name: str) -> Iterable[PackageVersion]:
        """
        Fetch PyPI versions for a given package, using `_raw_cache` (populated by
        `packages_info_batch`) and fetching if not cached.

        PyPI's main endpoint omits dependency info for older versions, and fetching it
        per-version is expensive — so only the latest version's dependencies are populated here.
        """
        if package_name not in self._raw_cache:
            self.packages_info_batch([package_name])

        data = self._raw_cache[package_name]
        info = data["info"]
        releases = data["releases"]

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
            runs_code_at_install, install_exec_reason = detect_pypi_install_execution(release_files)

            # requires_python is per-file but consistent across files for a given version.
            requires_python = next(
                (f.get("requires_python") for f in release_files if f.get("requires_python")),
                None,
            )

            # Only the latest version has requires_dist in the main response.
            dependencies = {}
            if version == info["version"]:
                # This is a list of strings, convert it to the dict format like npm's.
                dependencies = {dep: "" for dep in latest_version_dependencies}
                # Zero-cost cache warmup: populate _version_requires_cache from data we already have.
                key = (package_name, version)
                if key not in self._version_requires_cache:
                    self._version_requires_cache[key] = parse_requires_dist(latest_version_dependencies)

            # PyPI API gap: No equivalent for 'unpublished_date_iso'.
            yield PackageVersion(
                version=version,
                published_date_iso=published_date_iso,
                declared_dependencies=dependencies,
                license=info.get("license"),
                description=info.get("summary"),
                package_url=f"{PYPI_REGISTRY_FRONT}/project/{package_name}/{version}/",
                is_yanked=is_yanked,
                unpublished_date_iso=None,
                is_prerelease=PackagingVersion(version).is_prerelease,
                runtime_requirements={"python": requires_python} if requires_python else None,
                runs_code_at_install=runs_code_at_install,
                install_execution_reason=install_exec_reason,
            )

    def package_version_requires(self, package_name: str, version: str) -> dict[str, str]:
        """Return {normalized_dep_name: version_specifier} for a specific published version.

        Returns empty dict if the version is not found or has no runtime dependencies.
        """
        key = (package_name, version)
        if key not in self._version_requires_cache:
            raw = batch_fetch_requires_dist([key], self.session)
            self._version_requires_cache[key] = parse_requires_dist(raw.get(key, []))
        return self._version_requires_cache[key]

    @staticmethod
    def rewrite_specifier(
        specifier: str | None,
        new_version: str,
        constraint_type: ConstraintType | None = None,
    ) -> str | None:
        """Rewrite a PyPI version specifier for an updated package version.

        When the return value equals the input specifier, no manifest edit is needed — callers
        should skip pyproject.toml edits and pass the package to --upgrade-package on uv lock
        instead.

        Returns:
            DECLARED (>=x): unchanged — lockfile-only update.
            PINNED (==x.y.z): rewritten to ==new_version.
            NARROWED with ~=: preserves the N-part format using parts of new_version.
            NARROWED other (compound, ==x.*, !=, etc.): falls back to ==new_version.
            OVERRIDE / ADDITIVE: unchanged — managed by external tooling.
        """
        if constraint_type in (ConstraintType.DECLARED, ConstraintType.OVERRIDE, ConstraintType.ADDITIVE):
            return specifier

        if constraint_type == ConstraintType.PINNED:
            return f"=={new_version}"

        # NARROWED: try to preserve ~= operator
        if specifier and specifier.startswith("~="):
            old_parts = specifier[2:].strip().split(".")
            new_parts = new_version.split(".")
            result_parts = new_parts[: len(old_parts)]
            while len(result_parts) < len(old_parts):
                result_parts.append("0")
            return f"~={'.'.join(result_parts)}"

        # Other NARROWED (compound >=x,<y, ==x.*, !=x, <x, etc.) — fall back to exact pin
        return f"=={new_version}"

    def warmup_version_requires(self, pairs: list[tuple[str, str]]) -> None:
        """Batch-fetch requires_dist for (package, version) pairs not yet in the cache.

        Uses the existing parallel batch client — replaces N sequential HTTP calls
        (one per simulate_single invocation) with a single parallel prefetch.
        """
        missing = [p for p in pairs if p not in self._version_requires_cache]
        if not missing:
            return
        raw = batch_fetch_requires_dist(missing, self.session)
        for key in missing:
            self._version_requires_cache[key] = parse_requires_dist(raw.get(key, []))
