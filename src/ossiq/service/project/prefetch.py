"""
Bulk pre-fetch helpers: package info, repositories, versions-since-installed,
and classification of dependencies that must be excluded from the scan.
"""

from collections.abc import Iterable
from dataclasses import replace
from datetime import datetime
from itertools import chain
from urllib.parse import urlparse

from packaging.version import InvalidVersion

from ossiq.adapters.api_epss import EpssApiFirstOrg
from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.adapters.detectors import is_git_hosted_source
from ossiq.domain.common import RepositoryProvider
from ossiq.domain.cve import CVE
from ossiq.domain.exceptions import UnknownPackageVersion
from ossiq.domain.package import Package
from ossiq.domain.project import Dependency
from ossiq.domain.repository import Repository
from ossiq.messages import IGNORE_REASON_IGNORE_FLAG, IGNORE_REASON_NON_REGISTRY
from ossiq.service.common import package_versions
from ossiq.service.project.models import DependencyDescriptor, IgnoredDependency
from ossiq.sources.core import AbstractProjectSources
from ossiq.timeutil import age_days_from_iso


def get_package_versions_since(
    packages_registry: AbstractPackageRegistryApi,
    package_name: str,
    installed_version: str,
    *,
    allow_prerelease: bool = False,
    allow_prerelease_packages: tuple[str, ...] = (),
) -> list[package_versions.PackageVersion]:
    """
    Calculate Package versions lag: delta between
    installed package and the latest one.
    """
    try:
        versions = [
            v
            for v in packages_registry.package_versions(package_name)
            if packages_registry.compare_versions(v.version, installed_version) >= 0
        ]
        if not allow_prerelease and package_name not in allow_prerelease_packages:
            # Always retain the installed version so installed_release is never None,
            # even when the installed version itself is a prerelease.
            versions = [v for v in versions if not v.is_prerelease or v.version == installed_version]
        return versions
    except UnknownPackageVersion:
        return []


def update_latest_versions_for_prerelease(
    packages_registry: AbstractPackageRegistryApi,
    packages_info: dict[str, Package],
    *,
    allow_prerelease: bool,
    allow_prerelease_packages: tuple[str, ...],
) -> None:
    """Update latest_version in-place for packages where prerelease should be considered."""
    for pkg in packages_info.values():
        if not allow_prerelease and pkg.name not in allow_prerelease_packages:
            continue
        try:
            best = packages_registry.newest_version(packages_registry.package_versions(pkg.name))
            if best:
                pkg.latest_version = best.version
        except UnknownPackageVersion:
            # Best-effort prefetch: skip packages with unknown/invalid version data
            # so one bad package does not block processing of the rest.
            continue


def prefetch_versions_since(
    packages_registry: AbstractPackageRegistryApi,
    unique_pairs: Iterable[tuple[str, str]],
    *,
    allow_prerelease: bool = False,
    allow_prerelease_packages: tuple[str, ...] = (),
) -> dict[tuple[str, str], list[package_versions.PackageVersion]]:
    """Pre-compute versions-since-installed for all unique (package_name, installed_version) pairs."""
    result: dict[tuple[str, str], list[package_versions.PackageVersion]] = {}
    for name, version in unique_pairs:
        if (name, version) not in result:
            result[(name, version)] = get_package_versions_since(
                packages_registry,
                name,
                version,
                allow_prerelease=allow_prerelease,
                allow_prerelease_packages=allow_prerelease_packages,
            )
    return result


def prefetch_packages_info(
    packages_registry: AbstractPackageRegistryApi, canonical_names: Iterable[str]
) -> dict[str, Package]:
    """Pre-fetch package info for all unique canonical names in parallel."""
    unique = list(dict.fromkeys(canonical_names))
    return packages_registry.packages_info_batch(unique)


def nearest_cve_fix_version(
    fix_versions: Iterable[str],
    installed_version: str,
    registry: AbstractPackageRegistryApi,
) -> str | None:
    """Return the smallest comparable fix strictly newer than the installed version."""
    nearest = None
    for candidate in fix_versions:
        try:
            if registry.compare_versions(candidate, installed_version) <= 0:
                continue
            if nearest is None or registry.compare_versions(candidate, nearest) < 0:
                nearest = candidate
        except (InvalidVersion, UnknownPackageVersion):
            # OSV can include non-registry ranges such as git commit hashes.
            continue
    return nearest


def cve_fix_age_days(
    cve: CVE,
    installed_version: str,
    releases: Iterable[package_versions.PackageVersion],
    registry: AbstractPackageRegistryApi,
    now: datetime | None,
) -> int | None:
    """Return the age of the nearest available fix release, if the registry knows it."""
    selected_fix = nearest_cve_fix_version(cve.fix_versions, installed_version, registry)
    if not selected_fix:
        return None

    for release in releases:
        # Fast path: bypass expensive version parsing if strings match exactly
        if release.version == selected_fix:
            return age_days_from_iso(release.published_date_iso, now=now)

        # Slow path: semantic version equivalence (e.g. "1.0" == "1.0.0")
        try:
            if registry.compare_versions(release.version, selected_fix) == 0:
                return age_days_from_iso(release.published_date_iso, now=now)
        except (InvalidVersion, UnknownPackageVersion):
            continue

    return None


def aggregate_cve_ids(cve_map: dict[tuple[str, str], set[CVE]]) -> dict[str, set[str]]:
    """Map each primary CVE ID to a set of itself and all its alias IDs."""
    return {cve.id: {cve.id} | set(cve.cve_ids)
            for cves in cve_map.values() for cve in cves}  # fmt: off


def enrich_cves_with_epss_and_fix_age(
    cve_map: dict[tuple[str, str], set[CVE]],
    epss_client: EpssApiFirstOrg,
    registry: AbstractPackageRegistryApi,
    now: datetime | None,
) -> dict[tuple[str, str], set[CVE]]:
    """Return a copy of cve_map with EPSS scores and fix-release ages populated."""
    if not cve_map:
        return {}

    cve_backlink = aggregate_cve_ids(cve_map)
    cve_ids = set(chain.from_iterable(cve_backlink.values()))
    epss_scores = epss_client.get_epss_batch(cve_ids)

    release_cache: dict[str, tuple[package_versions.PackageVersion, ...]] = {}
    enriched_map: dict[tuple[str, str], set[CVE]] = {}

    for (package_name, installed_version), cves in cve_map.items():
        releases: tuple[package_versions.PackageVersion, ...] = ()

        if any(cve.fix_versions for cve in cves):
            if package_name not in release_cache:
                try:
                    release_cache[package_name] = tuple(registry.package_versions(package_name))
                except UnknownPackageVersion:
                    release_cache[package_name] = ()
            releases = release_cache[package_name]

        enriched_cves = set()
        for cve in cves:
            # Cleanly gather EPSS scores for the CVE and its aliases
            aliases = cve_backlink.get(cve.id, set())
            cve_epss_scores = [epss_scores[aid] for aid in aliases if aid in epss_scores]
            max_epss = max(cve_epss_scores) if cve_epss_scores else None

            enriched_cves.add(
                replace(
                    cve,
                    epss=max_epss,
                    fix_age_days=cve_fix_age_days(cve, installed_version, releases, registry, now),
                )
            )

        enriched_map[(package_name, installed_version)] = enriched_cves

    return enriched_map


def prefetch_source_code_repositories_info(
    sources: AbstractProjectSources,
    repo_urls: Iterable[str],
) -> dict[str, Repository]:
    """
    Pre-fetch repository info for all unique GitHub repo URLs in parallel.
    Returns a mapping of url -> Repository; non-GitHub URLs are skipped.
    """

    github_urls = [url for url in repo_urls if (urlparse(url).hostname or "").lower() == "github.com"]
    if not github_urls:
        return {}
    return sources.get_source_code_provider(RepositoryProvider.PROVIDER_GITHUB).repositories_info_batch(github_urls)


def partition_git_hosted(deps: Iterable[Dependency], enabled: bool) -> tuple[list[Dependency], list[Dependency]]:
    """Split deps into (registry-resolvable, git/URL-hosted).

    Git/URL-hosted deps aren't on the registry, so fetching them crashes the scan; they're
    skipped like --ignore and reported at the end. When disabled (non-npm), all deps are
    treated as registry-resolvable.
    """
    registry: list[Dependency] = []
    git_hosted: list[Dependency] = []
    for dep in deps:
        is_git = enabled and is_git_hosted_source(dep.version_defined, dep.source)
        (git_hosted if is_git else registry).append(dep)
    return registry, git_hosted


def build_ignored_packages(
    git_hosted: list[Dependency],
    direct_descriptors: list[DependencyDescriptor],
    ignore_set: frozenset[str],
) -> list[IgnoredDependency]:
    """Build the ignored-dependencies report: git/URL-hosted deps (auto-skipped) plus explicit
    --ignore deps. Deduplicated by canonical name; git-hosted wins on overlap.
    """
    ignored: dict[str, IgnoredDependency] = {}
    for dep in git_hosted:
        ignored.setdefault(
            dep.canonical_name,
            IgnoredDependency(
                name=dep.name,
                spec=dep.version_defined or dep.source or "",
                reason=IGNORE_REASON_NON_REGISTRY,
            ),
        )
    for descriptor in direct_descriptors:
        if descriptor.canonical_name in ignore_set:
            ignored.setdefault(
                descriptor.canonical_name,
                IgnoredDependency(
                    name=descriptor.name,
                    spec=descriptor.version_constraint or "",
                    reason=IGNORE_REASON_IGNORE_FLAG,
                ),
            )
    return list(ignored.values())
