"""
Bulk pre-fetch helpers: package info, repositories, versions-since-installed,
and classification of dependencies that must be excluded from the scan.
"""

from collections.abc import Iterable

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.adapters.detectors import is_git_hosted_source
from ossiq.domain.common import RepositoryProvider
from ossiq.domain.exceptions import UnknownPackageVersion
from ossiq.domain.package import Package
from ossiq.domain.project import Dependency
from ossiq.domain.repository import Repository
from ossiq.messages import IGNORE_REASON_IGNORE_FLAG, IGNORE_REASON_NON_REGISTRY
from ossiq.service.common import package_versions
from ossiq.service.project.models import DependencyDescriptor, IgnoredDependency
from ossiq.sources.core import AbstractProjectSources


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
            pass


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


def prefetch_source_code_repositories_info(
    sources: AbstractProjectSources,
    repo_urls: Iterable[str],
) -> dict[str, Repository]:
    """
    Pre-fetch repository info for all unique GitHub repo URLs in parallel.
    Returns a mapping of url -> Repository; non-GitHub URLs are skipped.
    """

    if not (github_urls := [url for url in repo_urls if "github.com" in url]):
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
