"""
Aggregate all the changes around Package Registry, Source Code Repository
given currently installed package version without polluting with
versions out of scope.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ossiq.adapters.detectors import detect_source_code_provider
from ossiq.domain.common import NoPackageVersionsFound
from ossiq.domain.package import Package
from ossiq.domain.repository import Repository
from ossiq.domain.version import PackageVersion, RepositoryVersion, Version
from ossiq.unit_of_work.core import AbstractProjectUnitOfWork


@dataclass
class TransitiveVersionDelta:
    """Version delta for transitive dependencies: installed and latest versions only."""

    installed: Version | None
    latest: Version | None


def filter_versions_between(versions: list[str], installed: str, latest: str, comparator: Callable) -> Iterable[str]:
    """
    Filter out versions which we're interested in.
    """

    if installed == latest:
        return

    for version in sorted(versions):
        if comparator(version, installed) >= 0 and comparator(version, latest) <= 0:
            yield version


def aggregated_package_versions(
    uow: AbstractProjectUnitOfWork,
    repository_info: Repository,
    package_info: Package,
    installed_version: str,
) -> tuple[list[PackageVersion], list[RepositoryVersion]]:
    """
    Load package versions from a given registry.
    """
    package_info = uow.packages_registry.package_info(package_info.name)

    source_code_provider_type = detect_source_code_provider(package_info.repo_url)
    source_code_provider = uow.get_source_code_provider(source_code_provider_type)
    # Leveraging abstractions to the full extend
    package_versions = list(uow.packages_registry.package_versions(package_info.name))

    if not package_versions:
        raise NoPackageVersionsFound(f"Cannot load package versions for {package_info.name}")

    # NOTE: we don't need to pull all the versions, just the difference between
    # what we have and what is the latest available.
    if package_info.latest_version:
        versions_delta = list(
            filter_versions_between(
                [p.version for p in package_versions],
                installed_version,
                package_info.latest_version,
                comparator=uow.packages_registry.compare_versions,
            )
        )
    else:
        versions_delta = [p.version for p in package_versions]

    # filter out versions we don't need
    packages_delta = [p for p in package_versions if p.version in versions_delta]

    repository_versions = list(
        source_code_provider.repository_versions(
            repository_info, packages_delta, comparator=uow.packages_registry.compare_versions
        )
    )

    if repository_versions is None:
        raise NoPackageVersionsFound(f"Cannot load repository versions for {package_info.name}")

    return package_versions, repository_versions


def package_changes(uow: AbstractProjectUnitOfWork, package_name: str, installed_version: str) -> Iterable[Version]:
    """
    Aggregate changes between two versions of a package regardless of the registry.
    """

    package_info = uow.packages_registry.package_info(package_name)
    repository_provider = uow.get_source_code_provider(detect_source_code_provider(package_info.repo_url))

    # then extract some repository info
    repository_info = repository_provider.repository_info(package_info.repo_url)

    # Pull what is in the project file
    package_versions, repository_versions = aggregated_package_versions(
        uow, repository_info, package_info, installed_version
    )

    repo_versions_map = {version.version: version for version in repository_versions}

    for package_version in package_versions:
        # Assumption: identify changes only for versions available in the source code repository
        if package_version.version not in repo_versions_map:
            continue

        yield Version(
            package_registry=uow.packages_registry.package_registry,
            repository_provider=repository_info.provider,
            package_data=package_version,
            repository_data=repo_versions_map[package_version.version],
        )


def transitive_package_delta(
    uow: AbstractProjectUnitOfWork,
    package_info: Package,
    installed_version: str,  # actually installed version in the environment
) -> TransitiveVersionDelta:
    """
    For transitive packages analysis we need to pull installed and latest versions only.

    Returns TransitiveVersionDelta with installed and latest Version objects.
    """
    latest_version = package_info.latest_version

    repository_provider = uow.get_source_code_provider(detect_source_code_provider(package_info.repo_url))
    repository_info = repository_provider.repository_info(package_info.repo_url)

    # Fetch all package versions from registry (will be cached for shared deps)
    package_versions = list(uow.packages_registry.package_versions(package_info.name))

    if not package_versions:
        raise NoPackageVersionsFound(f"Cannot load package versions for {package_info.name}")

    # Build lookup map for package versions
    pkg_versions_map = {pv.version: pv for pv in package_versions}

    # Filter to only installed and latest PackageVersion objects
    versions_to_fetch = {installed_version}
    if latest_version and latest_version != installed_version:
        versions_to_fetch.add(latest_version)

    packages_delta = [pkg_versions_map[v] for v in versions_to_fetch if v in pkg_versions_map]

    # Fetch repository versions for installed and latest only
    repository_versions = list(
        repository_provider.repository_versions(
            repository_info, packages_delta, comparator=uow.packages_registry.compare_versions
        )
    )

    repo_versions_map = {rv.version: rv for rv in repository_versions}

    # Build Version objects for installed and latest
    installed_ver = None
    latest_ver = None

    if installed_version in pkg_versions_map and installed_version in repo_versions_map:
        installed_ver = Version(
            package_registry=uow.packages_registry.package_registry,
            repository_provider=repository_info.provider,
            package_data=pkg_versions_map[installed_version],
            repository_data=repo_versions_map[installed_version],
        )

    if latest_version and latest_version in pkg_versions_map and latest_version in repo_versions_map:
        latest_ver = Version(
            package_registry=uow.packages_registry.package_registry,
            repository_provider=repository_info.provider,
            package_data=pkg_versions_map[latest_version],
            repository_data=repo_versions_map[latest_version],
        )

    return TransitiveVersionDelta(installed=installed_ver, latest=latest_ver)
