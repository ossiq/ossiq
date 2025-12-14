"""
Aggregate all the changes around Package Registry, Source Code Repository
given currently installed package version without polluting with
versions out of scope.
"""

from collections.abc import Iterable

from ossiq.domain.common import NoPackageVersionsFound, identify_project_source_code_provider_kind
from ossiq.domain.repository import Repository
from ossiq.domain.version import PackageVersion, RepositoryVersion, Version, compare_versions, normalize_version
from ossiq.unit_of_work.core import AbstractProjectUnitOfWork


def filter_versions_between(versions: list[str], installed: str, latest: str) -> Iterable[str]:
    """
    Filter out versions which we're interested in.
    """

    if installed == latest:
        return

    installed_norm, latest_norm = normalize_version(installed), normalize_version(latest)

    for version in sorted(versions):
        version_norm = normalize_version(version)
        if not version_norm:
            continue

        if compare_versions(version_norm, installed_norm) >= 0 and compare_versions(version_norm, latest_norm) <= 0:
            yield version


def aggregated_package_versions(
    uow: AbstractProjectUnitOfWork,
    repository_info: Repository,
    package_name: str,
    installed_version: str,
    latest_version: str,
) -> tuple[list[PackageVersion], list[RepositoryVersion]]:
    """
    Load package versions from a given registry.
    """
    package_info = uow.packages_registry.package_info(package_name)
    repository_provider = uow.get_source_code_provider(
        identify_project_source_code_provider_kind(package_info.repo_url)
    )
    # Leveraging abstractions to the full extend
    package_versions = list(uow.packages_registry.package_versions(package_name))

    if not package_versions:
        raise NoPackageVersionsFound(f"Cannot load package versions for {package_name}")

    # NOTE: we don't need to pull all the versions, just the difference between
    # what we have and what is the latest available.
    versions_delta = list(
        filter_versions_between([p.version for p in package_versions], installed_version, latest_version)
    )

    # filter out versions we don't need
    packages_delta = [p for p in package_versions if p.version in versions_delta]

    repository_versions = list(repository_provider.repository_versions(repository_info, packages_delta))

    if repository_versions is None:
        raise NoPackageVersionsFound(f"Cannot load repository versions for {package_name}")

    return package_versions, repository_versions


def package_changes(uow: AbstractProjectUnitOfWork, package_name: str, installed_version: str) -> Iterable[Version]:
    """
    Aggregate changes between two versions of a package regardless of the registry.
    """

    package_info = uow.packages_registry.package_info(package_name)
    latest_version = package_info.latest_version

    repository_provider = uow.get_source_code_provider(
        identify_project_source_code_provider_kind(package_info.repo_url)
    )

    # then extract some repository info
    repository_info = repository_provider.repository_info(package_info.repo_url)

    # Pull what is in the project file
    package_versions, repository_versions = aggregated_package_versions(
        uow, repository_info, package_name, installed_version, latest_version
    )

    repo_versions_map = {version.version: version for version in repository_versions}

    for package_version in package_versions:
        # Assumption: identify changes only for versions available in the source code repository
        if package_version.version not in repo_versions_map:
            continue

        yield Version(
            package_registry=uow.packages_registry.registry,
            repository_provider=repository_info.provider,
            package_data=package_version,
            repository_data=repo_versions_map[package_version.version],
        )
