"""
Aggregate all the changes around Package Registry, Source Code Repository
given currently installed package version without polluting with
versions out of scope.
"""

from collections.abc import Callable, Iterable

from ossiq.adapters.detectors import detect_source_code_provider
from ossiq.domain.common import NoPackageVersionsFound
from ossiq.domain.repository import Repository
from ossiq.domain.version import PackageVersion, RepositoryVersion, Version
from ossiq.unit_of_work.core import AbstractProjectUnitOfWork


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
    package_name: str,
    installed_version: str,
    latest_version: str | None,
) -> tuple[list[PackageVersion], list[RepositoryVersion]]:
    """
    Load package versions from a given registry.
    """
    package_info = uow.packages_registry.package_info(package_name)
    source_code_provider_type = detect_source_code_provider(package_info.repo_url)
    source_code_provider = uow.get_source_code_provider(source_code_provider_type)
    # Leveraging abstractions to the full extend
    package_versions = list(uow.packages_registry.package_versions(package_name))

    if not package_versions:
        raise NoPackageVersionsFound(f"Cannot load package versions for {package_name}")

    # NOTE: we don't need to pull all the versions, just the difference between
    # what we have and what is the latest available.
    if latest_version:
        versions_delta = list(
            filter_versions_between(
                [p.version for p in package_versions],
                installed_version,
                latest_version,
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
        raise NoPackageVersionsFound(f"Cannot load repository versions for {package_name}")

    return package_versions, repository_versions


def package_changes(uow: AbstractProjectUnitOfWork, package_name: str, installed_version: str) -> Iterable[Version]:
    """
    Aggregate changes between two versions of a package regardless of the registry.
    """

    package_info = uow.packages_registry.package_info(package_name)
    latest_version = package_info.latest_version

    repository_provider = uow.get_source_code_provider(detect_source_code_provider(package_info.repo_url))

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
            package_registry=uow.packages_registry.package_registry,
            repository_provider=repository_info.provider,
            package_data=package_version,
            repository_data=repo_versions_map[package_version.version],
        )
