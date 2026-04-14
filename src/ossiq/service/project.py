"""
Service to take care of a Package versions
"""

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from rich.console import Console

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.adapters.package_managers.dependency_tree import GraphExporter
from ossiq.domain.common import RepositoryProvider, build_purl, parse_spdx_expression
from ossiq.domain.cve import CVE
from ossiq.domain.exceptions import ProjectPathNotFoundError, UnknownPackageVersion
from ossiq.domain.package import Package
from ossiq.domain.project import ConstraintSource
from ossiq.domain.repository import Repository
from ossiq.domain.version import VersionsDifference
from ossiq.service.common import package_versions
from ossiq.unit_of_work import core as unit_of_work

console = Console()


@dataclass(frozen=True)
class DependencyDescriptor:
    name: str
    canonical_name: str
    version: str
    is_optional: bool
    dependency_path: list[str] | None
    version_constraint: str | None
    constraint_info: ConstraintSource


@dataclass
class ScanRecord:
    """
    Main aggregated output of the OSS IQ tool.
    """

    package_name: str
    dependency_name: str
    is_optional_dependency: bool
    installed_version: str
    latest_version: str | None
    versions_diff_index: VersionsDifference
    time_lag_days: int | None
    releases_lag: int | None
    cve: list[CVE]
    constraint_info: ConstraintSource
    version_constraint: str | None = None
    dependency_path: list[str] | None = None
    license: list[str] | None = None
    repo_url: str | None = None
    repository: Repository | None = None
    homepage_url: str | None = None
    package_url: str | None = None
    purl: str | None = None


@dataclass
class ScanResult:
    project_name: str
    packages_registry: str
    project_path: str
    production_packages: list[ScanRecord]
    optional_packages: list[ScanRecord]
    transitive_packages: list[ScanRecord] = field(default_factory=list)


def parse_iso(datetime_str: str | None):
    """
    Parse ISO datetime string to datetime object.
    """
    if datetime_str:
        return datetime.fromisoformat(datetime_str.replace("Z", "+00:00"))

    return None


def calculate_time_lag_in_days(
    versions: list[package_versions.PackageVersion], installed_version: str, latest_version: str | None
) -> int | None:
    """
    Calculates the time difference in days between the installed and latest package versions.
    """
    installed_date = None
    latest_date = None

    if installed_version == latest_version or not latest_version:
        return 0

    for pv in versions:
        if pv.version == installed_version and pv.published_date_iso:
            installed_date = parse_iso(pv.published_date_iso)
        elif pv.version == latest_version and pv.published_date_iso:
            latest_date = parse_iso(pv.published_date_iso)

    if installed_date and latest_date:
        return (latest_date - installed_date).days

    return None


def get_package_versions_since(
    packages_registry: AbstractPackageRegistryApi, package_name: str, installed_version: str
) -> list[package_versions.PackageVersion]:
    """
    Calculate Package versions lag: delta between
    installed package and the latest one.
    """
    try:
        return [
            v
            for v in packages_registry.package_versions(package_name)
            if packages_registry.compare_versions(v.version, installed_version) >= 0
        ]
    except UnknownPackageVersion:
        return []


def scan_record(
    packages_registry: AbstractPackageRegistryApi,
    package_info: Package,
    package_name: str,
    canonical_name: str,
    package_version: str,
    is_optional_dependency: bool,
    prefetched_cves: set[CVE],
    prefetched_versions_since: list[package_versions.PackageVersion],
    constraint_info: ConstraintSource,
    dependency_path: list[str] | None = None,
    version_constraint: str | None = None,
    prefetched_repository: Repository | None = None,
) -> ScanRecord:
    """
    Factory to generate ScanRecord instances
    """
    releases_since_installed = prefetched_versions_since

    time_lag_days = calculate_time_lag_in_days(releases_since_installed, package_version, package_info.latest_version)

    installed_release = next(
        (release for release in releases_since_installed if release.version == package_version), None
    )

    version_diff_index = packages_registry.difference_versions(package_version, package_info.latest_version)

    return ScanRecord(
        package_name=canonical_name,
        dependency_name=package_name,
        installed_version=package_version,
        latest_version=package_info.latest_version,
        time_lag_days=time_lag_days,
        releases_lag=len(releases_since_installed) - 1,
        versions_diff_index=version_diff_index,
        cve=list(prefetched_cves) if installed_release else [],
        is_optional_dependency=is_optional_dependency,
        dependency_path=dependency_path,
        version_constraint=version_constraint,
        constraint_info=constraint_info,
        repo_url=package_info.repo_url,
        repository=prefetched_repository,
        homepage_url=package_info.homepage_url,
        package_url=package_info.package_url,
        license=parse_spdx_expression(
            package_info.license or (prefetched_repository.license if prefetched_repository else None)
        ),
        purl=build_purl(packages_registry.package_registry, canonical_name, package_version),
    )


def prefetch_versions_since(
    packages_registry: AbstractPackageRegistryApi,
    unique_pairs: Iterable[tuple[str, str]],
) -> dict[tuple[str, str], list[package_versions.PackageVersion]]:
    """Pre-compute versions-since-installed for all unique (package_name, installed_version) pairs."""
    result: dict[tuple[str, str], list[package_versions.PackageVersion]] = {}
    for name, version in unique_pairs:
        if (name, version) not in result:
            result[(name, version)] = get_package_versions_since(packages_registry, name, version)
    return result


def prefetch_packages_info(
    packages_registry: AbstractPackageRegistryApi, canonical_names: Iterable[str]
) -> dict[str, Package]:
    """Pre-fetch package info for all unique canonical names in parallel."""
    unique = list(dict.fromkeys(canonical_names))
    return packages_registry.packages_info_batch(unique)


def prefetch_source_code_repositories_info(
    uow: unit_of_work.AbstractProjectUnitOfWork,
    repo_urls: Iterable[str],
) -> dict[str, Repository]:
    """
    Pre-fetch repository info for all unique GitHub repo URLs in parallel.
    Returns a mapping of url -> Repository; non-GitHub URLs are skipped.
    """
    github_urls = [url for url in repo_urls if "github.com" in url]
    if not github_urls:
        return {}
    return uow.get_source_code_provider(RepositoryProvider.PROVIDER_GITHUB).repositories_info_batch(github_urls)


def scan(uow: unit_of_work.AbstractProjectUnitOfWork) -> ScanResult:
    """
    Project scan service to leverage Project UoW to gather metrics
    """

    def sort_function(pkg: ScanRecord):
        return (
            pkg.versions_diff_index.diff_index,
            len(pkg.cve),
            pkg.time_lag_days,
            pkg.package_name,
        )

    with uow:
        project_info = uow.packages_manager.project_info()
        # FIXME: catch this issue way before as part of command validation
        if not project_info.project_path:
            raise ProjectPathNotFoundError("Project Path is not Specified")

        # Collect all dependency descriptors
        prod_deps = [
            DependencyDescriptor(
                name=dep.name,
                canonical_name=dep.canonical_name,
                version=dep.version_installed,
                is_optional=False,
                dependency_path=None,
                version_constraint=dep.version_defined,
                constraint_info=dep.constraint_info,
            )
            for dep in project_info.dependencies.values()
        ]

        opt_deps: list[DependencyDescriptor] = []
        if not uow.production:
            opt_deps = [
                DependencyDescriptor(
                    name=dep.name,
                    canonical_name=dep.canonical_name,
                    version=dep.version_installed,
                    is_optional=True,
                    dependency_path=None,
                    version_constraint=dep.version_defined,
                    constraint_info=dep.constraint_info,
                )
                for dep in project_info.optional_dependencies.values()
            ]

        walker = GraphExporter(project_info.dependency_tree)
        trans_deps = [
            DependencyDescriptor(
                name=node.name,
                canonical_name=node.canonical_name,
                version=node.version_installed,
                is_optional=False,
                dependency_path=path,
                version_constraint=node.version_defined,
                constraint_info=node.constraint_info,
            )
            for node, path in walker.walk_all_paths()
        ]

        all_deps = prod_deps + opt_deps + trans_deps

        # Pass 1: pre-fetch package infos
        packages_info = prefetch_packages_info(uow.packages_registry, (dep.canonical_name for dep in all_deps))

        # Github repository info
        repositories_info = prefetch_source_code_repositories_info(
            uow,
            {pkg.repo_url for pkg in packages_info.values() if pkg.repo_url is not None},
        )
        # Batch CVE fetch for all unique packages
        # force unique pair package/version regardless position in the graph
        unique_packages = list(set((packages_info[dep.canonical_name], dep.version) for dep in all_deps))

        cve_map = uow.cve_database.get_cves_batch(unique_packages)

        # Pre-compute versions-since-installed for all unique (package, version) pairs
        versions_since_map = prefetch_versions_since(
            uow.packages_registry,
            {(packages_info[dep.canonical_name].name, dep.version) for dep in all_deps},
        )

        # Pass 2: build ScanRecords using pre-fetched data; license comes from registry + GitHub
        def build_records(descriptors: list[DependencyDescriptor]) -> list[ScanRecord]:
            return [
                scan_record(
                    uow.packages_registry,
                    packages_info[dep.canonical_name],
                    dep.name,
                    dep.canonical_name,
                    dep.version,
                    dep.is_optional,
                    cve_map.get((packages_info[dep.canonical_name].name, dep.version), set()),
                    versions_since_map[(packages_info[dep.canonical_name].name, dep.version)],
                    dep.constraint_info,
                    dep.dependency_path,
                    dep.version_constraint,
                    repositories_info.get(packages_info[dep.canonical_name].repo_url or ""),
                )
                for dep in descriptors
            ]

        production_packages = sorted(build_records(prod_deps), key=sort_function, reverse=True)
        optional_packages = sorted(build_records(opt_deps), key=sort_function, reverse=True)
        transitive_packages = build_records(trans_deps)

        return ScanResult(
            project_name=project_info.name,
            project_path=project_info.project_path,
            packages_registry=project_info.package_registry.value,
            production_packages=production_packages,
            optional_packages=optional_packages,
            transitive_packages=transitive_packages,
        )
