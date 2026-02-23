"""
Service to take care of a Package versions
"""

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from rich.console import Console

from ossiq.adapters.api_interfaces import AbstractCveDatabaseApi, AbstractPackageRegistryApi
from ossiq.adapters.package_managers.dependency_tree import GraphExporter
from ossiq.domain.cve import CVE
from ossiq.domain.exceptions import ProjectPathNotFoundError
from ossiq.domain.project import Dependency
from ossiq.domain.version import VersionsDifference
from ossiq.service.common import package_versions
from ossiq.unit_of_work import core as unit_of_work

console = Console()


@dataclass
class ScanRecord:
    package_name: str
    is_optional_dependency: bool
    installed_version: str
    latest_version: str | None
    versions_diff_index: VersionsDifference
    time_lag_days: int | None
    releases_lag: int | None
    cve: list[CVE]
    dependency_path: list[str] | None = None


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

    return [
        v
        for v in packages_registry.package_versions(package_name)
        if packages_registry.compare_versions(v.version, installed_version) >= 0
    ]


def scan_record(
    packages_registry: AbstractPackageRegistryApi,
    cve_database: AbstractCveDatabaseApi,
    package_name: str,
    package_version: str,
    is_optional_dependency: bool,
    dependency_path: list[str] | None = None,
) -> ScanRecord:
    """
    Factory to generate ScanRecord instances
    """
    package_info = packages_registry.package_info(package_name)

    releases_since_installed = get_package_versions_since(packages_registry, package_info.name, package_version)

    time_lag_days = calculate_time_lag_in_days(releases_since_installed, package_version, package_info.latest_version)

    installed_release = next(
        (release for release in releases_since_installed if release.version == package_version), None
    )

    cve = []
    if installed_release:
        cve = list(cve_database.get_cves_for_package(package_info, installed_release.version))

    return ScanRecord(
        package_name=package_name,
        installed_version=package_version,
        latest_version=package_info.latest_version,
        time_lag_days=time_lag_days,
        releases_lag=len(releases_since_installed) - 1,
        versions_diff_index=packages_registry.difference_versions(package_version, package_info.latest_version),
        cve=cve,
        is_optional_dependency=is_optional_dependency,
        dependency_path=dependency_path,
    )


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

        def pull_packages_info(
            dependencies: Iterable[Dependency], is_optional_dependency: bool
        ) -> Iterable[ScanRecord]:
            for package in dependencies:
                yield scan_record(
                    uow.packages_registry,
                    uow.cve_database,
                    package.name,
                    package.version_installed,
                    is_optional_dependency,
                )

        production_packages = sorted(
            pull_packages_info(project_info.dependencies.values(), False),
            key=sort_function,
            reverse=True,
        )

        optional_packages: list[ScanRecord] = []
        # uow.production is driven by the setting
        if not uow.production:
            optional_packages = sorted(
                pull_packages_info(project_info.optional_dependencies.values(), True),
                key=sort_function,
                reverse=True,
            )

        walker = GraphExporter(project_info.dependency_tree)
        transitive_packages = [
            scan_record(
                uow.packages_registry,
                uow.cve_database,
                node.name,
                node.version_installed,
                is_optional_dependency=False,
                dependency_path=path,
            )
            for node, path in walker.walk_all_paths()
        ]

        return ScanResult(
            project_name=project_info.name,
            project_path=project_info.project_path,
            packages_registry=project_info.package_registry.value,
            production_packages=production_packages,
            optional_packages=optional_packages,
            transitive_packages=transitive_packages,
        )
