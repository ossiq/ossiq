"""
Service to take care of a Package versions
"""

from dataclasses import dataclass
from datetime import datetime

from rich.console import Console

from ossiq.domain.cve import CVE
from ossiq.domain.exceptions import ProjectPathNotFoundError
from ossiq.domain.project import Project
from ossiq.domain.version import VersionsDifference
from ossiq.service.common import package_versions
from ossiq.unit_of_work import core as unit_of_work

console = Console()


@dataclass
class ProjectMetricsRecord:
    package_name: str
    is_dev_dependency: bool
    installed_version: str
    latest_version: str | None
    versions_diff_index: VersionsDifference
    time_lag_days: int | None
    releases_lag: int | None
    cve: list[CVE]


@dataclass
class ProjectMetrics:
    project_name: str
    packages_registry: str
    project_path: str
    production_packages: list[ProjectMetricsRecord]
    development_packages: list[ProjectMetricsRecord]


def parse_iso(datetime_str: str | None):
    """
    Parse ISO datetime string to datetime object.
    """
    if datetime_str:
        return datetime.fromisoformat(datetime_str.replace("Z", "+00:00"))

    return None


def calculate_time_lag(
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
    uow: unit_of_work.AbstractProjectUnitOfWork, package_name: str, installed_version: str
) -> list[package_versions.PackageVersion]:
    """
    Calculate Package versions lag: delta between
    installed package and the latest one.
    """

    return [
        v
        for v in uow.packages_registry.package_versions(package_name)
        if uow.packages_registry.compare_versions(v.version, installed_version) >= 0
    ]


def scan_record(
    uow: unit_of_work.AbstractProjectUnitOfWork,
    project_info: Project,
    package_name: str,
    package_version: str,
    is_dev_dependency: bool,
) -> ProjectMetricsRecord:
    """
    Factory to generate ProjectMetricsRecord instances
    """
    package_info = uow.packages_registry.package_info(package_name)
    installed_version = project_info.installed_package_version(package_info.name)

    releases_since_installed = get_package_versions_since(uow, package_info.name, installed_version)

    time_lag_days = calculate_time_lag(releases_since_installed, installed_version, package_info.latest_version)

    installed_release = next(
        (release for release in releases_since_installed if release.version == installed_version), None
    )

    cve = []
    if installed_release:
        cve = list(uow.cve_database.get_cves_for_package(package_info, installed_release))

    return ProjectMetricsRecord(
        package_name=package_name,
        installed_version=package_version,
        latest_version=package_info.latest_version,
        time_lag_days=time_lag_days,
        releases_lag=len(releases_since_installed) - 1,
        versions_diff_index=uow.packages_registry.difference_versions(installed_version, package_info.latest_version),
        cve=cve,
        is_dev_dependency=is_dev_dependency,
    )


def scan(uow: unit_of_work.AbstractProjectUnitOfWork) -> ProjectMetrics:
    def sort_function(pkg: ProjectMetricsRecord):
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

        production_packages: list[ProjectMetricsRecord] = []
        development_packages: list[ProjectMetricsRecord] = []

        for package_name, package in project_info.dependencies.items():
            production_packages.append(scan_record(uow, project_info, package_name, package.version_installed, False))

        # uow.production is driven by the setting
        if not uow.production:
            for package_name, package in project_info.optional_dependencies.items():
                development_packages.append(
                    scan_record(uow, project_info, package_name, package.version_installed, True)
                )

        return ProjectMetrics(
            project_name=project_info.name,
            project_path=project_info.project_path,
            packages_registry=project_info.package_registry.value,
            production_packages=sorted(
                [pkg for pkg in production_packages if not pkg.is_dev_dependency], key=sort_function, reverse=True
            ),
            development_packages=sorted(
                [pkg for pkg in development_packages if pkg.is_dev_dependency], key=sort_function, reverse=True
            ),
        )
