"""
Service to take care of a Package versions
"""
import itertools

from dataclasses import dataclass
from datetime import datetime
from typing import List

from rich.console import Console
from update_burden.domain.package import Package
from update_burden.domain.project import Project
from update_burden.domain.version import compare_versions, normalize_version
from update_burden.service.common import package_versions
from update_burden.unit_of_work import core as unit_of_work

console = Console()


@dataclass
class ProjectOverviewRecord:
    package_name: str
    is_dev_dependency: bool
    installed_version: str
    latest_version: str
    lag_days: int


@dataclass
class ProjectOverviewSummary:
    project_name: str
    packages_registry: str
    project_path: str
    project_files: List[str]
    installed_packages_overview: List[ProjectOverviewRecord]


def parse_iso(datetime_str: str | None):
    """
    Parse ISO datetime string to datetime object.
    """
    if datetime_str:
        return datetime.fromisoformat(datetime_str.replace("Z", "+00:00"))

    return None


def calculate_time_difference(
        versions: List[package_versions.PackageVersion],
        installed_version: str,
        latest_version: str) -> int | None:
    """
    Calculates the time difference in days between the installed and latest package versions.
    """
    installed_date = None
    latest_date = None

    if installed_version == latest_version:
        return 0

    for pv in versions:
        if pv.version == installed_version and pv.published_date_iso:
            installed_date = parse_iso(pv.published_date_iso)
        elif pv.version == latest_version and pv.published_date_iso:
            latest_date = parse_iso(pv.published_date_iso)

    if installed_date and latest_date:
        return (latest_date - installed_date).days

    return None


def get_package_versions_lag(
        uow: unit_of_work.AbstractProjectUnitOfWork,
        project_info: Project,
        package_info: Package) -> int | None:
    """
    Calculate Package versions lag: delta between
    installed package and the latest one.
    """
    installed_version = project_info.installed_package_version(
        package_info.name)

    versions = [
        v for v in
        uow.packages_registry.package_versions(package_info.name)
        if compare_versions(v.version, installed_version) >= 0
    ]

    latest_version = package_info.latest_version

    return calculate_time_difference(
        versions,
        installed_version,
        latest_version
    )


def overview(uow: unit_of_work.AbstractProjectUnitOfWork) -> ProjectOverviewSummary:
    with uow:
        project_info = uow.packages_registry.project_info(uow.project_path)
        packages: List[ProjectOverviewRecord] = []

        # Combine production and dev dependencies for processing
        dependencies = itertools.chain(
            ((name, version, False)
             for name, version in project_info.dependencies.items()),
            ((name, version, True)
             for name, version in project_info.dev_dependencies.items())
        )

        for package_name, package_version, is_dev_dependency in dependencies:
            if uow.production and is_dev_dependency:
                continue

            package_info = uow.packages_registry.package_info(package_name)
            versions_lag = get_package_versions_lag(
                uow,
                project_info,
                package_info
            )
            packages.append(
                ProjectOverviewRecord(
                    package_name=package_name,
                    installed_version=normalize_version(package_version),
                    latest_version=package_info.latest_version,
                    lag_days=versions_lag,
                    is_dev_dependency=is_dev_dependency
                )
            )

        return ProjectOverviewSummary(
            project_name=project_info.name,
            project_path=project_info.project_path,
            project_files=project_info.project_files,
            packages_registry=project_info.package_registry.value,
            installed_packages_overview=packages
        )
