"""
Service to take care of a Package versions
"""

from dataclasses import dataclass
from typing import List

from rich.console import Console
from update_burden.domain.version import normalize_version
from update_burden.unit_of_work import core as unit_of_work
# from update_burden.domain.common import RepositoryProviderType

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


def overview(uow: unit_of_work.AbstractProjectUnitOfWork) -> ProjectOverviewSummary:
    with uow:
        # registry = uow.packages_registry.package_info(package_name)
        # source_code_provider = uow.get_source_code_provider(
        #     repository_provider_type)
        # repository = source_code_provider.repository_info(
        #     "https://github.com/mklymyshyn/ossrisk"
        # )

        project_info = uow.packages_registry.project_info(uow.project_path)
        packages: List[ProjectOverviewRecord] = []
        for package_name, package_version in project_info.dependencies.items():
            packages.append(
                ProjectOverviewRecord(
                    package_name=package_name,
                    installed_version=normalize_version(package_version),
                    latest_version=None,
                    lag_days=0,
                    is_dev_dependency=False
                )
            )

        return ProjectOverviewSummary(
            project_name=project_info.name,
            project_path=project_info.project_path,
            project_files=project_info.project_files,
            packages_registry=project_info.package_registry.value,
            installed_packages_overview=packages
        )
