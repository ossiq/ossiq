"""
Service to take care of a Package versions
"""
from dataclasses import dataclass

from rich.console import Console
from update_burden.unit_of_work import core as unit_of_work
# from update_burden.domain.common import RepositoryProviderType

console = Console()


@dataclass
class ProjectOverview:
    # TODO: Add Response format for overview
    pass


def overview(uow: unit_of_work.AbstractProjectUnitOfWork):
    with uow:
        # registry = uow.packages_registry.package_info(package_name)
        # source_code_provider = uow.get_source_code_provider(
        #     repository_provider_type)
        # repository = source_code_provider.repository_info(
        #     "https://github.com/mklymyshyn/ossrisk"
        # )

        project_info = uow.packages_registry.project_info(uow.project_path)
        console.print(f"[bold]Detected Project:[/bold] {project_info}")
        console.print(
            f"[bold]Detected Registry:[/bold] {uow.packages_registry}")
