"""
Service to take care of a Package versions
"""

from rich.console import Console
from update_burden.unit_of_work import core as unit_of_work

console = Console()


def versions(uow: unit_of_work.AbstractPackageUnitOfWork):
    with uow:

        repository = uow.repository_provider.repository_info(
            "https://github.com/mklymyshyn/ossrisk"
        )
        registry = uow.packages_registry.package_info(uow.package_name)

        console.print(f"[bold]Detected Repository:[/bold] {repository}")
        console.print(f"[bold]Detected Registry:[/bold] {registry}")
