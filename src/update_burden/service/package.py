"""
Service to take care of a Package versions
"""

from rich.console import Console
from update_burden.unit_of_work import core as unit_of_work
from update_burden.domain.common import RepositoryProviderType
from update_burden.adapters.api import SourceCodeProviderApiFactory

console = Console()


def versions(uow: unit_of_work.AbstractProjectUnitOfWork,
             repository_provider_type: RepositoryProviderType,
             package_name: str):
    with uow:
        repository_provider = SourceCodeProviderApiFactory.get_provider(
            repository_provider_type,
            uow.settings
        )
        repository = repository_provider.repository_info(
            "https://github.com/mklymyshyn/ossrisk"
        )
        registry = uow.packages_registry.package_info(package_name)

        console.print(f"[bold]Detected Repository:[/bold] {repository}")
        console.print(f"[bold]Detected Registry:[/bold] {registry}")
