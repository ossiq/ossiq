"""
Package Unit Of Work pattern to isolate
I/O for external sources
"""

from ossiq.adapters.api import get_cve_database, get_package_registry, get_source_code_provider
from ossiq.adapters.api_interfaces import AbstractSourceCodeProviderApi
from ossiq.domain.common import ProjectPackagesRegistry, RepositoryProvider
from ossiq.settings import Settings
from ossiq.unit_of_work.core import AbstractProjectUnitOfWork


class ProjectUnitOfWork(AbstractProjectUnitOfWork):
    """
    Practical implementation of an abstraction around a
    single installed package
    """

    def __init__(
        self,
        settings: Settings,
        project_path: str,
        packages_registry_type: ProjectPackagesRegistry,
        production: bool = False,
    ):
        """
        Takes a single package details pulled from
        """
        super().__init__()

        self.project_path = project_path
        self.settings = settings
        self.packages_registry_type = packages_registry_type
        self.production = production
        self.cve_database = get_cve_database()

    def __enter__(self):
        """
        Initialize actual instances of respective clients (and other stuff when needed)
        """
        self.packages_registry = get_package_registry(self.packages_registry_type)

    def __exit__(self, *args):
        pass

    def get_source_code_provider(self, repository_provider_type: RepositoryProvider) -> AbstractSourceCodeProviderApi:
        """
        Return source code provider (like Github) using factory and respective type
        """
        return get_source_code_provider(repository_provider_type, self.settings)
