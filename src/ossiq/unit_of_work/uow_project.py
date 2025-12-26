"""
Package Unit Of Work pattern to isolate
I/O for external sources
"""

from ossiq.adapters.api import create_cve_database, create_package_registry_api, create_source_code_provider
from ossiq.adapters.api_interfaces import AbstractSourceCodeProviderApi
from ossiq.adapters.package_managers.api import create_package_managers
from ossiq.domain.common import ProjectPackagesRegistry, RepositoryProvider
from ossiq.domain.exceptions import UnknownProjectPackageManager
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
        narrow_package_manager: ProjectPackagesRegistry | None = None,
        production: bool = False,
    ):
        """
        Takes a single package details pulled from
        """
        super().__init__()

        self.project_path = project_path
        self.settings = settings
        self.production = production
        self.narrow_package_registry = narrow_package_manager
        self.cve_database = create_cve_database()

        # set up values before creation
        self.package_manager = None
        self.package_registry = None

    def __enter__(self):
        """
        Initialize actual instances of respective clients (and other stuff when needed)
        """

        packages_managers = create_package_managers(self.project_path, self.settings)

        if not packages_managers:
            raise UnknownProjectPackageManager(f"Unable to identify Package Manager for project at {self.project_path}")

        if self.narrow_package_registry:
            self.packages_manager = next(
                (
                    manager
                    for manager in packages_managers
                    if manager.package_manager_type.ecosystem == self.narrow_package_registry
                ),
                None,
            )
        else:
            self.packages_manager = next(packages_managers)

        self.packages_registry = create_package_registry_api(self.packages_manager.package_manager_type.ecosystem)

    def __exit__(self, *args):
        pass

    def get_source_code_provider(self, repository_provider_type: RepositoryProvider) -> AbstractSourceCodeProviderApi:
        """
        Return source code provider (like Github) using factory and respective type
        """
        return create_source_code_provider(repository_provider_type, self.settings)
