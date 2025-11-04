"""
Package Unit Of Work pattern to isolate
I/O for external sources
"""
from update_burden.adapters.api import (
    get_package_registry,
    get_source_code_provider
)
from update_burden.adapters.api_interfaces import AbstractSourceCodeProviderApi
from update_burden.config import Settings
from update_burden.domain.common import ProjectPackagesRegistryKind
from .core import AbstractProjectUnitOfWork


class ProjectUnitOfWork(AbstractProjectUnitOfWork):
    """
    Practical implementation of an abstraction around a
    single installed package
    """

    def __init__(self,
                 settings: Settings,
                 project_path: str,
                 packages_registry_type: ProjectPackagesRegistryKind):
        """
        Takes a single package details pulled from 
        """
        self.project_path = project_path
        self.settings = settings
        self.packages_registry_type = packages_registry_type

    def __enter__(self):
        """
        Initialize actual instances of respective clients (and other stuff when needed)
        """
        self.packages_registry = get_package_registry(
            self.packages_registry_type
        )

    def __exit__(self, *args):
        pass

    def get_source_code_provider(
            self,
            repository_provider_type: str) -> AbstractSourceCodeProviderApi:
        """
        Return source code provider (like Github) using factory and respective type
        """
        return get_source_code_provider(
            repository_provider_type,
            self.settings
        )
