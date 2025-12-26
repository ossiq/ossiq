"""
Different types of abstract Unit of Works
"""

import abc

from ossiq.adapters.api_interfaces import (
    AbstractCveDatabaseApi,
    AbstractPackageManagerApi,
    AbstractPackageRegistryApi,
    AbstractSourceCodeProviderApi,
)
from ossiq.domain.common import ProjectPackagesRegistry, RepositoryProvider
from ossiq.settings import Settings


class AbstractProjectUnitOfWork(abc.ABC):
    """
    Abstract Unit of Work definition for Package services
    """

    settings: Settings
    project_path: str
    narrow_package_manager: ProjectPackagesRegistry | None
    packages_manager: AbstractPackageManagerApi | None
    packages_registry: AbstractPackageRegistryApi | None
    cve_database: AbstractCveDatabaseApi
    production: bool

    @abc.abstractmethod
    def get_source_code_provider(self, repository_provider_type: RepositoryProvider) -> AbstractSourceCodeProviderApi:
        """
        Method to get source code provider by its type. The point here is that
        single project has multiple package installed and each package
        might come from different source code providers (Github, Bitbucket, etc.)
        """
        raise NotImplementedError("Source Code Provider getter not implemented")

    def __enter__(self):
        raise NotImplementedError("Enter not implemented")

    def __exit__(self, *args):
        raise NotImplementedError("Exit not implemented")
