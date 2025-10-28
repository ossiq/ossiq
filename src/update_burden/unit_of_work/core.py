"""
Different types of abstract Unit of Works
"""

import abc

from update_burden.adapters.api_interfaces import (
    AbstractPackageRegistryApi,
    AbstractSourceCodeProviderApi
)
from update_burden.domain.common import (
    RepositoryProviderType,
    ProjectPackagesRegistryKind
)
from update_burden.config import Settings


class AbstractProjectUnitOfWork(abc.ABC):
    """
    Abstract Unit of Work definition for Package services
    """

    settings: Settings
    project_path: str
    packages_registry_type: ProjectPackagesRegistryKind
    packages_registry: AbstractPackageRegistryApi

    @abc.abstractmethod
    def get_source_code_provider(
            self,
            repository_provider_type: RepositoryProviderType) -> AbstractSourceCodeProviderApi:
        """
        Method to get source code provider by its type. The point here is that
        single project has multiple package installed and each package
        might come from different source code providers (Github, Bitbucket, etc.)
        """
        raise NotImplementedError(
            "Source Code Provider getter not implemented")

    def __enter__(self):
        raise NotImplementedError("Enter not implemented")

    def __exit__(self, *args):
        raise NotImplementedError("Exit not implemented")

    # @abc.abstractmethod
    # def commit(self):
    #     raise NotImplementedError

    # @abc.abstractmethod
    # def rollback(self):
    #     raise NotImplementedError
