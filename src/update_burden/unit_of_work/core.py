"""
Different types of abstract Unit of Works
"""

import abc

from update_burden.adapters.api_interfaces import (
    AbstractPackageRegistryApiClient,
    AbstractSourceCodeApiClient
)
from update_burden.domain.common import (
    RepositoryProviderType,
    PackageRegistryType
)
from update_burden.config import Settings


class AbstractPackageUnitOfWork(abc.ABC):
    """
    Abstract Unit of Work definition for Package services
    """

    settings: Settings
    package_name: str
    installed_package_version: str

    repository_provider_type: RepositoryProviderType
    packages_registry_type: PackageRegistryType

    repository_provider: AbstractSourceCodeApiClient
    packages_registry: AbstractPackageRegistryApiClient

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
