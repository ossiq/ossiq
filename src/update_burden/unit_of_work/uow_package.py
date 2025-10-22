"""
Package Unit Of Work pattern to isolate
I/O for external sources
"""
from update_burden.adapters.api import SourceCodeApiClientFactory
from update_burden.config import Settings
from update_burden.domain.common import (
    RepositoryProviderType,
    PackageRegistryType
)
from .core import AbstractPackageUnitOfWork


class PackageUnitOfWork(AbstractPackageUnitOfWork):
    """
    Practical implementation of an abstraction around a
    single installed package
    """

    def __init__(self,
                 settings: Settings,
                 package_name: str,
                 installed_package_version: str,
                 repository_provider_type: RepositoryProviderType,
                 packages_registry_type: PackageRegistryType):
        """
        Takes a single package details pulled from 
        """
        self.settings = settings
        self.package_name = package_name
        self.installed_package_version = installed_package_version

        self.repository_provider_type = repository_provider_type
        self.packages_registry_type = packages_registry_type

    def __enter__(self):
        """
        Initialize actual instances of respective clients (and other stuff when needed)
        """
        self.repository_provider = SourceCodeApiClientFactory.get_client(
            self.repository_provider_type,
            self.settings
        )

        self.packages_registry = None

    def __exit__(self, *args):
        pass

    # def commit(self):
    #     pass

    # def rollback(self):
    #     pass
