"""
Interfaces related to external APIs
"""

import abc
from typing import Iterable, List

from update_burden.domain.package import Package

from ..domain.repository import Repository
from ..domain.version import PackageVersion


class AbstractSourceCodeApiClient(abc.ABC):
    """
    Abstract client to communicate with source code repositories like GitHub    
    """

    @abc.abstractmethod
    def repository_info(self, repository_url: str):
        raise NotImplementedError

    @abc.abstractmethod
    def repository_versions(self, repository: Repository, package_versions: List[PackageVersion]):
        raise NotImplementedError


class AbstractPackageRegistryApiClient(abc.ABC):
    """
    Abstract client to communicate with package registries like PyPi or NPM
    """

    @abc.abstractmethod
    def package_info(self, package_name: str) -> Package:
        raise NotImplementedError

    @abc.abstractmethod
    def package_versions(self, package_name: str) -> Iterable[PackageVersion]:
        raise NotImplementedError
