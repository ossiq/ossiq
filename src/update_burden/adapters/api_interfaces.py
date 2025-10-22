"""
Interfaces related to external APIs
"""

import abc
from typing import List

from ..domain.repository import Repository
from ..domain.version import PackageVersion
from ..config import Settings


class AbstractSourceCodeApiClient(abc.ABC):
    """
    Abstract client to communicate with source code repositories like GitHub    
    """

    @abc.abstractmethod
    def get_repository(self, repository_url: str):
        raise NotImplementedError

    @abc.abstractmethod
    def get_versions(self, repository: Repository, package_versions: List[PackageVersion]):
        raise NotImplementedError


class AbstractPackageRegistryApiClient(abc.ABC):
    """
    Abstract client to communicate with package registries like PyPi or NPM
    """
    @abc.abstractmethod
    def set_config(self, settings: Settings):
        raise NotImplementedError

    @abc.abstractmethod
    def get(self, reference):
        raise NotImplementedError
