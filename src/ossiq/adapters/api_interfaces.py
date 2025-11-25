"""
Interfaces related to external APIs
"""

import abc
from typing import Iterable, List

from ossiq.domain.package import Package
from ossiq.domain.project import Project

from ..domain.repository import Repository
from ..domain.version import PackageVersion


class AbstractSourceCodeProviderApi(abc.ABC):
    """
    Abstract client to communicate with source code repositories like GitHub    
    """

    @abc.abstractmethod
    def repository_info(self, repository_url: str):
        raise NotImplementedError

    @abc.abstractmethod
    def repository_versions(self, repository: Repository, package_versions: List[PackageVersion]):
        raise NotImplementedError

    @abc.abstractmethod
    def __repr__(self):
        raise NotImplementedError


class AbstractPackageRegistryApi(abc.ABC):
    """
    Abstract client to communicate with package registries like PyPi or NPM
    """

    @abc.abstractmethod
    def package_info(self, package_name: str) -> Package:
        """
        Get a particular package info
        """
        raise NotImplementedError

    @abc.abstractmethod
    def package_versions(self, package_name: str) -> Iterable[PackageVersion]:
        """
        Get a particular package versions between what is installed
        currently in the project and the latest version available
        """
        raise NotImplementedError

    @abc.abstractmethod
    def project_info(self, project_path: str) -> Project:
        """
        Method to return a particular Project info
        with all installed dependencies with their versions
        """
        raise NotImplementedError

    @abc.abstractmethod
    def __repr__(self):
        raise NotImplementedError
