"""
Interfaces related to external APIs
"""

import abc
from collections.abc import Iterable

from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.cve import CVE
from ossiq.domain.ecosystem import PackageManagerType
from ossiq.domain.package import Package
from ossiq.domain.project import Project
from ossiq.settings import Settings

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
    def repository_versions(self, repository: Repository, package_versions: list[PackageVersion]):
        raise NotImplementedError

    @abc.abstractmethod
    def __repr__(self):
        raise NotImplementedError


class AbstractPackageRegistryApi(abc.ABC):
    """
    Abstract client to communicate with package registries like PyPi or NPM
    """

    settings: Settings
    registry: ProjectPackagesRegistry
    package_registry_ecosystem: ProjectPackagesRegistry

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
    def __repr__(self):
        raise NotImplementedError


class AbstractCveDatabaseApi(abc.ABC):
    """
    Abstract client to communicate with CVEs repositories like osv.dev or github CVE APIs
    """

    @abc.abstractmethod
    def get_cves_for_package(self, package: Package, version: PackageVersion) -> set[CVE]:
        """
        Method to return a particular CVE info
        """
        raise NotImplementedError

    @abc.abstractmethod
    def __repr__(self):
        raise NotImplementedError


class AbstractPackageManagerApi(abc.ABC):
    """
    Abstract Package Manager to extract installed versions
    of packages from different package managers.
    """

    settings: Settings
    package_manager_type: PackageManagerType
    project_path: str

    @staticmethod
    @abc.abstractmethod
    def has_package_manager(project_path: str) -> bool:
        """
        Detect that package mangager is used in a project_path
        """
        pass

    @abc.abstractmethod
    def project_info(self) -> Project:
        """
        Extract project dependencies using file format from a specific
        package manager.
        """
        pass
