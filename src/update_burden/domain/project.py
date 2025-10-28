
"""
Module to define abstract Package
"""
from typing import Dict
from .version import normalize_version
from .common import ProjectPackagesRegistryKind


class Project:
    """Class for a package."""
    package_registry: ProjectPackagesRegistryKind
    name: str
    dependencies: Dict[str, str]
    dev_dependencies: Dict[str, str]

    def __init__(self,
                 package_registry: ProjectPackagesRegistryKind,
                 name: str,
                 dependencies: Dict[str, str],
                 dev_dependencies: Dict[str, str]):

        self.package_registry = package_registry
        self.name = name
        self.dependencies = dependencies
        self.dev_dependencies = dev_dependencies

    def __repr__(self):
        return f"""{self.package_registry} Package(
  name='{self.name}'
  dependencies={self.dependencies}
)"""

    def installed_package_version(self, package: str):
        """
        Get installed version of a package.
        """
        version = None
        if package in self.dependencies:
            version = self.dependencies[package]
        elif package in self.dev_dependencies:
            version = self.dev_dependencies[package]

        return normalize_version(version)
