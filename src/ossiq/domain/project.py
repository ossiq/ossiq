"""
Module to define abstract Package
"""

from .common import PackageNotInstalled
from .ecosystem import PackageManagerType
from .version import normalize_version


class Project:
    """Class for a package."""

    package_manager: PackageManagerType
    name: str
    project_path: str | None
    dependencies: dict[str, str]
    dev_dependencies: dict[str, str]

    def __init__(
        self,
        package_manager: PackageManagerType,
        name: str,
        project_path: str,
        dependencies: dict[str, str],
        dev_dependencies: dict[str, str],
    ):
        self.package_manager = package_manager
        self.name = name
        self.project_path = project_path
        self.dependencies = dependencies
        self.dev_dependencies = dev_dependencies

    def __repr__(self):
        return f"""{self.package_manager.name} Package(
  name='{self.name}'
  dependencies={self.dependencies}
)"""

    def installed_package_version(self, package_name: str):
        """
        Get installed version of a package.
        """
        if package_name in self.dependencies:
            version = self.dependencies[package_name]
        elif package_name in self.dev_dependencies:
            version = self.dev_dependencies[package_name]
        else:
            raise PackageNotInstalled(f"Package {package_name} not found in project {self.name}")

        return normalize_version(version)

    @property
    def package_registry(self):
        return self.package_manager.ecosystem
