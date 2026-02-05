"""
Module to define abstract Package
"""

import re
from dataclasses import dataclass, field

from .common import PackageNotInstalled
from .packages_manager import PackageManagerType


@dataclass(order=True)
class Dependency:
    """
    Represents a Dependency with child (transitive) depenencies
    """

    name: str
    # Factually installed version. Fallback to version_defined if there's no lockfile
    version_installed: str
    # Version, nominally defined in project requirements before resolution
    version_defined: str | None = None
    source: str | None = None
    required_engine: str | None = None
    categories: list[str] = field(default_factory=list, compare=False)

    # list of direct dependencies for this particular dependency
    # NOTE: there's no segregation between Optional vs Non-Optional at this point
    dependencies: dict[str, "Dependency"] = field(default_factory=dict, compare=False, hash=False)
    optional_dependencies: dict[str, "Dependency"] = field(default_factory=dict, compare=False, hash=False)


class Project:
    """Class for a package."""

    package_manager_type: PackageManagerType
    name: str
    project_path: str | None

    dependency_tree: Dependency

    def __init__(
        self,
        package_manager_type: PackageManagerType,
        name: str,
        project_path: str,
        dependency_tree: Dependency,
    ):
        self.package_manager_type = package_manager_type
        self.name = name
        self.project_path = project_path
        self.dependency_tree = dependency_tree

    def __repr__(self):
        return f"""{self.package_manager_type.name} Package(
  name='{self.name}'
  dependencies={self.dependencies}
)"""

    def installed_package_version(self, package_name: str):
        """
        Get installed version of a package.
        """
        prod_package = self.dependencies.get(package_name, None)

        if prod_package:
            return prod_package.version_installed

        optional_package = self.optional_dependencies.get(package_name, None)

        if optional_package:
            return optional_package.version_installed

        raise PackageNotInstalled(f"Package {package_name} not found in project {self.name}")

    @property
    def package_registry(self):
        return self.package_manager_type.package_registry

    @property
    def dependencies(self):
        return self.dependency_tree.dependencies

    @property
    def optional_dependencies(self):
        return self.dependency_tree.optional_dependencies


def normalize_filename(source_name: str) -> str:
    """
    Normalize a source name (package name, directory name) to a valid filename component.
    """

    # Convert to lowercase for consistency
    normalized = source_name.lower()

    # Replace filesystem-unsafe characters, @, dots, and whitespace with underscore,
    # then collapse multiple consecutive underscores or hyphens.
    normalized = re.sub(r'[/\\:*?"<>|@.\s]+', "_", normalized)
    normalized = re.sub(r"_+", "_", normalized)

    normalized = normalized.strip("_-")

    if not normalized:
        normalized = "unnamed"

    return normalized
