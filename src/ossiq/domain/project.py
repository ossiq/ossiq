"""
Module to define abstract Package
"""

import re
from dataclasses import dataclass, field

from .common import PackageNotInstalled
from .packages_manager import PackageManagerType


@dataclass(frozen=True)
class Dependency:
    name: str
    # Factually installed version. Fallback to version_defined if there's no lockfile
    version_installed: str
    # Version, nominally defined in project requirements before resolution
    version_defined: str | None = None
    categories: list[str] = field(default_factory=lambda: [])


class Project:
    """Class for a package."""

    package_manager_type: PackageManagerType
    name: str
    project_path: str | None
    dependencies: dict[str, Dependency]
    # Optional dependencies with respective categories.
    # NOTE: one dependency could be in dependencies and
    # multiple categories of optional dependencies (1-to-Many link)
    optional_dependencies: dict[str, Dependency]

    def __init__(
        self,
        package_manager_type: PackageManagerType,
        name: str,
        project_path: str,
        dependencies: dict[str, Dependency],
        optional_dependencies: dict[str, Dependency],
    ):
        self.package_manager_type = package_manager_type
        self.name = name
        self.project_path = project_path
        self.dependencies = dependencies
        self.optional_dependencies = optional_dependencies

    def __repr__(self):
        return f"""{self.package_manager_type.name} Package(
  name='{self.name}'
  dependencies={self.dependencies}
)"""

    def installed_package_version(self, package_name: str):
        """
        Get installed version of a package.
        """
        if package_name in self.dependencies:
            version = self.dependencies[package_name].version_installed
        elif package_name in self.optional_dependencies:
            version = self.optional_dependencies[package_name].version_installed
        else:
            raise PackageNotInstalled(f"Package {package_name} not found in project {self.name}")

        return version

    @property
    def package_registry(self):
        return self.package_manager_type.package_registry


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
