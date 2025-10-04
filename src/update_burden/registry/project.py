
"""
Module to define abstract Package
"""
from typing import Dict
from .versions import normalize_version

PROJECT_TYPE_NPM, PROJECT_TYPE_PYPI = "NPM", "PYPI"


class Project:
    """Class for a package."""
    project_type: str
    name: str
    dependencies: Dict[str, str]
    dev_dependencies: Dict[str, str]

    def __init__(self, project_type: str, name: str,
                 dependencies: Dict[str, str],
                 dev_dependencies: Dict[str, str]):

        assert project_type in (
            PROJECT_TYPE_NPM, PROJECT_TYPE_PYPI), "Invalid project type"

        self.project_type = project_type
        self.name = name
        self.dependencies = dependencies
        self.dev_dependencies = dev_dependencies

    def __repr__(self):
        return f"""{self.project_type} Package(
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
