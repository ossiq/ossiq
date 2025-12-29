"""
Support for classic pip requirements.txt files (without pyproject.toml).

This adapter handles legacy Python projects that use simple requirements.txt
files with pinned versions (package==version format).
"""

import os
import re
from collections import namedtuple

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import PIP_CLASSIC, PackageManagerType
from ossiq.domain.project import Dependency, Project
from ossiq.domain.version import normalize_version
from ossiq.settings import Settings

PipClassicProject = namedtuple("PipClassicProject", ["manifest"])


class PackageManagerPythonPipClassic(AbstractPackageManagerApi):
    """
    Package Manager adapter for classic pip requirements.txt files.

    Supports simple pinned dependency format (package==version).
    Does not require pyproject.toml.
    """

    settings: Settings
    package_manager_type: PackageManagerType = PIP_CLASSIC
    project_path: str

    @staticmethod
    def project_files(project_path: str) -> PipClassicProject:
        return PipClassicProject(manifest=os.path.join(project_path, PIP_CLASSIC.primary_manifest.name))

    @staticmethod
    def has_package_manager(project_path: str) -> bool:
        """
        Detect that classic pip requirements.txt is used in a project_path.
        Only requires requirements.txt to be present.
        """
        project_files = PackageManagerPythonPipClassic.project_files(project_path)
        return os.path.exists(project_files.manifest)

    def __init__(self, project_path: str, settings: Settings):
        super().__init__()
        self.settings = settings
        self.project_path = project_path

    @staticmethod
    def normalize_package_name(name: str) -> str:
        """
        Normalize package name according to PEP 503.

        PyPI package names are case-insensitive and treat hyphens/underscores
        equivalently. This normalization ensures consistency.

        Examples:
            "requests[security]" -> "requests"
            "Django-REST-Framework" -> "django-rest-framework"
            "some_package" -> "some-package"
        """
        # Remove extras specification (e.g., "requests[security]" -> "requests")
        name = re.sub(r"\[.*\]", "", name)

        # Convert to lowercase and replace underscores with hyphens
        name = name.lower().replace("_", "-")

        return name.strip()

    def parse_requirements_txt(self) -> dict[str, Dependency]:
        """
        Parse requirements.txt file for pinned dependencies.

        Only processes lines with pinned versions (==).
        Skips editable installs, VCS dependencies, URL dependencies,
        and range specifiers.

        Returns:
            Dictionary of dependencies {package_name: Dependency}
        """
        project_files = self.project_files(self.project_path)
        dependencies = {}

        try:
            with open(project_files.manifest, encoding="utf-8") as f:
                lines = f.readlines()
        except FileNotFoundError as e:
            raise PackageManagerLockfileParsingError(f"requirements.txt not found at {project_files.manifest}") from e
        except UnicodeDecodeError as e:
            raise PackageManagerLockfileParsingError(f"Failed to decode requirements.txt: {e}") from e

        for line in lines:
            # Strip whitespace and comments
            line = line.strip()

            # Remove inline comments
            if "#" in line:
                line = line.split("#")[0].strip()

            # Skip empty lines
            if not line:
                continue

            # Skip editable installs
            if line.startswith("-e") or line.startswith("--editable"):
                continue

            # Skip other pip options
            if line.startswith("-"):
                continue

            # Skip VCS dependencies (git+, hg+, svn+, bzr+)
            if re.match(r"^(git|hg|svn|bzr)\+", line):
                continue

            # Skip URL dependencies
            if line.startswith("http://") or line.startswith("https://") or line.startswith("file://"):
                continue

            # Parse pinned dependency: package==version or package[extras]==version
            # Pattern: package_name[optional_extras]==version
            match = re.match(r"^([a-zA-Z0-9._\-\[\]]+)==([^\s;]+)", line)

            if not match:
                # Not a pinned dependency, skip it
                # (Could be >=, ~=, or other specifier)
                continue

            package_spec = match.group(1)  # e.g., "requests" or "requests[security]"
            version_spec = match.group(2)  # e.g., "2.31.0"

            # Normalize package name (removes extras, lowercases, etc.)
            package_name = self.normalize_package_name(package_spec)

            # Normalize version (remove any remaining modifiers)
            version = normalize_version(version_spec)

            if not package_name or not version:
                # Skip invalid entries
                continue

            # Create dependency instance
            dependencies[package_name] = Dependency(
                name=package_spec,  # Keep original name with extras if present
                version_installed=version,
                version_defined=f"=={version_spec}",  # Preserve original spec
                categories=[],  # No categories in classic requirements.txt
            )

        return dependencies

    def project_info(self) -> Project:
        """
        Extract project dependencies from requirements.txt.

        Since requirements.txt doesn't distinguish between main and optional
        dependencies, all dependencies are treated as main dependencies.
        """
        # Parse dependencies from requirements.txt
        dependencies = self.parse_requirements_txt()

        # Project name: fallback to directory basename
        project_package_name = os.path.basename(self.project_path)

        return Project(
            package_manager_type=self.package_manager_type,
            name=project_package_name,
            project_path=self.project_path,
            dependencies=dependencies,
            optional_dependencies={},  # Classic requirements.txt has no optional deps
        )

    def __repr__(self):
        return f"{self.package_manager_type.name} Package Manager"
