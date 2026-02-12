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

# Compiled regex patterns for performance (avoid recompilation in loops)
# Matches lines to skip: pip options, VCS deps, URL deps
_SKIP_LINE_PATTERN = re.compile(
    r"^("
    r"-[a-z\-]|"  # Pip options like -e, --editable, -r, --requirement, etc.
    r"(git|hg|svn|bzr)\+|"  # VCS dependencies (git+, hg+, svn+, bzr+)
    r"(https?|file)://"  # URL dependencies (http://, https://, file://)
    r")",
    re.IGNORECASE,
)
# Matches pinned dependencies: package==version or package[extras]==version
_PINNED_DEPENDENCY_PATTERN = re.compile(r"^([a-zA-Z0-9._\-\[\]]+)==([^\s;]+)")
# Matches extras specification in package names
_EXTRAS_PATTERN = re.compile(r"\[.*\]")


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

    def _read_requirements_lines(self, manifest_path: str) -> list[str]:
        """
        Read and return lines from requirements.txt file.

        Args:
            manifest_path: Path to requirements.txt file

        Returns:
            List of lines from the file

        Raises:
            PackageManagerLockfileParsingError: If file not found or decode fails
        """
        try:
            with open(manifest_path, encoding="utf-8") as f:
                return f.readlines()
        except FileNotFoundError as e:
            raise PackageManagerLockfileParsingError(f"requirements.txt not found at {manifest_path}") from e
        except UnicodeDecodeError as e:
            raise PackageManagerLockfileParsingError(f"Failed to decode requirements.txt: {e}") from e

    @staticmethod
    def _parse_pinned_requirement(line: str) -> tuple[str, str] | None:
        """
        Extract package specification and version from pinned requirement line.

        Args:
            line: Preprocessed requirement line

        Returns:
            Tuple of (package_spec, version_spec) if line is pinned requirement,
            None otherwise.

        Examples:
            "requests==2.31.0" -> ("requests", "2.31.0")
            "Django[extra]==4.2.0" -> ("Django[extra]", "4.2.0")
            "package>=1.0.0" -> None (not pinned)
        """
        match = _PINNED_DEPENDENCY_PATTERN.match(line)
        if not match:
            return None
        return match.group(1), match.group(2)

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

        lines = self._read_requirements_lines(project_files.manifest)

        for line in lines:
            # Remove inline comments
            if "#" in line:
                line = line.split("#")[0].strip()

            if not line or bool(_SKIP_LINE_PATTERN.match(line)):
                continue

            # Parse pinned dependency: package==version or package[extras]==version
            parsed = self._parse_pinned_requirement(line)
            if not parsed:
                # Not a pinned dependency, skip (could be >=, ~=, or other specifier)
                continue

            package_spec, version_spec = parsed

            # Normalize package name (removes extras, lowercases, etc.)
            package_name = _EXTRAS_PATTERN.sub("", package_spec).lower().replace("_", "-").strip()

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

        dependency_tree = Dependency(
            name=project_package_name,
            version_installed="",  # Not applicable for the project itself
            dependencies=dependencies,
            optional_dependencies={},
        )

        return Project(
            package_manager_type=self.package_manager_type,
            name=project_package_name,
            project_path=self.project_path,
            dependency_tree=dependency_tree,
        )

    def __repr__(self):
        return f"{self.package_manager_type.name} Package Manager"
