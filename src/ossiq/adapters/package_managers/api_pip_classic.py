"""
Support for classic pip requirements.txt files (without pyproject.toml).

This adapter handles legacy Python projects that use simple requirements.txt
files with pinned versions (package==version format).
"""

import os
import re
from collections import namedtuple

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.adapters.package_managers.utils import normalize_pep503_name
from ossiq.domain.common import ConstraintType
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import PIP_CLASSIC, PackageManagerType
from ossiq.domain.project import ConstraintSource, Dependency, Project
from ossiq.domain.version import normalize_version
from ossiq.settings import Settings

PipClassicProject = namedtuple("PipClassicProject", ["manifest"])

# Compiled regex patterns for performance (avoid recompilation in loops)
# Matches lines to skip: pip options (excluding -c), VCS deps, URL deps
_SKIP_LINE_PATTERN = re.compile(
    r"^("
    r"-[a-z\-]|"  # Pip options like -e, --editable, -r, --requirement, etc.
    r"(git|hg|svn|bzr)\+|"  # VCS dependencies (git+, hg+, svn+, bzr+)
    r"(https?|file)://"  # URL dependencies (http://, https://, file://)
    r")",
    re.IGNORECASE,
)
# Matches -c <file> constraint file directives
_CONSTRAINT_FILE_PATTERN = re.compile(r"^-c\s+(.+)$", re.IGNORECASE)
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

    @staticmethod
    def _load_constraint_file(path: str, constraint_names: set[str], visited: set[str] | None = None) -> None:
        """
        Read a pip constraints file and accumulate normalised package names into constraint_names.

        Handles recursive -c includes with a visited-file guard to prevent infinite loops.
        Only package name lines are collected; version specifiers are intentionally ignored
        because the constraint is applied at resolution time — what matters for tagging is
        *which* package is constrained, not the specific range.
        """
        if visited is None:
            visited = set()
        abs_path = os.path.realpath(path)
        if abs_path in visited:
            return
        visited.add(abs_path)

        try:
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
        except (FileNotFoundError, UnicodeDecodeError):
            return  # Silently skip unreadable constraint files

        for raw_line in lines:
            line = raw_line.split("#")[0].strip()
            if not line:
                continue
            # Recurse into nested -c includes
            c_match = _CONSTRAINT_FILE_PATTERN.match(line)
            if c_match:
                nested_path = os.path.join(os.path.dirname(path), c_match.group(1).strip())
                PackageManagerPythonPipClassic._load_constraint_file(nested_path, constraint_names, visited)
                continue
            # Skip all other pip options and non-package lines
            if _SKIP_LINE_PATTERN.match(line):
                continue
            constraint_names.add(normalize_pep503_name(line))

    def parse_requirements_txt(self) -> dict[str, Dependency]:
        """
        Parse requirements.txt file for pinned dependencies.

        Only processes lines with pinned versions (==).
        Skips editable installs, VCS dependencies, URL dependencies,
        and range specifiers. Follows -c <file> constraint directives and
        tags the corresponding packages with ConstraintType.ADDITIVE.

        Returns:
            Dictionary of dependencies {package_name: Dependency}
        """
        project_files = self.project_files(self.project_path)
        manifest_dir = os.path.dirname(project_files.manifest)
        dependencies: dict[str, Dependency] = {}
        constraint_names: set[str] = set()

        lines = self._read_requirements_lines(project_files.manifest)

        for line in lines:
            # Remove inline comments
            if "#" in line:
                line = line.split("#")[0].strip()

            if not line:
                continue

            # Intercept -c <file> before the general skip pattern
            c_match = _CONSTRAINT_FILE_PATTERN.match(line)
            if c_match:
                constraint_path = os.path.join(manifest_dir, c_match.group(1).strip())
                self._load_constraint_file(constraint_path, constraint_names)
                continue

            if _SKIP_LINE_PATTERN.match(line):
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
                canonical_name=package_name,
                version_installed=version,
                version_defined=f"=={version_spec}",  # Preserve original spec
                categories=[],  # No categories in classic requirements.txt,
                constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="requirements.txt"),
            )

        # Second pass: tag packages that appear in constraint files
        if constraint_names:
            manifest_basename = os.path.basename(project_files.manifest)
            for pkg_name, dep in dependencies.items():
                if normalize_pep503_name(pkg_name) in constraint_names:
                    dep.constraint_info = ConstraintSource(
                        type=ConstraintType.ADDITIVE,
                        source_file=manifest_basename,
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
            canonical_name=project_package_name,
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
