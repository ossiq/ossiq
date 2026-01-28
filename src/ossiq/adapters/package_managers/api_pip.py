"""
Support of pylock.toml package manager (PEP 751)
"""

import os
import re
import tomllib
from collections import namedtuple
from collections.abc import Callable, Iterable

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.adapters.package_managers.dependency_tree import BaseDependencyResolver
from ossiq.adapters.package_managers.utils import find_lockfile_parser
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import PIP, PackageManagerType
from ossiq.domain.project import Dependency, Project
from ossiq.settings import Settings

PylockProject = namedtuple("PylockProject", ["manifest", "lockfile"])


class PyLockResolver(BaseDependencyResolver):
    """
    Concrete resolver for pylock.toml (and uv-style) lockfiles.

    Handles the [[package]] list format where dependencies are
    provided as a list of name/version maps.
    """

    def get_all_packages(self) -> Iterable[dict]:
        """Returns the list of packages defined under the [[package]] header."""
        return self.raw_data.get("package", [])

    def extract_package_identity(self, pkg_data: dict) -> tuple[str, str]:
        """Extracts name and the specific installed version."""
        return pkg_data["name"], pkg_data["version"]

    def extract_package_metadata(self, pkg_data: dict) -> tuple[str | None, str | None, str | None]:
        """
        Extracts source details, environment markers, and the nominal requirement.
        """
        # Source can be a string or a dict like { registry = "..." } or { git = "..." }
        source_val = pkg_data.get("source")
        source = None
        if isinstance(source_val, dict):
            # Extract the first available value from the source dict
            source = next(iter(source_val.values()), None)
        elif isinstance(source_val, str):
            source = source_val

        marker = pkg_data.get("marker")

        # Pulling version_defined from the metadata block if present
        v_def = pkg_data.get("metadata", {}).get("version_spec")

        return source, marker, v_def

    def get_raw_dependencies(self, pkg_data: dict) -> Iterable[dict]:
        """Returns the list of dependency objects."""
        return pkg_data.get("dependencies", [])

    def extract_dependency_identity(self, dep_data: dict) -> tuple[str, str | None]:
        """
        In pylock, a dependency entry is usually: { name = "requests" }
        Sometimes it includes a version: { name = "requests", version = "2.31.0" }
        """
        return dep_data["name"], dep_data.get("version")


class PackageManagerPythonPip(AbstractPackageManagerApi):
    """
    Package Manager adapter for pylock.toml (PEP 751) lockfile format.

    Cross-references pyproject.toml to identify direct dependencies since
    pylock.toml does not include a project package entry.
    """

    settings: Settings
    package_manager_type: PackageManagerType = PIP
    project_path: str

    # Dynamic mapping between pylock lockfile versions
    # Note: lock-version is a string "1.0" in pylock.toml, unlike UV's integers
    supported_versions = {'lock_version == "1.0"': "parse_lockfile_v1_0"}

    @staticmethod
    def project_files(project_path: str) -> PylockProject:
        return PylockProject(
            os.path.join(project_path, PIP.primary_manifest.name),
            # NOTE: we know for sure that for PYLOCK lockfile is never None,
            # hence [possibly-missing-attribute] warning is False Positive here
            os.path.join(project_path, PIP.lockfile.name),  # type: ignore
        )

    @staticmethod
    def has_package_manager(project_path: str) -> bool:
        """
        Detect that pylock package manager is used in a project_path.
        Requires both pyproject.toml and pylock.toml.
        """
        project_files = PackageManagerPythonPip.project_files(project_path)

        if os.path.exists(project_files.manifest) and os.path.exists(project_files.lockfile):
            return True

        return False

    def __init__(self, project_path: str, settings: Settings):
        super().__init__()
        self.settings = settings
        self.project_path = project_path

        # Validate that there's handler for pylock version
        for version_condition, version_handler in self.supported_versions.items():
            if not getattr(self, version_handler, None):
                raise TypeError(
                    f"There's no handler for {version_handler} for the version condition: {version_condition}"
                )

    @staticmethod
    def normalize_package_name(name: str) -> str:
        """
        Normalize package name according to PEP 503.

        PyPI package names are case-insensitive and treat hyphens/underscores
        equivalently. This normalization ensures matching between pyproject.toml
        dependency names (which may include extras) and pylock.toml package names.

        Examples:
            "requests[security]" -> "requests"
            "requests>=2.31.0" -> "requests"
            "Django-REST-Framework" -> "django-rest-framework"
            "some_package" -> "some-package"
        """
        # First, extract package name from dependency specification
        # Dependency specs can include version constraints (>=, ==, ~=, etc.)
        # Split on common version operators to get just the package name
        for operator in [">=", "<=", "==", "!=", "~=", ">", "<", "@"]:
            if operator in name:
                name = name.split(operator)[0]
                break

        # Remove extras specification (e.g., "requests[security]" -> "requests")
        name = re.sub(r"\[.*\]", "", name)

        # Convert to lowercase and replace underscores with hyphens
        name = name.lower().replace("_", "-")

        return name.strip()

    def parse_lockfile_v1_0(
        self,
        direct_dependencies: set[str],
        optional_dependencies_map: dict[str, list[str]],
        pylock_data: dict,
    ) -> Dependency:
        """
        Lockfile parser for pylock.toml lock-version "1.0"

        Args:
            direct_dependencies: Set of normalized package names from [project.dependencies]
            optional_dependencies_map: Map of category -> list of normalized package names
            pylock_data: Parsed pylock.toml data

        Returns:
            Tuple of (dependencies, optional_dependencies) dictionaries
        """

        resolver = PyLockResolver(pylock_data)
        root_node = resolver.build_graph(None)
        if not root_node:
            raise ValueError("Failed to parse pylock lockfile")

        return root_node

    def get_lockfile_parser(self, lock_version: str | None) -> Callable[..., Dependency]:
        """
        Find and return lockfile parser instance based on lock-version field.
        """

        context = {"lock_version": lock_version}

        handler_name = find_lockfile_parser(self.supported_versions, context)
        if not handler_name or not hasattr(self, handler_name):
            raise PackageManagerLockfileParsingError(f"There's no parser for pylock.toml lock-version `{lock_version}`")

        return getattr(self, handler_name)

    def load_pyproject_data(self):
        """
        Read and parse project-related data from both pyproject.toml and pylock.toml
        """
        project_files = PackageManagerPythonPip.project_files(self.project_path)

        try:
            with open(project_files.manifest, "rb") as f:
                pyproject_data = tomllib.load(f)
            with open(project_files.lockfile, "rb") as f:
                pylock_data = tomllib.load(f)
        except (FileNotFoundError, tomllib.TOMLDecodeError) as e:
            raise PackageManagerLockfileParsingError("Failed to read pylock project files") from e

        return pyproject_data, pylock_data

    def extract_pyproject_dependencies(self, pyproject_data: dict) -> tuple[set[str], dict[str, list[str]]]:
        """
        Extract direct and optional dependencies from pyproject.toml.

        Returns:
            Tuple of (direct_dependencies_set, optional_dependencies_map)
            where optional_dependencies_map is {category: [normalized_package_names]}
        """

        project_section = pyproject_data.get("project", {})

        # Extract direct dependencies
        direct_deps_raw = project_section.get("dependencies", [])
        direct_dependencies = {self.normalize_package_name(dep) for dep in direct_deps_raw}

        # Extract optional dependencies by category
        optional_deps_raw = project_section.get("optional-dependencies", {})
        optional_dependencies_map = {}

        for category, deps_list in optional_deps_raw.items():
            normalized_deps = [self.normalize_package_name(dep) for dep in deps_list]
            optional_dependencies_map[category] = normalized_deps

        return direct_dependencies, optional_dependencies_map

    def project_info(self) -> Project:
        """
        Extract project dependencies by cross-referencing pyproject.toml
        with pylock.toml to identify direct vs transitive dependencies.
        """

        pyproject_data, pylock_data = self.load_pyproject_data()

        # Extract project name (fallback to directory basename)
        project_package_name = pyproject_data.get("project", {}).get("name", os.path.basename(self.project_path))

        # Extract direct and optional dependencies from pyproject.toml
        direct_dependencies, optional_dependencies_map = self.extract_pyproject_dependencies(pyproject_data)

        # Get the appropriate parser based on lock-version
        lockfile_parser = self.get_lockfile_parser(pylock_data.get("lock-version", None))

        # Parse lockfile with cross-reference data
        dependency_tree = lockfile_parser(  # type: ignore
            direct_dependencies, optional_dependencies_map, pylock_data
        )

        return Project(
            package_manager_type=self.package_manager_type,
            name=project_package_name,
            project_path=self.project_path,
            dependency_tree=dependency_tree,
        )

    def __repr__(self):
        return f"{self.package_manager_type.name} Package Manager"
