"""
Support of UV package manager
"""

import os
import tomllib
from collections import namedtuple
from collections.abc import Callable, Iterable

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.adapters.package_managers.dependency_tree import BaseDependencyResolver
from ossiq.adapters.package_managers.utils import find_lockfile_parser
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import UV, PackageManagerType
from ossiq.domain.project import Dependency, Project
from ossiq.settings import Settings

UvProject = namedtuple("UvProject", ["manifest", "lockfile"])


class UVResolverV1R3(BaseDependencyResolver):
    """
    Concrete resolver for uv.lock files.
    """

    def get_all_packages(self) -> Iterable[dict]:
        # UV stores packages in a top-level list [[package]]
        return self.raw_data.get("package", [])

    def extract_package_identity(self, pkg_data: dict) -> tuple[str, str]:
        return pkg_data["name"], pkg_data["version"]

    def extract_package_metadata(self, pkg_data: dict) -> tuple[str | None, str | None, str | None]:
        # UV sources are usually objects: source = { registry = "..." }
        source_data = pkg_data.get("source", {})
        source = source_data.get("registry") if isinstance(source_data, dict) else str(source_data)

        marker = pkg_data.get("marker")

        # Accessing version_defined from the metadata block
        v_def = pkg_data.get("metadata", {}).get("version_spec")

        return source, marker, v_def

    def get_raw_dependencies(self, pkg_data: dict) -> Iterable[tuple[str | None, Iterable[dict]]]:
        if pkg_data.get("optional-dependencies", {}):
            yield from pkg_data.get("optional-dependencies", {}).items()

        yield None, pkg_data.get("dependencies", [])

    def extract_dependency_identity(self, dep_data: dict) -> tuple[str, str | None]:
        # UV dependencies in the list are usually just {'name': '...'}
        return dep_data["name"], dep_data.get("version")


class PackageManagerPythonUv(AbstractPackageManagerApi):
    """
    Abstract Package Manager to extract installed versions
    of packages from different package managers.
    """

    settings: Settings
    package_manager_type: PackageManagerType = UV
    project_path: str

    # Dynamic mapping between UV lockfile versions
    supported_versions = {"version == 1 && revision >= 3": "parse_lockfile_v1_r3"}

    @staticmethod
    def project_files(project_path: str) -> UvProject:
        return UvProject(
            os.path.join(project_path, UV.primary_manifest.name),
            # NOTE: we know for sure that for UV lockfile is never None,
            # hence [possibly-missing-attribute] warning is False Positive here
            os.path.join(project_path, UV.lockfile.name),  # type: ignore
        )

    @staticmethod
    def has_package_manager(project_path: str) -> bool:
        """
        Detect that UV package manager is used in a project_path.
        """
        project_files = PackageManagerPythonUv.project_files(project_path)

        if os.path.exists(project_files.manifest) and os.path.exists(project_files.lockfile):
            return True

        return False

    def __init__(self, project_path: str, settings: Settings):
        super().__init__()
        self.settings = settings
        self.project_path = project_path

        # Validate that there's handler for UV version
        for version_condition, version_handler in self.supported_versions.items():
            if not getattr(self, version_handler, None):
                raise TypeError(
                    f"There's no handler for {version_handler} for the version condition: {version_condition}"
                )

    def parse_lockfile_v1_r3(self, project_package_name: str, uv_lock_data: dict) -> Dependency:
        """
        Lockfile parser for UV version `1` and revision `3`
        """

        resolver = UVResolverV1R3(uv_lock_data)
        root_node = resolver.build_graph(project_package_name)
        if not root_node:
            raise PackageManagerLockfileParsingError("Cannot parse UV lockfile")

        return root_node

    def get_lockfile_parser(self, version: str | None, revision: str | None) -> Callable[..., Dependency]:
        """
        Find and return lockfile parser instance
        """

        context = {"version": version, "revision": revision}

        handler_name = find_lockfile_parser(self.supported_versions, context)
        if not handler_name or not hasattr(self, handler_name):
            raise PackageManagerLockfileParsingError(
                f"There's no parser for UV version `{version}` and revision `{revision}`"
            )

        return getattr(self, handler_name)

    def load_pyproject_data(self):
        """
        Read and parse project-related data
        """
        project_files = PackageManagerPythonUv.project_files(self.project_path)

        try:
            with open(project_files.manifest, "rb") as f:
                pyproject_data = tomllib.load(f)
            with open(project_files.lockfile, "rb") as f:
                uv_lock_data = tomllib.load(f)
        except (FileNotFoundError, tomllib.TOMLDecodeError) as e:
            raise PackageManagerLockfileParsingError("Failed to read UV project files") from e

        return pyproject_data, uv_lock_data

    def project_info(self) -> Project:
        """
        Extract project dependencies using file format from a specific
        package manager.
        """

        pyproject_data, uv_lock_data = self.load_pyproject_data()
        project_package_name = pyproject_data.get("project", {}).get("name", os.path.basename(self.project_path))

        # NOTE: each lockfile could have different parser.
        # Which parser to use determined by version and revision
        # attributes from within lockfile itself.
        lockfile_parser = self.get_lockfile_parser(
            uv_lock_data.get("version", None), uv_lock_data.get("revision", None)
        )

        dependency_tree = lockfile_parser(project_package_name, uv_lock_data)

        return Project(
            package_manager_type=self.package_manager_type,
            name=project_package_name,
            project_path=self.project_path,
            dependency_tree=dependency_tree,
        )

    def __repr__(self):
        return f"{self.package_manager_type.name} Package Manager"
