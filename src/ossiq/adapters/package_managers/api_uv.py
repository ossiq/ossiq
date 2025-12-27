"""
Support of UV package manager
"""

import os
import tomllib
from collections import defaultdict, namedtuple

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.adapters.package_managers.utils import find_lockfile_parser
from ossiq.domain.ecosystem import UV, PackageManagerType
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.project import Dependency, Project
from ossiq.settings import Settings

UvProject = namedtuple("UvProject", ["manifest", "lockfile"])


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
            os.path.join(project_path, UV.lockfile.name),  # ty: ignore
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

    def parse_lockfile_v1_r3(
        self, project_package_name: str, uv_lock_data: dict
    ) -> tuple[dict[str, Dependency], dict[str, Dependency]]:
        """
        Lockfile parser for UV version `1` and revision `3`
        """

        dependencies = {}
        optional_dependencies = {}

        main_package = next(
            (package for package in uv_lock_data.get("package", []) if package["name"] == project_package_name), None
        )

        if not main_package:
            raise PackageManagerLockfileParsingError("Cannot extract project package from UV lockfile")

        optional_dependencies_map = main_package.get("optional-dependencies", {})
        main_dependencies_set = set(package["name"] for package in main_package.get("dependencies", []))

        categories_map = defaultdict(list)
        for category, packages in optional_dependencies_map.items():
            for package in packages:
                categories_map[package["name"]].append(category)

        for package in uv_lock_data.get("package", []):
            name = package["name"]
            if name == project_package_name:
                continue

            dependency_instance = Dependency(
                name=name, version_installed=package["version"], categories=categories_map.get(name, [])
            )

            if name in main_dependencies_set:
                dependencies[name] = dependency_instance

            # NOTE: dependency could be in multiple categories at once!
            if name in categories_map:
                optional_dependencies[name] = dependency_instance

            # if name not in main_dependencies_set and name not in categories_map:
            # TODO: Handle transitive dependencies, no need for now

        return dependencies, optional_dependencies

    def get_lockfile_parser(
        self, version: str | None, revision: str | None
    ) -> callable[tuple[dict[str, Dependency], dict[str, Dependency]]] | None:
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

    def project_info(self) -> Project:
        """
        Extract project dependencies using file format from a specific
        package manager.
        """

        project_files = PackageManagerPythonUv.project_files(self.project_path)

        with open(project_files.manifest, "rb") as f:
            pyproject_data = tomllib.load(open(project_files.manifest, "rb"))

        with open(project_files.lockfile, "rb") as f:
            uv_lock_data = tomllib.load(f)

        project_package_name = pyproject_data.get("project", {}).get("name", os.path.basename(self.project_path))

        # NOTE: each lockfile could have different parser.
        # Which parser to use determined by version and revision
        # attributes from within lockfile itself.
        lockfile_parser = self.get_lockfile_parser(
            uv_lock_data.get("version", None), uv_lock_data.get("revision", None)
        )

        dependencies, optional_dependencies = lockfile_parser(project_package_name, uv_lock_data)  # ty: ignore

        return Project(
            package_manager_type=self.package_manager_type,
            name=project_package_name,
            project_path=self.project_path,
            dependencies=dependencies,
            optional_dependencies=optional_dependencies,
        )

    def __repr__(self):
        return f"{self.package_manager_type.name} Package Manager"
