"""
Support of NPM package manager
"""

import json
import os
from collections import defaultdict, namedtuple
from collections.abc import Callable
from dataclasses import replace
from itertools import chain

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.adapters.package_managers.utils import find_lockfile_parser
from ossiq.domain.ecosystem import NPM, PackageManagerType
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.project import Dependency, Project
from ossiq.domain.version import normalize_version
from ossiq.settings import Settings

NpmProject = namedtuple("NpmProject", ["manifest", "lockfile"])

CATEGORIES_DEV = "development"
CATEGORIES_OPTIONAL = "optional"
CATEGORIES_PEER = "peer"


class PackageManagerJsNpm(AbstractPackageManagerApi):
    """
    Abstract Package Manager to extract installed versions
    of packages from different package managers.
    """

    settings: Settings
    package_manager_type: PackageManagerType = NPM
    project_path: str

    # Dynamic mapping between NPM lockfile versions
    supported_versions: dict[str, str] = {"lockfileVersion == 3": "parse_lockfile_v3"}

    @staticmethod
    def project_files(project_path: str) -> NpmProject:
        # NOTE: we know for sure that for NPM.lockfile is never None,
        # hence [possibly-missing-attribute] warning is False Positive here
        lockfile = os.path.join(project_path, NPM.lockfile.name)  # ty: ignore

        if not os.path.exists(lockfile):
            lockfile = None

        return NpmProject(os.path.join(project_path, NPM.primary_manifest.name), lockfile)

    @staticmethod
    def has_package_manager(project_path: str) -> bool:
        """
        Detect that NPM package manager is used in a project_path.
        For now, lockfile is optional.
        """
        project_files = PackageManagerJsNpm.project_files(project_path)

        return os.path.exists(project_files.manifest)

    def __init__(self, project_path: str, settings: Settings):
        super().__init__()
        self.settings = settings
        self.project_path = project_path

    def get_lockfile_parser(
        self, lockfile_version: int | None
    ) -> Callable[..., tuple[dict[str, Dependency], dict[str, Dependency]]] | None:
        """
        Find and return lockfile parser instance
        """

        context = {"lockfileVersion": lockfile_version}

        handler_name = find_lockfile_parser(self.supported_versions, context)
        if not handler_name or not hasattr(self, handler_name):
            raise PackageManagerLockfileParsingError(f"There's no parser for NPM lockfile version `{lockfile_version}`")

        return getattr(self, handler_name)

    def parse_lockfile_v3(
        self,
        nominal_dependencies: dict[str, Dependency],
        nominal_optional_dependencies: dict[str, Dependency],
        lockfile_data: dict,
    ) -> tuple[dict[str, Dependency], dict[str, Dependency]]:
        """
        Lockfile parser for NPM
        """
        packages = lockfile_data.get("packages", {})
        main_package = packages.get("", None)

        if not main_package:
            raise PackageManagerLockfileParsingError("Cannot extract project package from NPM lockfile")

        # Go through nominal dependencies
        dependencies = {}
        optional_dependencies = {}

        for package_name, package_instance in chain(
            nominal_dependencies.items(), nominal_optional_dependencies.items()
        ):
            installed_package_name = f"node_modules/{package_name}"
            if installed_package_name not in packages:
                raise PackageManagerLockfileParsingError(
                    f"Couldn't resolve {package_name}: {installed_package_name} not found in lockfile/packages section"
                )
            installed_package = packages[installed_package_name]
            version = installed_package.get("version", None)

            if not version:
                raise PackageManagerLockfileParsingError(
                    f"Couldn't extract version for {package_name}: {installed_package}"
                )

            updated_package_instance = replace(
                package_instance,
                version_installed=version,
            )
            if package_name in nominal_dependencies:
                dependencies[package_name] = updated_package_instance

            if package_name in nominal_optional_dependencies:
                optional_dependencies[package_name] = updated_package_instance

        return dependencies, optional_dependencies

    def parse_package_json(self, project_data: dict) -> tuple[dict[str, Dependency], dict[str, Dependency]]:
        """
        Extracting dependencies and categories from package.json
        """

        categories_map = defaultdict(list)

        category_sources = [
            (project_data.get("devDependencies", {}), CATEGORIES_DEV),
            (project_data.get("peerDependencies", {}), CATEGORIES_PEER),
            (project_data.get("optionalDependencies", {}), CATEGORIES_OPTIONAL),
        ]

        for deps, category in category_sources:
            for package_name in deps:
                categories_map[package_name].append(category)

        def create_dependency(name: str, version: str) -> Dependency:
            return Dependency(
                name=name,
                version_installed=normalize_version(version),
                version_defined=version,
                categories=categories_map.get(name, []),
            )

        dependencies = {
            name: create_dependency(name, version) for name, version in project_data.get("dependencies", {}).items()
        }

        optional_dependencies = {}
        for deps, _ in category_sources:
            for name, version in deps.items():
                if name not in dependencies and name not in optional_dependencies:
                    optional_dependencies[name] = create_dependency(name, version)

        return dependencies, optional_dependencies

    def project_info(self) -> Project:
        """
        Extract project dependencies using file format from a specific
        package manager.
        """

        project_files = PackageManagerJsNpm.project_files(self.project_path)

        with open(project_files.manifest, encoding="utf-8") as f:
            project_data = json.load(f)
        lockfile_data = None

        fallback_name = os.path.basename(self.project_path)
        project_package_name = project_data.get("name", fallback_name)

        def create_project(
            dependencies: dict[str, Dependency], optional_dependencies: dict[str, Dependency]
        ) -> Project:
            return Project(
                package_manager_type=self.package_manager_type,
                name=project_package_name,
                project_path=self.project_path,
                dependencies=dependencies,
                optional_dependencies=optional_dependencies,
            )

        # Exceptional case, no lockfile
        if not project_files.lockfile:
            dependencies, optional_dependencies = self.parse_package_json(project_data)

            return create_project(
                dependencies=dependencies,
                optional_dependencies=optional_dependencies,
            )

        # Lockfile present, let's parse it
        with open(project_files.lockfile, encoding="utf-8") as f:
            lockfile_data = json.load(f)

        nominal_dependencies, nominal_optional_dependencies = self.parse_package_json(project_data)
        lockfile_parser = self.get_lockfile_parser(lockfile_data.get("lockfileVersion"))

        dependencies, optional_dependencies = lockfile_parser(
            nominal_dependencies, nominal_optional_dependencies, lockfile_data
        )  # ty: ignore

        return create_project(
            dependencies=dependencies,
            optional_dependencies=optional_dependencies,
        )

    def __repr__(self):
        return f"{self.package_manager_type.name} Package Manager"
