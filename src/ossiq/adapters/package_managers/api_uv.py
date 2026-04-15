"""
Support of UV package manager
"""

import os
import tomllib
from collections import namedtuple
from collections.abc import Callable, Iterable

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.adapters.package_managers.dependency_tree import BaseDependencyResolver
from ossiq.adapters.package_managers.utils import find_lockfile_parser, normalize_pep503_name
from ossiq.domain.common import ConstraintType
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import UV, PackageManagerType
from ossiq.domain.project import ConstraintSource, Dependency, Project
from ossiq.domain.version import classify_pypi_specifier
from ossiq.settings import Settings

UvProject = namedtuple("UvProject", ["manifest", "lockfile"])


class UVResolverV1R3(BaseDependencyResolver):
    """
    Concrete resolver for uv.lock files.
    """

    def classify_constraint(self, spec: str | None) -> ConstraintType:
        return classify_pypi_specifier(spec)

    def build_initial_dependency(
        self,
        name: str,
        canonical_name: str,
        version_installed: str,
        source: str | None,
        required_engine: str | None,
        version_defined: str | None,
    ):
        return Dependency(
            name=name,
            canonical_name=canonical_name,
            version_installed=version_installed,
            source=source,
            required_engine=required_engine,
            version_defined=version_defined,
            constraint_info=ConstraintSource(
                type=classify_pypi_specifier(version_defined),
                source_file="pyproject.toml",
            ),
        )

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

        return source, marker, None

    def get_raw_dependencies(self, pkg_data: dict) -> Iterable[tuple[str | None, Iterable[dict]]]:
        metadata = pkg_data.get("metadata", {})

        # Specifiers for regular deps live in [package.metadata].requires-dist
        requires_dist = metadata.get("requires-dist", [])
        dist_specifiers: dict[str, str | None] = {e["name"]: e.get("specifier") for e in requires_dist}

        # Specifiers for optional/dev deps live in [package.metadata.requires-dev].<group>
        dev_specifiers: dict[str, dict[str, str | None]] = {
            group: {e["name"]: e.get("specifier") for e in entries}
            for group, entries in metadata.get("requires-dev", {}).items()
        }

        def enrich(deps: list[dict], spec_map: dict[str, str | None]) -> list[dict]:
            if not spec_map:
                return deps
            return [
                {**dep, "specifier": spec_map[dep["name"]]}
                if dep["name"] in spec_map and dep.get("specifier") is None
                else dep
                for dep in deps
            ]

        if pkg_data.get("optional-dependencies", {}):
            for category, deps in pkg_data["optional-dependencies"].items():
                yield category, enrich(list(deps), dev_specifiers.get(category, {}))

        yield None, enrich(pkg_data.get("dependencies", []), dist_specifiers)

    def extract_dependency_identity(self, dep_data: dict) -> tuple[str, str | None]:
        # UV dependency entries: {name = "requests", specifier = ">=2.31.0"}
        # The 'specifier' key carries the version constraint; not all entries have it.
        return dep_data["name"], dep_data.get("specifier")


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

    def get_lockfile_parser(self, version: int | str | None, revision: int | str | None) -> Callable[..., Dependency]:
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

    @staticmethod
    def constraint_dependencies_setting(
        dep_tree: Dependency,
        constraint_names: set[str],
        override_names: set[str],
        source_file: str = "pyproject.toml",
    ) -> None:
        """Walk dep_tree recursively and set constraint_info on matching nodes."""
        for dep in {**dep_tree.dependencies, **dep_tree.optional_dependencies}.values():
            norm = normalize_pep503_name(dep.canonical_name)
            if norm in override_names:
                dep.constraint_info = ConstraintSource(type=ConstraintType.OVERRIDE, source_file=source_file)
            elif norm in constraint_names:
                dep.constraint_info = ConstraintSource(type=ConstraintType.ADDITIVE, source_file=source_file)
            else:
                dep.constraint_info = ConstraintSource(type=ConstraintType.DECLARED, source_file=source_file)
            PackageManagerPythonUv.constraint_dependencies_setting(dep, constraint_names, override_names, source_file)

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

        # Constraint/Override settings from [tool.uv] section
        uv_section = pyproject_data.get("tool", {}).get("uv", {})
        constraint_specs: list[str] = uv_section.get("constraint-dependencies", [])
        override_specs: list[str] = uv_section.get("override-dependencies", [])
        if constraint_specs or override_specs:
            constraint_names = {normalize_pep503_name(s) for s in constraint_specs}
            override_names = {normalize_pep503_name(s) for s in override_specs}
            self.constraint_dependencies_setting(dependency_tree, constraint_names, override_names)

        return Project(
            package_manager_type=self.package_manager_type,
            name=project_package_name,
            project_path=self.project_path,
            dependency_tree=dependency_tree,
        )

    def __repr__(self):
        return f"{self.package_manager_type.name} Package Manager"
