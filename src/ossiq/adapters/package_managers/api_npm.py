"""
Support of NPM package manager
"""

import json
import os
from collections import defaultdict, namedtuple
from collections.abc import Callable, Iterable

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.adapters.package_managers.dependency_tree import BaseDependencyResolver
from ossiq.adapters.package_managers.utils import find_lockfile_parser
from ossiq.domain.common import ConstraintType
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import NPM, PackageManagerType
from ossiq.domain.project import ConstraintSource, Dependency, Project
from ossiq.domain.version import classify_npm_specifier, normalize_version
from ossiq.settings import Settings

NpmProject = namedtuple("NpmProject", ["manifest", "lockfile"])

CATEGORIES_DEV = "development"
CATEGORIES_OPTIONAL = "optional"
CATEGORIES_PEER = "peer"
CATEGORIES_OVERRIDDEN = "overridden"


class NPMResolverV3(BaseDependencyResolver):
    """
    Concrete resolver for NPM v3 lockfiles.
    """

    def __init__(self, raw_data: dict):
        super().__init__(raw_data)
        root_entry = raw_data.get("packages", {}).get("", {})
        self.overrides, self._scope_paths = self._flatten_overrides(root_entry.get("overrides", {}))

    @staticmethod
    def _collect_overrides(
        overrides: dict,
        result: dict[str, str],
        scope_paths: dict[str, list[str]],
        current_path: list[str],
    ) -> None:
        """
        Recursively walk an npm overrides block, accumulating results in-place.

        Handles flat entries:   {"foo": "1.0.0"}
        Handles nested entries: {"foo": {".": "1.0.0", "bar": "2.0.0"}}
          "." is npm's self-reference — the version for "foo" itself.
        """
        for name, value in overrides.items():
            if isinstance(value, str):
                result[name] = value
                if current_path:
                    scope_paths[name] = list(current_path)
            elif isinstance(value, dict):
                if "." in value and isinstance(value["."], str):
                    result[name] = value["."]
                    if current_path:
                        scope_paths[name] = list(current_path)
                nested = {k: v for k, v in value.items() if k != "."}
                if nested:
                    NPMResolverV3._collect_overrides(nested, result, scope_paths, current_path + [name])

    @staticmethod
    def _flatten_overrides(overrides: dict) -> tuple[dict[str, str], dict[str, list[str]]]:
        """
        Flatten a nested npm overrides block into two flat mappings:
          - version_map:  {package_name: forced_version}
          - scope_paths:  {package_name: [ancestor, ...]} for scoped (nested) overrides

        Example:
            {"foo": "1.0.0"}
            -> ({"foo": "1.0.0"}, {})

            {"foo": {".": "1.0.0", "bar": "2.0.0"}}
            -> ({"foo": "1.0.0", "bar": "2.0.0"}, {"bar": ["foo"]})
        """
        result: dict[str, str] = {}
        scope_paths: dict[str, list[str]] = {}
        NPMResolverV3._collect_overrides(overrides, result, scope_paths, [])
        return result, scope_paths

    def classify_constraint(self, spec: str | None) -> ConstraintType:
        return classify_npm_specifier(spec)

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
                type=classify_npm_specifier(version_defined),
                source_file="package.json",
            ),
        )

    def build_graph(self, root_name: str) -> Dependency | None:
        root = super().build_graph(root_name)
        # Mark any package in the overrides dict with the "overridden" category and constraint_info
        for name in self.overrides:
            node = self.find_root(name)
            if node:
                if CATEGORIES_OVERRIDDEN not in node.categories:
                    node.categories.append(CATEGORIES_OVERRIDDEN)
                node.constraint_info = ConstraintSource(
                    type=ConstraintType.OVERRIDE,
                    source_file="package.json",
                    scope_path=self._scope_paths.get(name),
                )
        return root

    def get_all_packages(self) -> Iterable[dict]:
        packages = self.raw_data.get("packages", {})
        for path, data in packages.items():
            pkg_info = data.copy()
            pkg_info["_path"] = path
            yield pkg_info

    def extract_package_identity(self, pkg_data: dict) -> tuple[str, str]:
        path = pkg_data.get("_path", "")
        if path == "":
            # Root package: use the name field or lockfile top-level name
            name = pkg_data.get("name") or self.raw_data.get("name", "")
        else:
            # Non-root: always use the path component as identity.
            # This correctly handles npm aliases where the 'name' field holds the
            # real package name (e.g. "lodash") while the path key is the alias
            # (e.g. "node_modules/lodash-range-tilde").
            # For nested node_modules (e.g. "node_modules/rc-trigger/node_modules/rc-util"),
            # this yields the innermost package name ("rc-util"), consistent with
            # how dependencies reference it in the lockfile.
            name = path.split("node_modules/")[-1]
        version = pkg_data.get("version", "0.0.0")
        return name, version

    def get_raw_dependencies(self, pkg_data: dict) -> Iterable[tuple[str | None, Iterable[dict]]]:
        # NPM v3 uses 'dependencies' and 'devDependencies' inside the package block
        # NOTE: 'optionalDependencies' is also a common block in NPM!
        # NOTE: categories in lockfile takes PRECEDENCE over package.json

        yield None, [{"name": n, "version": c} for n, c in pkg_data.get("dependencies", {}).items()]
        for category, key in [
            (CATEGORIES_DEV, "devDependencies"),
            (CATEGORIES_OPTIONAL, "optionalDependencies"),
            (CATEGORIES_PEER, "peerDependencies"),
        ]:
            if key in pkg_data:
                yield category, [{"name": n, "version": c} for n, c in pkg_data[key].items()]

    def extract_canonical_name(self, pkg_data: dict) -> str | None:
        """
        Returns the canonical npm package name when the lockfile path uses an alias.

        For aliased entries like "node_modules/chalk-legacy" with {"name": "chalk"},
        returns "chalk". For non-aliased entries, returns None.
        """
        path = pkg_data.get("_path", "")
        if path == "":
            return None  # root package, not an alias
        path_name = path.split("node_modules/")[-1]
        lockfile_name = pkg_data.get("name")
        if lockfile_name and lockfile_name != path_name:
            return lockfile_name
        return None

    def extract_package_metadata(self, pkg_data: dict) -> tuple[str | None, str | None, str | None]:
        """
        NPM 'resolved' is the source URL.
        'engines' can be used as markers.
        """
        source = pkg_data.get("resolved")  # The registry URL or git link

        # Mapping engines (node version) to the marker concept
        engines = pkg_data.get("engines", {})
        node = engines.get("node")
        required_engine = f"node: {node}" if node else None

        # NPM doesn't store the original 'version_defined' inside the package
        # block itself, but rather in the parent's dependency list.
        v_def = None

        return source, required_engine, v_def

    def extract_dependency_identity(self, dep_data: dict) -> tuple[str, str | None]:
        """
        In NPM's dependency list, 'version' is actually the constraint (e.g., ^1.2.3).
        """
        return dep_data["name"], dep_data.get("version")


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

    @staticmethod
    def parse_npm_alias(version: str) -> tuple[str | None, str]:
        """
        Parse an npm alias specifier into (canonical_name, constraint).

        "npm:lodash@~4.17.0"   -> ("lodash",      "~4.17.0")
        "npm:chalk@4.1.2"      -> ("chalk",        "4.1.2")
        "npm:@scope/pkg@^1.0"  -> ("@scope/pkg",   "^1.0")
        "^4.18.0"              -> (None,            "^4.18.0")  (not an alias, pass-through)
        """
        if version.startswith("npm:"):
            without_prefix = version[4:]  # e.g. "chalk@4.1.2" or "@scope/pkg@^1.0.0"
            at_idx = without_prefix.rfind("@")
            if at_idx > 0:  # package name must be non-empty
                return without_prefix[:at_idx], without_prefix[at_idx + 1 :]
        return None, version

    def __init__(self, project_path: str, settings: Settings):
        super().__init__()
        self.settings = settings
        self.project_path = project_path

    def get_lockfile_parser(self, lockfile_version: int | None) -> Callable[..., Dependency] | None:
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
        lockfile_data: dict,
    ) -> Dependency:
        """
        Lockfile parser for NPM
        """
        resolver = NPMResolverV3(lockfile_data)
        dependency_tree = resolver.build_graph(lockfile_data["name"])

        # No dependencies - no analysis, something wrong
        if not dependency_tree or (not dependency_tree.dependencies and not dependency_tree.optional_dependencies):
            raise PackageManagerLockfileParsingError("Could not parse NPM lockfile")
        return dependency_tree

    def parse_package_json(self, project_data: dict) -> Dependency:
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
            # For npm alias specs like "npm:lodash@~4.17.0", extract the canonical
            # package name and constraint in one pass; plain versions pass through.
            canonical_name, constraint = PackageManagerJsNpm.parse_npm_alias(version)

            return Dependency(
                name=name,
                canonical_name=canonical_name or name,
                version_installed=normalize_version(constraint),
                version_defined=version,
                categories=categories_map.get(name, []),
                constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
            )

        dependencies = {
            name: create_dependency(name, version) for name, version in project_data.get("dependencies", {}).items()
        }

        optional_dependencies = {}
        for deps, _ in category_sources:
            for name, version in deps.items():
                if name not in dependencies and name not in optional_dependencies:
                    optional_dependencies[name] = create_dependency(name, version)

        return Dependency(
            name=project_data.get("name", ""),
            canonical_name=project_data.get("name", ""),
            version_installed=project_data.get("version", ""),
            dependencies=dependencies,
            optional_dependencies=optional_dependencies,
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
        )

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

        def create_project(dependency_tree: Dependency) -> Project:
            return Project(
                package_manager_type=self.package_manager_type,
                name=project_package_name,
                project_path=self.project_path,
                dependency_tree=dependency_tree,
            )

        # Exceptional case, no lockfile
        if not project_files.lockfile:
            return create_project(dependency_tree=self.parse_package_json(project_data))

        # Lockfile present, let's parse it
        with open(project_files.lockfile, encoding="utf-8") as f:
            lockfile_data = json.load(f)

        lockfile_parser = self.get_lockfile_parser(lockfile_data.get("lockfileVersion"))
        if not lockfile_parser:
            raise PackageManagerLockfileParsingError("Could not find a parser for the given lockfile version")

        return create_project(dependency_tree=lockfile_parser(lockfile_data))

    def __repr__(self):
        return f"{self.package_manager_type.name} Package Manager"
