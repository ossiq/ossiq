"""
Support of NPM package manager
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from collections import defaultdict, namedtuple
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi, HelperSpec
from ossiq.adapters.package_managers.dependency_tree import BaseDependencyResolver
from ossiq.adapters.package_managers.utils import find_lockfile_parser
from ossiq.domain.common import ConstraintType
from ossiq.domain.exceptions import PackageManagerExecutionError, PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import NPM, PackageManagerType
from ossiq.domain.project import ConstraintSource, Dependency, Project
from ossiq.domain.version import classify_npm_specifier, normalize_version
from ossiq.settings import Settings

if TYPE_CHECKING:
    from ossiq.service.update import UpdatePlan


NpmProject = namedtuple("NpmProject", ["manifest", "lockfile"])

CATEGORIES_DEV = "development"
CATEGORIES_OPTIONAL = "optional"
CATEGORIES_PEER = "peer"
CATEGORIES_OVERRIDDEN = "overridden"

DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


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
        source = pkg_data.get("resolved")
        # FIXME: convert engines into something more consumable for the solver later
        node = parse_node_engine(pkg_data.get("engines"))
        required_engine = f"node: {node}" if node else None
        # NPM doesn't store the original 'version_defined' inside the package
        # block itself, but rather in the parent's dependency list.
        return source, required_engine, None

    def extract_dependency_identity(self, dep_data: dict) -> tuple[str, str | None]:
        """
        In NPM's dependency list, 'version' is actually the constraint (e.g., ^1.2.3).
        """
        return dep_data["name"], dep_data.get("version")


def parse_node_engine(engines: dict | list | None) -> str | None:
    """Extract the node engine constraint from an engines field (dict or list form)."""
    if isinstance(engines, dict):
        return engines.get("node")
    if isinstance(engines, list) and engines:
        return engines[0]
    return None


def make_manifest_dependency(name: str, version: str, categories: list[str]) -> Dependency:
    """Build a Dependency from a package.json entry (no lockfile needed)."""
    canonical_name, constraint = PackageManagerJsNpm.parse_npm_alias(version)
    return Dependency(
        name=name,
        canonical_name=canonical_name or name,
        version_installed=normalize_version(constraint),
        version_defined=version,
        categories=categories,
        constraint_info=ConstraintSource(type=classify_npm_specifier(constraint), source_file="package.json"),
    )


def build_optional_dependencies(
    category_sources: list[tuple[dict, str]],
    dependencies: dict[str, Dependency],
    categories_map: dict[str, list[str]],
) -> dict[str, Dependency]:
    """Build the optional_dependencies map from non-production sections of package.json."""
    result: dict[str, Dependency] = {}
    for deps, _ in category_sources:
        for dep_name, version in deps.items():
            if dep_name not in dependencies and dep_name not in result:
                result[dep_name] = make_manifest_dependency(dep_name, version, categories_map.get(dep_name, []))
    return result


def relax_spec(original_spec: str, recommended: str, pin_all: bool) -> str:
    """Return the final specifier for an updated direct dep.

    --pin-all writes the exact recommended version. Otherwise the original operator is kept and
    its floor bumped to the recommended version; specs without a ^/~ operator pin to exact. npm
    aliases (npm:pkg@range) are left untouched — bumping the inner constraint is unsupported.
    """
    s = original_spec.strip()
    if s.startswith("npm:"):
        return original_spec
    if pin_all:
        return recommended
    if s.startswith("^"):
        return f"^{recommended}"
    if s.startswith("~"):
        return f"~{recommended}"
    return recommended


def apply_direct_specs(pkg: dict, plan: UpdatePlan) -> None:
    """Write final direct-dep specifiers to pkg in-place.

    Updated deps are relaxed via relax_spec (or exact-pinned for forced/pin-all);
    deps not in the plan are left untouched.
    """
    direct_entries = {e.package_name: e for e in plan.direct_entries}
    for section in DEP_SECTIONS:
        for name, current_spec in list(pkg.get(section, {}).items()):
            entry = direct_entries.get(name)
            if entry is None:
                continue
            if entry.is_forced:
                pkg[section][name] = entry.recommended_version
            else:
                pkg[section][name] = relax_spec(current_spec, entry.recommended_version, plan.pin_all)


class PackageManagerJsNpm(AbstractPackageManagerApi):
    """
    Abstract Package Manager to extract installed versions
    of packages from different package managers.
    """

    settings: Settings
    package_manager_type: PackageManagerType = NPM
    project_path: str

    # Dynamic mapping between NPM lockfile versions
    supported_versions: dict[str, str] = {
        "lockfileVersion == 3": "parse_lockfile_v3",
        "lockfileVersion == 2": "parse_lockfile_v2",
    }

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

    def parse_lockfile_v2(self, lockfile_data: dict) -> Dependency:
        """Lockfile parser for NPM v2 (npm v7/v8 default).

        v2 carries the same flat packages map as v3, plus a legacy dependencies
        nested-tree for npm v6 back-compat. We parse via the packages section.
        """
        if "packages" not in lockfile_data:
            raise PackageManagerLockfileParsingError("NPM v2 lockfile is missing the 'packages' section")
        return self.parse_lockfile_v3(lockfile_data)

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
        """Extracting dependencies and categories from package.json."""
        category_sources = [
            (project_data.get("devDependencies", {}), CATEGORIES_DEV),
            (project_data.get("peerDependencies", {}), CATEGORIES_PEER),
            (project_data.get("optionalDependencies", {}), CATEGORIES_OPTIONAL),
        ]
        categories_map: dict[str, list[str]] = defaultdict(list)
        for deps, category in category_sources:
            for package_name in deps:
                categories_map[package_name].append(category)

        dependencies = {
            name: make_manifest_dependency(name, version, categories_map.get(name, []))
            for name, version in project_data.get("dependencies", {}).items()
        }
        optional_dependencies = build_optional_dependencies(category_sources, dependencies, categories_map)

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

        engines = project_data.get("engines", {})
        node_constraint = engines.get("node") if isinstance(engines, dict) else None
        engine_constraints = {"node": node_constraint} if node_constraint else None

        def create_project(dependency_tree: Dependency, has_lockfile: bool = True) -> Project:
            return Project(
                package_manager_type=self.package_manager_type,
                name=project_package_name,
                project_path=self.project_path,
                dependency_tree=dependency_tree,
                engine_constraints=engine_constraints,
                has_lockfile=has_lockfile,
            )

        # Exceptional case, no lockfile
        if not project_files.lockfile:
            return create_project(dependency_tree=self.parse_package_json(project_data), has_lockfile=False)

        # Lockfile present, let's parse it
        with open(project_files.lockfile, encoding="utf-8") as f:
            lockfile_data = json.load(f)

        lockfile_parser = self.get_lockfile_parser(lockfile_data.get("lockfileVersion"))
        if not lockfile_parser:
            raise PackageManagerLockfileParsingError("Could not find a parser for the given lockfile version")

        return create_project(dependency_tree=lockfile_parser(lockfile_data))

    @classmethod
    def helper_specs(cls) -> list[HelperSpec]:
        """Advertise NPM helper sub-commands."""
        return [
            HelperSpec("apply-state", "Apply final package.json specifiers and overrides for manual npm install"),
        ]

    def apply_state(self, plan: UpdatePlan) -> str:
        """Write final package.json specifiers and transitive overrides without running npm install.

        Intended for use by generate_update_script so the manifest is ready before the user
        runs npm install manually.
        """
        manifest_path = os.path.join(plan.project_path, "package.json")
        with open(manifest_path, encoding="utf-8") as f:
            pkg = json.load(f)

        apply_direct_specs(pkg, plan)

        transitive = {e.package_name: e.recommended_version for e in plan.all_entries if not e.is_direct}
        if transitive:
            overrides = pkg.get("overrides", {})
            overrides.update(transitive)
            pkg["overrides"] = overrides

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(pkg, f, indent=2)
            f.write("\n")

        n_direct = len(plan.direct_entries)
        n_transitive = len(plan.transitive_entries)
        return f"Applied {n_direct} direct, {n_transitive} transitive update(s) to package.json."

    def execute_update(self, plan: UpdatePlan) -> None:
        """Apply manifest changes then run npm install. Restores package.json on failure."""
        manifest_path = os.path.join(plan.project_path, "package.json")
        with open(manifest_path, encoding="utf-8") as f:
            original_content = f.read()

        pkg = json.loads(original_content)
        apply_direct_specs(pkg, plan)

        transitive = {e.package_name: e.recommended_version for e in plan.all_entries if not e.is_direct}
        if transitive:
            overrides = pkg.get("overrides", {})
            overrides.update(transitive)
            pkg["overrides"] = overrides

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(pkg, f, indent=2)
            f.write("\n")

        try:
            subprocess.run(["npm", "install", "--ignore-scripts"], cwd=plan.project_path, check=True)
        except subprocess.CalledProcessError as exc:
            with open(manifest_path, "w", encoding="utf-8") as f:
                f.write(original_content)
            raise PackageManagerExecutionError(f"npm install failed (exit {exc.returncode})") from exc

    def generate_update_script(self, plan: UpdatePlan, cli_extra_args: str = "") -> str:
        """Generate bash script that applies manifest changes then runs npm install."""
        path_q = shlex.quote(plan.project_path)
        apply = f"ossiq helpers npm apply-state {path_q}"
        if cli_extra_args:
            apply += f" {cli_extra_args}"
        lines = [
            "#!/usr/bin/env bash",
            f"# OSS IQ update — npm  |  project: {plan.project_name}",
            f"# {len(plan.direct_entries)} direct, {len(plan.transitive_entries)} transitive updates",
            "set -euo pipefail",
            "",
            f"cd {path_q}",
            "",
            'echo "Applying updates to package.json..."',
            apply,
            "",
            'echo "Installing..."',
            "npm install --ignore-scripts",
            "",
            'echo "Done."',
        ]
        return "\n".join(lines)

    def install_package(self, package_name: str, version: str | None = None) -> int:
        """Run npm install to add a package to the project."""
        spec = f"{package_name}@{version}" if version else package_name
        return subprocess.run(["npm", "install", spec], cwd=self.project_path).returncode

    def __repr__(self):
        return f"{self.package_manager_type.name} Package Manager"
