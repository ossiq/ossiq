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
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
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

NPM_STATE_FILE = ".ossiq_npm_state.json"
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


def resolve_override_value(orig_val: str, name: str, recommended: dict[str, str]) -> str:
    """Return the version to write back for a single override entry during restore.

    npm cross-reference values (starting with '$') are kept verbatim; everything
    else uses the recommended version if available, falling back to the original.
    """
    if orig_val.startswith("$"):
        return orig_val
    return recommended.get(name, orig_val)


def format_override_diff_line(key: str, orig_v: str | None, curr_v: str | None) -> str:
    """Format one line of the overrides diff."""
    if orig_v == curr_v:
        return f"  = {key}: {curr_v}"
    if orig_v is None:
        return f"  + {key}: {curr_v}  (added)"
    if curr_v is None:
        return f"  - {key}: {orig_v}  (removed)"
    return f"  ~ {key}: {orig_v} → {curr_v}"


def build_locked_overrides(plan: UpdatePlan, direct_dep_names: set[str]) -> dict[str, str]:
    """Build npm overrides for freeze_state: all non-direct packages at current installed
    versions, with plan entries overriding their packages at recommended versions."""
    overrides = {name: version for name, version in plan.installed_versions.items() if name not in direct_dep_names}
    for entry in plan.all_entries:
        if entry.package_name not in direct_dep_names:
            overrides[entry.package_name] = entry.recommended_version
    return overrides


def collect_original_specs(pkg: dict) -> dict[str, dict[str, str]]:
    """Snapshot the declared specifier of every direct dependency, per section.

    Saved before freeze rewrites them to exact versions so finalize_state/restore_state
    can rebuild the intended final specifiers.
    """
    return {
        section: dict(pkg[section]) for section in DEP_SECTIONS if isinstance(pkg.get(section), dict) and pkg[section]
    }


def freeze_direct_specs(plan: UpdatePlan, pkg: dict) -> None:
    """Pin every direct dependency to an exact version for a deterministic `npm install`.

    Updated deps take their recommended version; every other direct dep is held at its installed
    version so npm cannot greedily advance it within range. The intended final specifiers are
    restored afterwards by finalize_state (success) or restore_state (failure).
    """
    direct_entries = {e.package_name: e for e in plan.direct_entries}
    for section in DEP_SECTIONS:
        for name in list(pkg.get(section, {})):
            entry = direct_entries.get(name)
            if entry is not None:
                pkg[section][name] = entry.recommended_version
            elif name in plan.installed_versions:
                pkg[section][name] = plan.installed_versions[name]


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


def finalize_direct_specs(
    pkg: dict,
    original_specs: dict[str, dict[str, str]],
    recommended_versions: dict[str, str],
    pin_all: bool,
    forced_direct: set[str] | None = None,
) -> None:
    """Rewrite direct specifiers to their final form.

    Updated deps are relaxed via relax_spec; every other dep is restored to its original
    specifier. Deps forced via --override are written as exact versions regardless of mode.
    An empty recommended_versions restores all specifiers (rollback).
    """
    forced = forced_direct or set()
    for section, specs in original_specs.items():
        target = pkg.get(section)
        if not isinstance(target, dict):
            continue
        for name, original_spec in specs.items():
            if name not in target:
                continue
            recommended = recommended_versions.get(name)
            if recommended is None:
                target[name] = original_spec
            elif name in forced:
                target[name] = recommended
            else:
                target[name] = relax_spec(original_spec, recommended, pin_all)


def sync_lockfile_root_specs(lockfile_path: str, pkg: dict) -> None:
    """Align the lockfile root package's declared specifiers with package.json.

    Only the specifier strings in `packages[""]` are rewritten; resolved versions, integrity
    hashes, and installed node entries are left intact, so a deliberately below-max pinned
    version survives without npm re-resolving it.
    """
    with open(lockfile_path, encoding="utf-8") as f:
        lock = json.load(f)

    root = lock.get("packages", {}).get("", {})
    changed = False
    for section in DEP_SECTIONS:
        manifest_section = pkg.get(section)
        lock_section = root.get(section)
        if not isinstance(manifest_section, dict) or not isinstance(lock_section, dict):
            continue
        for name, spec in manifest_section.items():
            if name in lock_section and lock_section[name] != spec:
                lock_section[name] = spec
                changed = True

    if changed:
        with open(lockfile_path, "w", encoding="utf-8") as f:
            json.dump(lock, f, indent=2)
            f.write("\n")


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
            HelperSpec("freeze-state", "Lock full dependency tree in package.json overrides for safe update"),
            HelperSpec("finalize-state", "Relax specifiers to final form and sync lockfile after npm install"),
            HelperSpec("restore-state", "Restore original package.json overrides after npm install"),
            HelperSpec("overrides-diff", "Show diff between current and original overrides (read-only)"),
        ]

    def freeze_state(self, plan: UpdatePlan) -> None:
        """Write the state file, lock the transitive tree via overrides, and pin direct deps exact.

        Direct deps are pinned to exact versions (recommended for updates, installed otherwise) so
        `npm install` produces a deterministic lockfile. The original specifiers are saved so that
        finalize_state (success) or restore_state (failure) can rebuild the intended form.
        """
        manifest_path = os.path.join(plan.project_path, "package.json")
        state_path = os.path.join(plan.project_path, NPM_STATE_FILE)

        with open(manifest_path, encoding="utf-8") as f:
            pkg = json.load(f)

        original_overrides = pkg.get("overrides", {})
        original_specs = collect_original_specs(pkg)
        direct_dep_names = {name for section in DEP_SECTIONS for name in pkg.get(section, {})}
        locked_overrides = build_locked_overrides(plan, direct_dep_names)

        state = {
            "original_overrides": original_overrides,
            "locked_overrides": locked_overrides,
            "recommended_versions": {entry.package_name: entry.recommended_version for entry in plan.all_entries},
            "original_specs": original_specs,
            "pin_all": plan.pin_all,
            # --override targets persist beyond the update: transitive ones stay in `overrides`,
            # direct ones are written as exact pins by finalize_direct_specs.
            "forced_overrides": {
                entry.package_name: entry.recommended_version
                for entry in plan.all_entries
                if entry.is_forced and entry.package_name not in direct_dep_names
            },
            "forced_direct": [
                entry.package_name
                for entry in plan.all_entries
                if entry.is_forced and entry.package_name in direct_dep_names
            ],
        }
        with open(state_path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)

        pkg["overrides"] = locked_overrides
        freeze_direct_specs(plan, pkg)

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(pkg, f, indent=2)

    def finalize_state(self, project_path: str) -> str:
        """Apply final specifiers after a successful install and delete the state file.

        Restores original overrides (bumping any that point at an updated package), relaxes direct
        dep specifiers to their final form per mode, then syncs the lockfile root specifiers so
        package.json and package-lock.json stay consistent without re-resolving.
        """
        state_path = os.path.join(project_path, NPM_STATE_FILE)
        manifest_path = os.path.join(project_path, "package.json")
        lockfile_path = os.path.join(project_path, "package-lock.json")

        if not os.path.exists(state_path):
            raise FileNotFoundError(f"State file not found: {state_path}")

        with open(state_path, encoding="utf-8") as f:
            state = json.load(f)
        with open(manifest_path, encoding="utf-8") as f:
            pkg = json.load(f)

        original = state["original_overrides"]
        recommended = state.get("recommended_versions", {})
        original_specs = state.get("original_specs", {})
        pin_all = state.get("pin_all", False)

        restored = {name: resolve_override_value(orig_val, name, recommended) for name, orig_val in original.items()}
        restored.update(state.get("forced_overrides", {}))
        if restored:
            pkg["overrides"] = restored
        elif "overrides" in pkg:
            del pkg["overrides"]

        finalize_direct_specs(pkg, original_specs, recommended, pin_all, set(state.get("forced_direct", [])))

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(pkg, f, indent=2)

        if os.path.exists(lockfile_path):
            sync_lockfile_root_specs(lockfile_path, pkg)

        direct_count = sum(len(specs) for specs in original_specs.values())
        os.unlink(state_path)
        return f"Finalized {direct_count} direct specifier(s); lockfile synced."

    def restore_state(self, project_path: str) -> str:
        """Restore original package.json overrides from state file and delete it.

        Returns a summary message.
        """
        state_path = os.path.join(project_path, NPM_STATE_FILE)
        manifest_path = os.path.join(project_path, "package.json")

        if not os.path.exists(state_path):
            raise FileNotFoundError(f"State file not found: {state_path}")

        with open(state_path, encoding="utf-8") as f:
            state = json.load(f)
        with open(manifest_path, encoding="utf-8") as f:
            pkg = json.load(f)

        original = state["original_overrides"]
        recommended = state.get("recommended_versions", {})
        restored = {name: resolve_override_value(orig_val, name, recommended) for name, orig_val in original.items()}

        if restored:
            pkg["overrides"] = restored
        elif "overrides" in pkg:
            del pkg["overrides"]

        # Revert the exact pins written by freeze back to the original specifiers (no update applied).
        finalize_direct_specs(pkg, state.get("original_specs", {}), {}, False)

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(pkg, f, indent=2)

        os.unlink(state_path)
        return f"Overrides restored: {len(original)} original entries."

    def overrides_diff(self, project_path: str) -> str:
        """Return a read-only diff of current overrides vs original (from state file)."""
        state_path = os.path.join(project_path, NPM_STATE_FILE)
        manifest_path = os.path.join(project_path, "package.json")

        if not os.path.exists(state_path):
            raise FileNotFoundError(f"State file not found: {state_path}")

        with open(state_path, encoding="utf-8") as f:
            state = json.load(f)
        with open(manifest_path, encoding="utf-8") as f:
            pkg = json.load(f)

        original = state["original_overrides"]
        current = pkg.get("overrides", {})
        all_keys = sorted(set(original) | set(current))

        lines = ["package.json overrides diff (original → current):"]
        for key in all_keys:
            lines.append(format_override_diff_line(key, original.get(key), current.get(key)))
        return "\n".join(lines)

    def execute_update(self, plan: UpdatePlan) -> None:
        """Freeze state, run npm install, then finalize specifiers + lockfile. Rolled back on failure."""
        self.freeze_state(plan)
        try:
            subprocess.run(["npm", "install", "--ignore-scripts"], cwd=plan.project_path, check=True)
            self.finalize_state(plan.project_path)
        except Exception:
            self.restore_state(plan.project_path)
            raise

    def generate_update_script(self, plan: UpdatePlan, cli_extra_args: str = "") -> str:
        """Generate bash script that delegates all JSON manipulation to ossiq helpers."""
        path_q = shlex.quote(plan.project_path)
        freeze = f"ossiq helpers npm freeze-state {path_q}"
        if cli_extra_args:
            freeze += f" {cli_extra_args}"
        finalize = f"ossiq helpers npm finalize-state {path_q}"
        restore = f"ossiq helpers npm restore-state {path_q}"
        lines = [
            "#!/usr/bin/env bash",
            f"# OSS IQ update — npm  |  project: {plan.project_name}",
            f"# {len(plan.direct_entries)} direct, {len(plan.transitive_entries)} transitive updates",
            "set -euo pipefail",
            "",
            f"cd {path_q}",
            "",
            'echo "Freezing dependency tree and saving state..."',
            freeze,
            "",
            'echo "Installing..."',
            "npm install --ignore-scripts",
            "",
            'echo "Finalizing specifiers and syncing lockfile..."',
            finalize,
            "",
            'echo "Done."',
            "",
            f"# ROLLBACK: {restore}",
        ]
        return "\n".join(lines)

    def __repr__(self):
        return f"{self.package_manager_type.name} Package Manager"
