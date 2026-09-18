"""
Support of UV package manager
"""

from __future__ import annotations

import os
import re
import subprocess
import tomllib
from collections import defaultdict, namedtuple
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from packaging.requirements import InvalidRequirement, Requirement

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.adapters.api_pypi import PackageRegistryApiPypi
from ossiq.adapters.package_managers.api_pypi import enrich_registry_constraints
from ossiq.adapters.package_managers.dependency_tree import BaseDependencyResolver
from ossiq.adapters.package_managers.utils import extract_min_python_version, find_lockfile_parser
from ossiq.domain.common import ConstraintType, normalize_dist_name
from ossiq.domain.exceptions import PackageManagerExecutionError, PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import UV, PackageManagerType
from ossiq.domain.project import ConstraintSource, Dependency, Project
from ossiq.domain.version import classify_pypi_specifier
from ossiq.settings import Settings

if TYPE_CHECKING:
    from ossiq.service.update import UpdateEntry, UpdatePlan


UvProject = namedtuple("UvProject", ["manifest", "lockfile"])


def parse_pyproject_direct_specifiers(pyproject_data: dict) -> dict[str, str | None]:
    """Return {canonical_name: specifier} for all direct deps declared in pyproject.toml.

    Covers [project.dependencies] and [project.optional-dependencies].
    Used to authoritative-override stale lockfile metadata.requires-dist specifiers.
    """
    project_section = pyproject_data.get("project", {})
    dep_strings: list[str] = list(project_section.get("dependencies", []))
    for group_deps in project_section.get("optional-dependencies", {}).values():
        dep_strings.extend(group_deps)

    result: dict[str, str | None] = {}
    for dep_str in dep_strings:
        try:
            req = Requirement(dep_str)
            result[normalize_dist_name(req.name)] = str(req.specifier) or None
        except (InvalidRequirement, ValueError):
            pass
    return result


def apply_pyproject_constraints(root: Dependency, pyproject_specs: dict[str, str | None]) -> list[str]:
    """Reassert version_constraint_declared on root's direct deps from pyproject.toml.

    Pass 2 of dependency_tree.py's build_graph already sets version_constraint_declared from
    the lockfile's own recorded specifier (uv.lock's [package.metadata].requires-dist), but
    that can be stale if pyproject.toml was hand-edited since the last `uv lock`. pyproject.toml
    is the actual manifest, so its value always wins for the user-facing declared constraint.

    Returns names of packages whose lockfile specifier differs from pyproject.toml's
    (i.e. the lockfile is stale and needs `uv lock` to regenerate).
    """
    divergent: list[str] = []
    for dep in {**root.dependencies, **root.optional_dependencies}.values():
        canonical = normalize_dist_name(dep.canonical_name)
        if canonical not in pyproject_specs:
            continue
        pyproject_spec = pyproject_specs[canonical]
        if dep.version_constraint_declared != pyproject_spec:
            divergent.append(dep.name)
            dep.version_constraint_declared = pyproject_spec
    return divergent


def _direct_dependency_strings(pyproject_data: dict) -> list[str]:
    """Every exact, verbatim dependency string across [project.dependencies] and
    [project.optional-dependencies] in an already-parsed pyproject.toml document.

    Split out of find_pyproject_direct_specifiers so a caller that needs every package's
    strings (execute_update) can parse the document once instead of once per package - see
    execute_update's own docstring for why that matters beyond just performance.
    """
    project_section = pyproject_data.get("project", {})
    dep_strings: list[str] = list(project_section.get("dependencies", []))
    for group_deps in project_section.get("optional-dependencies", {}).values():
        dep_strings.extend(group_deps)
    return dep_strings


def find_pyproject_direct_specifiers(content: str, package_name: str) -> list[str]:
    """Every exact, verbatim dependency string in [project.dependencies] /
    [project.optional-dependencies] whose name normalises to `package_name`.

    Matching on the normalised name - not a string prefix of package_name - is what
    execute_update needs to safely target a rewrite. The previous approach matched any quoted
    string starting with the package name via regex (`"{package_name}[^"]*"`), which also
    matches "pydantic-settings==2.15.0" when updating "pydantic": re.sub then replaces every
    match with pydantic's new spec, silently destroying the pydantic-settings entry and leaving
    a duplicate pydantic line in its place. Confirmed by direct reproduction against
    execute_update - see the writer-corruption investigation.

    Returns a list, not one string: the same package can be declared in more than one place (the
    main list and an optional-dependencies group) with different specifiers, and every occurrence
    needs rewriting, exactly as the old code intended before its matching was fixed.

    Single-package convenience wrapper around _direct_dependency_strings, parsing `content` on
    every call - fine for one-off lookups (and what the tests exercise), but execute_update
    parses once itself and buckets by name rather than calling this per package.
    """
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return []

    target = normalize_dist_name(package_name)
    matches: list[str] = []
    for dep_str in _direct_dependency_strings(data):
        try:
            req = Requirement(dep_str)
        except InvalidRequirement:
            continue
        if normalize_dist_name(req.name) == target:
            matches.append(dep_str)
    return matches


def _parse_toml_array_specs(data: dict, table_path: tuple[str, ...], key: str) -> dict[str, str]:
    """Read a `key = ["pkg==version", ...]` array under `[table_path]`, keyed by normalised name."""
    table_data: dict = data
    for part in table_path:
        table_data = table_data.get(part, {})
    specs: dict[str, str] = {}
    for spec in table_data.get(key, []):
        try:
            specs[normalize_dist_name(Requirement(spec).name)] = spec
        except InvalidRequirement:
            specs[spec] = spec
    return specs


def upsert_toml_array(content: str, table_path: tuple[str, ...], key: str, overrides: dict[str, str]) -> str:
    """Merge forced pkg==version entries into a `key = [...]` array under `[table_path]` in pyproject.toml.

    Existing entries for other packages are preserved; an entry for a forced package is replaced.
    The table and the array key are created when missing. Editing is text-based so the rest of the
    file stays byte-identical; the result is re-parsed to guarantee valid TOML before it is returned.
    """
    if not overrides:
        return content

    data = tomllib.loads(content)
    table_data: dict = data
    for part in table_path:
        table_data = table_data.get(part, {})
    existing_specs: list[str] = table_data.get(key, [])

    merged: dict[str, str] = {}
    for spec in existing_specs:
        try:
            merged[normalize_dist_name(Requirement(spec).name)] = spec
        except InvalidRequirement:
            merged[spec] = spec
    for name, version in overrides.items():
        merged[normalize_dist_name(name)] = f"{name}=={version}"

    entries = "\n".join(f'    "{spec}",' for spec in merged.values())
    block = f"{key} = [\n{entries}\n]"

    table_header = ".".join(table_path)
    key_present = key in table_data

    if key_present:
        new_content = re.sub(rf"{re.escape(key)}\s*=\s*\[.*?\]", lambda match: block, content, count=1, flags=re.DOTALL)
    elif re.search(rf"^\[{re.escape(table_header)}\]\s*$", content, flags=re.MULTILINE):
        new_content = re.sub(
            rf"^\[{re.escape(table_header)}\]\s*$",
            lambda match: f"[{table_header}]\n{block}",
            content,
            count=1,
            flags=re.MULTILINE,
        )
    else:
        new_content = f"{content.rstrip()}\n\n[{table_header}]\n{block}\n"

    tomllib.loads(new_content)  # raises TOMLDecodeError when the edit produced invalid TOML
    return new_content


def upsert_uv_override_dependencies(content: str, overrides: dict[str, str]) -> str:
    """Merge forced pkg==version entries into [tool.uv] override-dependencies in pyproject.toml."""
    return upsert_toml_array(content, ("tool", "uv"), "override-dependencies", overrides)


def upsert_ossiq_metadata_overrides(content: str, overrides: dict[str, str]) -> str:
    """Merge pkg==version entries into [tool.ossiq.metadata] overrides in pyproject.toml.

    Records what OSS IQ itself last wrote to [tool.uv] override-dependencies, so a later run can
    tell its own writes apart from a user-authored override (see constraint_dependencies_setting's
    is_ossiq_authored).
    """
    return upsert_toml_array(content, ("tool", "ossiq", "metadata"), "overrides", overrides)


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

    def parse_lockfile_v1_r3(self, project_package_name: str, uv_lock_data: dict) -> tuple[Dependency, dict]:
        """
        Lockfile parser for UV version `1` and revision `3`
        """
        resolver = UVResolverV1R3(uv_lock_data)
        root_node = resolver.build_graph(project_package_name)
        if not root_node:
            raise PackageManagerLockfileParsingError("Cannot parse UV lockfile")

        return root_node, resolver.registry

    def get_lockfile_parser(
        self, version: int | str | None, revision: int | str | None
    ) -> Callable[..., tuple[Dependency, dict]]:
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
        override_specs: dict[str, str],
        ossiq_overrides: dict[str, str] | None = None,
        source_file: str = "pyproject.toml",
    ) -> None:
        """Walk dep_tree recursively and set constraint_info on matching nodes.

        override_specs and ossiq_overrides map normalised package name to the raw "pkg==version"
        specifier currently in [tool.uv] override-dependencies / [tool.ossiq.metadata] overrides
        respectively. is_ossiq_authored is only True when the two specifiers match exactly - if
        the user hand-edits the override's version, the values diverge and it correctly flips to
        False, even though the package name is still present in our last-written record.
        """
        ossiq_overrides = ossiq_overrides or {}
        for dep in {**dep_tree.dependencies, **dep_tree.optional_dependencies}.values():
            norm = normalize_dist_name(dep.canonical_name)
            if norm in override_specs:
                dep.constraint_info = ConstraintSource(
                    type=ConstraintType.OVERRIDE,
                    source_file=source_file,
                    is_ossiq_authored=ossiq_overrides.get(norm) == override_specs[norm],
                )
            elif norm in constraint_names:
                dep.constraint_info = ConstraintSource(type=ConstraintType.ADDITIVE, source_file=source_file)

            PackageManagerPythonUv.constraint_dependencies_setting(
                dep, constraint_names, override_specs, ossiq_overrides, source_file
            )

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

        dependency_tree, registry = lockfile_parser(project_package_name, uv_lock_data)

        pyproject_specs = parse_pyproject_direct_specifiers(pyproject_data)
        divergent = apply_pyproject_constraints(dependency_tree, pyproject_specs)

        if not self.settings.skip_pypi_enrichment:
            enrich_registry_constraints(registry)

        # Constraint/Override settings from [tool.uv] section
        uv_section = pyproject_data.get("tool", {}).get("uv", {})
        constraint_specs: list[str] = uv_section.get("constraint-dependencies", [])
        override_specs: list[str] = uv_section.get("override-dependencies", [])
        if constraint_specs or override_specs:
            constraint_names = {normalize_dist_name(s) for s in constraint_specs}
            override_specs_by_name = {normalize_dist_name(s): s for s in override_specs}
            ossiq_metadata = pyproject_data.get("tool", {}).get("ossiq", {}).get("metadata", {})
            ossiq_overrides_by_name = {normalize_dist_name(s): s for s in ossiq_metadata.get("overrides", [])}
            self.constraint_dependencies_setting(
                dependency_tree, constraint_names, override_specs_by_name, ossiq_overrides_by_name
            )

        requires_python = pyproject_data.get("project", {}).get("requires-python")
        engine_constraints = None
        if requires_python:
            min_py = extract_min_python_version(requires_python)
            if min_py:
                engine_constraints = {"python": min_py}

        return Project(
            package_manager_type=self.package_manager_type,
            name=project_package_name,
            project_path=self.project_path,
            dependency_tree=dependency_tree,
            engine_constraints=engine_constraints,
            manifest_lock_divergent=divergent,
        )

    @staticmethod
    def resolve_direct_specifier(entry: UpdateEntry, pin_all: bool) -> str | None:
        """Return the new specifier string to write into pyproject.toml, or the original when lockfile-only.

        When the return value equals entry.version_defined, no pyproject.toml edit is needed —
        the caller should add the package to --upgrade-package on uv lock instead.
        Forced (--override) entries always pin exact, regardless of mode.
        """
        if entry.is_forced or pin_all:
            return f"=={entry.recommended_version}"
        return PackageRegistryApiPypi.rewrite_specifier(
            entry.version_defined, entry.recommended_version, entry.constraint_type
        )

    def execute_update(self, plan: UpdatePlan) -> None:
        """Apply specifier rewrites, run uv lock + uv sync in-process. Restores pyproject.toml on failure.

        Parses pyproject.toml once and buckets every direct dependency string by normalised
        name, rather than calling find_pyproject_direct_specifiers (a full re-parse) once per
        changed package: that was both an O(n) redundant re-parse of an unchanging document for
        n changed packages, and fragile - a parse failure there silently returns [], which would
        make every *remaining* package in the loop receive no rewrite with no warning raised.
        Parsing content once, up front, before any specifier is rewritten, means an unparseable
        manifest fails loudly for the whole update instead of degrading package-by-package.
        """
        manifest_path = Path(plan.project_path) / "pyproject.toml"
        original_content = manifest_path.read_text(encoding="utf-8")

        try:
            parsed = tomllib.loads(original_content)
        except tomllib.TOMLDecodeError as exc:
            raise PackageManagerExecutionError(f"pyproject.toml is not valid TOML: {exc}") from exc

        dependency_strings_by_name: dict[str, list[str]] = defaultdict(list)
        for dep_str in _direct_dependency_strings(parsed):
            try:
                req = Requirement(dep_str)
            except InvalidRequirement:
                continue
            dependency_strings_by_name[normalize_dist_name(req.name)].append(dep_str)

        content = original_content
        for entry in plan.direct_entries:
            new_spec = self.resolve_direct_specifier(entry, plan.pin_all)
            if new_spec != entry.version_defined:
                spec_to_write = new_spec or f"=={entry.recommended_version}"
                for original_dep_str in dependency_strings_by_name.get(normalize_dist_name(entry.package_name), []):
                    content = content.replace(f'"{original_dep_str}"', f'"{entry.package_name}{spec_to_write}"', 1)

        forced_transitive = {
            entry.package_name: entry.recommended_version for entry in plan.transitive_entries if entry.is_forced
        }
        if forced_transitive:
            existing_overrides = _parse_toml_array_specs(parsed, ("tool", "uv"), "override-dependencies")
            existing_metadata = _parse_toml_array_specs(parsed, ("tool", "ossiq", "metadata"), "overrides")

            to_write: dict[str, str] = {}
            for name, version in forced_transitive.items():
                norm = normalize_dist_name(name)
                existing_spec = existing_overrides.get(norm)
                # Skip a package whose current override value isn't the one we last wrote — the
                # user has taken ownership of it (or it was always theirs). Never overwrite silently.
                if existing_spec is not None and existing_metadata.get(norm) != existing_spec:
                    continue
                to_write[name] = version

            if to_write:
                content = upsert_uv_override_dependencies(content, to_write)
                content = upsert_ossiq_metadata_overrides(content, to_write)

        if content != original_content:
            manifest_path.write_text(content, encoding="utf-8")

        upgrade_args = [
            arg
            for entry in plan.all_entries
            for arg in ("--upgrade-package", f"{entry.package_name}=={entry.recommended_version}")
        ]
        try:
            subprocess.run(["uv", "lock"] + upgrade_args, cwd=plan.project_path, check=True)
            subprocess.run(["uv", "sync"], cwd=plan.project_path, check=True)
        except subprocess.CalledProcessError as exc:
            manifest_path.write_text(original_content, encoding="utf-8")
            raise PackageManagerExecutionError(f"uv command failed (exit {exc.returncode})") from exc

    def install_package(self, package_name: str, version: str | None = None) -> int:
        """Run uv add to install a package into the project. Restores pyproject.toml on failure.

        `uv add <spec>` edits pyproject.toml itself, so there's no ossiq-side write to validate
        first - only the subprocess outcome to guard, the same way execute_update does.
        """
        spec = f"{package_name}=={version}" if version else package_name
        manifest_path = Path(self.project_path) / "pyproject.toml"
        original_content = manifest_path.read_text(encoding="utf-8")

        try:
            subprocess.run(["uv", "add", spec], cwd=self.project_path, check=True)
        except subprocess.CalledProcessError as exc:
            manifest_path.write_text(original_content, encoding="utf-8")
            raise PackageManagerExecutionError(f"uv add failed (exit {exc.returncode})") from exc
        return 0

    def __repr__(self):
        return f"{self.package_manager_type.name} Package Manager"
