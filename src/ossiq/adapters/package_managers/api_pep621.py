"""
Support for PEP 621 pyproject.toml projects that have no lockfile.

Handles a bare `[project].dependencies` declaration (e.g. a fresh `uv init`-style project
before `uv lock` has ever run) that no other adapter recognises: PackageManagerPythonUv and
PackageManagerPythonPip both additionally require a lockfile (uv.lock / pylock.toml), so a
project with only pyproject.toml previously matched no adapter at all and failed with
UnknownProjectPackageManager. A project that *does* have a lockfile matches this adapter too, and
`adapters.package_managers.api.PACKAGE_MANAGERS`' precedence order is what hands it to the
fuller-featured adapter instead - this module knows nothing about its siblings.

Scope: PEP 621 (`[project].dependencies`) only. A Poetry-only manifest (`[tool.poetry.dependencies]`,
no `[project]` table) does not match has_package_manager below and is not handled here - it needs
its own adapter (manifest parsing, poetry.lock format, non-PEP508 constraint syntax).
"""

import tomllib
from collections import namedtuple
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.domain.common import normalize_dist_name
from ossiq.domain.packages_manager import PEP621, PackageManagerType
from ossiq.domain.project import ConstraintSource, Dependency, Project
from ossiq.domain.version import classify_pypi_specifier, normalize_version
from ossiq.settings import Settings

Pep621Project = namedtuple("Pep621Project", ["manifest"])


class PackageManagerPythonPep621(AbstractPackageManagerApi):
    """
    Package Manager adapter for PEP 621 pyproject.toml projects without a lockfile.

    Direct-dependency-only: there is no lockfile to resolve transitive dependencies or exact
    installed versions from, so this mirrors PackageManagerPythonPipClassic's requirements.txt
    handling rather than the uv/pylock adapters' full lockfile-backed graphs.
    """

    settings: Settings
    package_manager_type: PackageManagerType = PEP621
    project_path: str

    @staticmethod
    def project_files(project_path: str) -> Pep621Project:
        return Pep621Project(manifest=str(Path(project_path) / PEP621.primary_manifest.name))

    @staticmethod
    def has_package_manager(project_path: str) -> bool:
        """
        Detect a PEP 621 project: pyproject.toml exists and declares a non-empty
        [project].dependencies list. An empty or absent section does not match - that avoids
        falsely claiming e.g. a pure-Poetry pyproject.toml with no [project] table.

        Answers only "does this tree look like mine?", nothing about other adapters. A uv or pylock
        project matches here too - both also have a pyproject.toml with dependencies - and the
        PACKAGE_MANAGERS precedence order is what hands those trees to the lockfile-backed adapter
        instead. This predicate used to call its two siblings' own has_package_manager to break
        that tie, which a Poetry adapter would have had to be added to as well.
        """
        project_files = PackageManagerPythonPep621.project_files(project_path)
        manifest = Path(project_files.manifest)
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError):
            return False
        return bool(data.get("project", {}).get("dependencies"))

    def __init__(self, project_path: str, settings: Settings):
        super().__init__()
        self.settings = settings
        self.project_path = project_path

    @staticmethod
    def _build_dependencies(dep_strings: list[str], category: str | None, source_file: str) -> dict[str, Dependency]:
        """Parse a list of PEP 508 requirement strings into direct Dependency nodes.

        There's no lockfile to report a resolved version from, so version_installed is a
        best-effort read off the specifier itself (exact for ==, lower bound for ranges) - the
        same approximation api_pip_classic.py uses for requirements.txt. A bare, unspecified
        dependency (no operator) has no way to derive even that, so it's skipped.
        """
        deps: dict[str, Dependency] = {}
        for dep_str in dep_strings:
            try:
                req = Requirement(dep_str)
            except InvalidRequirement:
                continue

            specifier = str(req.specifier) or None
            if not specifier:
                continue

            canonical_name = normalize_dist_name(req.name)
            version = normalize_version(specifier)
            if not canonical_name or not version:
                continue

            deps[canonical_name] = Dependency(
                name=req.name,
                canonical_name=canonical_name,
                version_installed=version,
                version_defined=specifier,
                version_constraint_declared=specifier,
                extras=sorted(req.extras) if req.extras else None,
                categories=[category] if category else [],
                constraint_info=ConstraintSource(
                    type=classify_pypi_specifier(specifier),
                    source_file=source_file,
                ),
            )
        return deps

    def parse_pyproject_dependencies(self, pyproject_data: dict) -> tuple[dict[str, Dependency], dict[str, Dependency]]:
        """Parse [project].dependencies and [project.optional-dependencies] into
        (main_dependencies, optional_dependencies), each keyed by canonical name."""
        project_section = pyproject_data.get("project", {})
        manifest_name = self.package_manager_type.primary_manifest.name

        main_deps = self._build_dependencies(project_section.get("dependencies", []), None, manifest_name)

        optional_deps: dict[str, Dependency] = {}
        for group, group_deps in project_section.get("optional-dependencies", {}).items():
            optional_deps.update(self._build_dependencies(group_deps, group, manifest_name))

        return main_deps, optional_deps

    def project_info(self) -> Project:
        """
        Extract project dependencies straight from [project].dependencies and
        [project.optional-dependencies] in pyproject.toml.

        No lockfile exists for this project shape, so this is a direct-dependency-only view -
        see domain/project.py's Project.has_lockfile.
        """
        project_files = self.project_files(self.project_path)
        pyproject_data = tomllib.loads(Path(project_files.manifest).read_text(encoding="utf-8"))

        project_package_name = pyproject_data.get("project", {}).get("name", Path(self.project_path).name)
        main_deps, optional_deps = self.parse_pyproject_dependencies(pyproject_data)

        dependency_tree = Dependency(
            name=project_package_name,
            canonical_name=project_package_name,
            version_installed="",  # Not applicable for the project itself
            dependencies=main_deps,
            optional_dependencies=optional_deps,
        )

        return Project(
            package_manager_type=self.package_manager_type,
            name=project_package_name,
            project_path=self.project_path,
            dependency_tree=dependency_tree,
            has_lockfile=False,
        )

    def __repr__(self):
        return f"{self.package_manager_type.name} Package Manager"
