"""
Support for classic pip requirements.txt files (without pyproject.toml).

This adapter handles legacy Python projects that use simple requirements.txt
files with pinned versions (package==version format).
"""

from __future__ import annotations

import dataclasses
import os
import re
import subprocess
import tempfile
from collections import namedtuple
from collections.abc import Callable

from packaging.requirements import InvalidRequirement, Requirement

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.adapters.package_managers.api_pypi import batch_fetch_requires_dist, make_session
from ossiq.domain.common import normalize_dist_name
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import PIP_CLASSIC, PackageManagerType
from ossiq.domain.project import ConstraintSource, Dependency, Project
from ossiq.domain.update_plan import UpdatePlan
from ossiq.domain.version import classify_pypi_specifier, normalize_version
from ossiq.settings import Settings
from ossiq.solver.pep508 import applicable_requirements

PipClassicProject = namedtuple("PipClassicProject", ["manifest"])

# Compiled regex patterns for performance (avoid recompilation in loops)
# Matches lines to skip: pip options (except -c, handled separately), VCS deps, URL deps
_SKIP_LINE_PATTERN = re.compile(
    r"^("
    r"-(?!c(?:\s|$))[a-z\-]|"  # Pip options except -c (e.g. -e, --editable, -r, --requirement)
    r"(git|hg|svn|bzr)\+|"  # VCS dependencies (git+, hg+, svn+, bzr+)
    r"(https?|file)://"  # URL dependencies (http://, https://, file://)
    r")",
    re.IGNORECASE,
)
# Matches -c <file> constraint file directives
_CONSTRAINT_FILE_PATTERN = re.compile(r"^-c\s+(.+)$", re.IGNORECASE)
# General requirement pattern: name[extras] + any PEP 440 specifier(s)
#   group 1 — package base name
#   group 2 — optional [extras] (including brackets)
#   group 3 — optional version specifier(s), e.g. "==2.31.0" or ">=2.0,<3.0"
_REQUIREMENT_PATTERN = re.compile(
    r"^([a-zA-Z0-9._\-]+)"
    r"(\[[^\]]+\])?"
    r"\s*((?:==|!=|>=|<=|~=|>|<)[^,\s;]+(?:\s*,\s*(?:==|!=|>=|<=|~=|>|<)[^,\s;]+)*)?"
)


class PackageManagerPythonPipClassic(AbstractPackageManagerApi):
    """
    Package Manager adapter for classic pip requirements.txt files.

    Supports simple pinned dependency format (package==version).
    Does not require pyproject.toml.
    """

    settings: Settings
    package_manager_type: PackageManagerType = PIP_CLASSIC
    project_path: str

    @staticmethod
    def project_files(project_path: str) -> PipClassicProject:
        return PipClassicProject(manifest=os.path.join(project_path, PIP_CLASSIC.primary_manifest.name))

    @staticmethod
    def has_package_manager(project_path: str) -> bool:
        """
        Detect that classic pip requirements.txt is used in a project_path.
        Only requires requirements.txt to be present.
        """
        project_files = PackageManagerPythonPipClassic.project_files(project_path)
        return os.path.exists(project_files.manifest)

    def __init__(self, project_path: str, settings: Settings):
        super().__init__()
        self.settings = settings
        self.project_path = project_path

    def read_requirements_lines(self, manifest_path: str) -> list[str]:
        """
        Read and return lines from requirements.txt file.

        Args:
            manifest_path: Path to requirements.txt file

        Returns:
            List of lines from the file

        Raises:
            PackageManagerLockfileParsingError: If file not found or decode fails
        """
        try:
            with open(manifest_path, encoding="utf-8") as f:
                return f.readlines()
        except FileNotFoundError as e:
            raise PackageManagerLockfileParsingError(f"requirements.txt not found at {manifest_path}") from e
        except UnicodeDecodeError as e:
            raise PackageManagerLockfileParsingError(f"Failed to decode requirements.txt: {e}") from e

    @staticmethod
    def parse_requirement(line: str) -> tuple[str, list[str] | None, str | None] | None:
        """
        Extract package spec, extras, and full version specifier from a requirement line.

        Args:
            line: Preprocessed requirement line (comments and whitespace already stripped)

        Returns:
            Tuple of (package_spec_with_extras, extras, version_spec) where:
                - package_spec_with_extras includes the raw extras bracket, e.g. "requests[security]"
                - extras is a parsed list like ["security", "tests"], or None
                - version_spec is the full specifier string like "==2.31.0" or ">=2.0,<3.0", or None
            Returns None if the line does not match a valid package requirement.

        Examples:
            "requests==2.31.0"            -> ("requests",           None,               "==2.31.0")
            "Django[extra]==4.2.0"        -> ("Django[extra]",      ["extra"],          "==4.2.0")
            "httpx[http2]>=0.24,<1.0"     -> ("httpx[http2]",       ["http2"],          ">=0.24,<1.0")
            "requests[sec,tests]>=2.28.0" -> ("requests[sec,tests]",["sec", "tests"],   ">=2.28.0")
            "package~=1.2"               -> ("package",            None,               "~=1.2")
            "bare-package"               -> ("bare-package",        None,               None)
        """
        match = _REQUIREMENT_PATTERN.match(line)
        if not match:
            return None
        base_name = match.group(1)
        extras_raw = match.group(2)  # e.g. "[security,tests]" or None
        version_spec = match.group(3) or None  # e.g. "==2.31.0" or None
        extras = [e.strip() for e in extras_raw[1:-1].split(",")] if extras_raw else None
        package_spec = base_name + (extras_raw or "")
        return package_spec, extras, version_spec

    @staticmethod
    def load_constraint_file(
        path: str, constraint_ranges: dict[str, list[str]], visited: set[str] | None = None
    ) -> None:
        """
        Read a pip constraints file and accumulate each package's specifiers into constraint_ranges.

        Handles recursive -c includes with a visited-file guard to prevent infinite loops. pip
        intersects every range with each requirement on the package, so the ranges are what bound a
        recommendation; a bare name maps to an empty list.
        shortcut: markers are ignored, so a range binds on every platform; honour them if one over-blocks.
        """
        if visited is None:
            visited = set()
        abs_path = os.path.realpath(path)
        if abs_path in visited:
            return
        visited.add(abs_path)

        try:
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
        except (FileNotFoundError, UnicodeDecodeError):
            return  # Silently skip unreadable constraint files

        for raw_line in lines:
            line = raw_line.split("#")[0].strip()
            if not line:
                continue
            # Recurse into nested -c includes
            c_match = _CONSTRAINT_FILE_PATTERN.match(line)
            if c_match:
                nested_path = os.path.join(os.path.dirname(path), c_match.group(1).strip())
                PackageManagerPythonPipClassic.load_constraint_file(nested_path, constraint_ranges, visited)
                continue
            # Skip all other pip options and non-package lines
            if _SKIP_LINE_PATTERN.match(line):
                continue
            try:
                req = Requirement(line)
            except InvalidRequirement:
                continue
            found = constraint_ranges.setdefault(normalize_dist_name(req.name), [])
            if req.specifier:
                found.append(str(req.specifier))

    def constraint_file_ranges(self) -> dict[str, list[str]]:
        """{normalised name: [specifier, ...]} from every `-c` file requirements.txt names."""
        manifest = self.project_files(self.project_path).manifest
        ranges: dict[str, list[str]] = {}
        for line in self.read_requirements_lines(manifest):
            c_match = _CONSTRAINT_FILE_PATTERN.match(line.split("#")[0].strip())
            if c_match:
                self.load_constraint_file(os.path.join(os.path.dirname(manifest), c_match.group(1).strip()), ranges)
        return ranges

    def installer_caps(self) -> dict[str, str]:
        """Return the `-c` files' ranges as {normalised name: range}."""
        return {name: ",".join(specs) for name, specs in self.constraint_file_ranges().items() if specs}

    def parse_requirements_txt(self) -> dict[str, Dependency]:
        """
        Parse requirements.txt for versioned dependencies.

        Handles any PEP 440 specifier (==, >=, ~=, !=, compound ranges, etc.) and
        preserves PyPI extras (e.g. requests[security]) as a structured list.
        Skips bare package names (no version specifier), editable installs, VCS and
        URL dependencies. Follows -c <file> constraint directives and records each
        constrained package's range as `ConstraintSource.constraint_range`.

        Returns:
            Dictionary of dependencies {package_name: Dependency}
        """
        project_files = self.project_files(self.project_path)
        dependencies: dict[str, Dependency] = {}
        constraint_ranges = self.constraint_file_ranges()

        lines = self.read_requirements_lines(project_files.manifest)

        for line in lines:
            # Remove inline comments
            if "#" in line:
                line = line.split("#")[0].strip()

            if not line:
                continue

            # -c <file> lines were read by constraint_file_ranges; intercepted before the general skip pattern
            if _CONSTRAINT_FILE_PATTERN.match(line):
                continue

            if _SKIP_LINE_PATTERN.match(line):
                continue

            parsed = self.parse_requirement(line)
            if not parsed:
                continue

            package_spec, extras, version_spec = parsed

            if not version_spec:
                # Bare package name with no version specifier — skip
                continue

            package_name = normalize_dist_name(package_spec)

            # Best-effort installed version: exact for ==, lower bound for ranges
            version = normalize_version(version_spec)

            if not package_name or not version:
                continue

            dependencies[package_name] = Dependency(
                name=package_spec,  # preserve original name with extras
                canonical_name=package_name,
                version_installed=version,
                version_defined=version_spec,  # full specifier including operator(s)
                extras=extras,
                categories=[],
                constraint_info=ConstraintSource(
                    type=classify_pypi_specifier(version_spec),
                    source_file="requirements.txt",
                ),
            )

        # Second pass: a constrained requirement keeps its own classification, since its line is still
        # the user's to rewrite; the cap bounds the pick (the strategy gate) and the solver (its parents' specs).
        for pkg_name, dep in dependencies.items():
            ranges = constraint_ranges.get(normalize_dist_name(pkg_name))
            if ranges is None:
                continue
            dep.parent_constraints.extend(ranges)
            dep.constraint_info = dataclasses.replace(dep.constraint_info, constraint_range=",".join(ranges) or None)

        return dependencies

    def enrich_and_build_tree(self, dependencies: dict[str, Dependency]) -> dict[str, Dependency]:
        """Fetch requires_dist for all packages, build parent->child edges,
        and return only true root packages (not required by any other listed package).
        """
        if not dependencies:
            return {}

        pkg_lookup: dict[str, Dependency] = {dep.canonical_name: dep for dep in dependencies.values()}

        packages = [(dep.canonical_name, dep.version_installed) for dep in dependencies.values()]
        requires_dist_map = batch_fetch_requires_dist(packages, make_session())

        is_child: set[str] = set()

        for dep in dependencies.values():
            raw = requires_dist_map.get((dep.canonical_name, dep.version_installed), [])
            spec_map = applicable_requirements(raw, dep.extras or ())
            for norm_name, specifier in spec_map.items():
                child = pkg_lookup.get(norm_name)
                if child is None or child.canonical_name == dep.canonical_name:
                    continue
                if child.version_defined is None and specifier:
                    child.version_defined = specifier
                    child.constraint_info = ConstraintSource(
                        type=classify_pypi_specifier(specifier),
                        source_file=child.constraint_info.source_file,
                    )
                dep.dependencies[child.canonical_name] = child
                is_child.add(child.canonical_name)

        return {name: dep for name, dep in dependencies.items() if dep.canonical_name not in is_child}

    def project_info(self) -> Project:
        """
        Extract project dependencies from requirements.txt.

        Since requirements.txt doesn't distinguish between main and optional
        dependencies, all dependencies are treated as main dependencies.
        """
        # Parse dependencies from requirements.txt
        dependencies = self.parse_requirements_txt()

        # Project name: fallback to directory basename
        project_package_name = os.path.basename(self.project_path)

        root_deps = self.enrich_and_build_tree(dependencies) if not self.settings.skip_pypi_enrichment else dependencies

        dependency_tree = Dependency(
            name=project_package_name,
            canonical_name=project_package_name,
            version_installed="",  # Not applicable for the project itself
            dependencies=root_deps,
            optional_dependencies={},
        )

        return Project(
            package_manager_type=self.package_manager_type,
            name=project_package_name,
            project_path=self.project_path,
            dependency_tree=dependency_tree,
            has_lockfile=False,
        )

    def execute_update(self, plan: UpdatePlan, on_pass: Callable[[int, int], None] | None = None) -> None:
        """Write a temp constraints file, run pip install in-process, then clean up."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            for entry in plan.all_entries:
                f.write(f"{entry.package_name}=={entry.recommended_version}\n")
            constraints_path = f.name
        try:
            subprocess.run(
                ["pip", "install", "-r", "requirements.txt", "-c", constraints_path],
                cwd=plan.project_path,
                check=True,
            )
        finally:
            os.unlink(constraints_path)

    def install_package(self, package_name: str, version: str | None = None) -> int:
        """Run pip install to add a package to the project."""
        spec = f"{package_name}=={version}" if version else package_name
        return subprocess.run(["pip", "install", spec], cwd=self.project_path).returncode

    def __repr__(self):
        return f"{self.package_manager_type.name} Package Manager"
