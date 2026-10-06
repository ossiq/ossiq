"""
Support of NPM package manager
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.adapters.package_managers.npm import manifest
from ossiq.adapters.package_managers.npm.constants import MANIFEST_FILE
from ossiq.adapters.package_managers.npm.engines import declared_engine_floors
from ossiq.adapters.package_managers.npm.lockfile import NPMResolverV3
from ossiq.adapters.package_managers.npm.writer import apply_direct_specs, write_transitive_overrides
from ossiq.adapters.package_managers.utils import find_lockfile_parser
from ossiq.domain.exceptions import PackageManagerExecutionError, PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import NPM, PackageManagerType
from ossiq.domain.project import Dependency, Project
from ossiq.settings import Settings

if TYPE_CHECKING:
    from ossiq.service.update import UpdatePlan


class NpmProject(NamedTuple):
    manifest: str
    lockfile: str | None


class PackageManagerJsNpm(AbstractPackageManagerApi):
    """
    Package manager adapter for npm: reads package.json and package-lock.json (v2 and v3),
    applies update plans and installs packages.
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
        """Parse an npm alias specifier into (canonical_name, constraint); see manifest.parse_npm_alias."""
        return manifest.parse_npm_alias(version)

    def __init__(self, project_path: str, settings: Settings):
        super().__init__()
        self.settings = settings
        self.project_path = project_path

    def get_lockfile_parser(self, lockfile_version: int | None) -> Callable[..., Dependency]:
        """
        Find and return lockfile parser instance
        """

        context = {"lockfileVersion": lockfile_version}

        handler_name = find_lockfile_parser(self.supported_versions, context)
        if not handler_name or not hasattr(self, handler_name):
            raise PackageManagerLockfileParsingError(f"There's no parser for NPM lockfile version `{lockfile_version}`")

        return getattr(self, handler_name)

    def parse_lockfile_v2(
        self,
        lockfile_data: dict,
        ossiq_overrides: dict[str, str] | None = None,
        overrides: dict | None = None,
    ) -> Dependency:
        """Lockfile parser for NPM v2 (npm v7/v8 default).

        v2 carries the same flat packages map as v3, plus a legacy dependencies
        nested-tree for npm v6 back-compat. We parse via the packages section.
        """
        if "packages" not in lockfile_data:
            raise PackageManagerLockfileParsingError("NPM v2 lockfile is missing the 'packages' section")
        return self.parse_lockfile_v3(lockfile_data, ossiq_overrides, overrides)

    def parse_lockfile_v3(
        self,
        lockfile_data: dict,
        ossiq_overrides: dict[str, str] | None = None,
        overrides: dict | None = None,
    ) -> Dependency:
        """
        Lockfile parser for NPM

        Args:
            lockfile_data: The decoded package-lock.json.
            ossiq_overrides: The overrides OSS IQ itself last wrote (`ossiq:metadata.overrides`).
            overrides: The manifest's `overrides` block, which the lockfile does not carry.
        """
        resolver = NPMResolverV3(lockfile_data, overrides)
        dependency_tree = resolver.build_graph(lockfile_data["name"], ossiq_overrides)

        # No dependencies - no analysis, something wrong
        if not dependency_tree or (not dependency_tree.dependencies and not dependency_tree.optional_dependencies):
            raise PackageManagerLockfileParsingError("Could not parse NPM lockfile")
        return dependency_tree

    def parse_package_json(self, project_data: dict) -> Dependency:
        """Extracting dependencies and categories from package.json."""
        return manifest.parse_package_json(project_data)

    def project_info(self) -> Project:
        """
        Extract project dependencies using file format from a specific
        package manager.
        """
        manifest_file, lockfile = self.project_files(self.project_path)
        project_data = json.loads(Path(manifest_file).read_text(encoding="utf-8"))

        if lockfile is None:
            dependency_tree = manifest.parse_package_json(project_data)
        else:
            lockfile_data = json.loads(Path(lockfile).read_text(encoding="utf-8"))
            parse_lockfile = self.get_lockfile_parser(lockfile_data.get("lockfileVersion"))
            ossiq_overrides: dict[str, str] = project_data.get("ossiq:metadata", {}).get("overrides", {})
            dependency_tree = parse_lockfile(lockfile_data, ossiq_overrides, project_data.get("overrides"))

        return Project(
            package_manager_type=self.package_manager_type,
            name=project_data.get("name", os.path.basename(self.project_path)),
            project_path=self.project_path,
            dependency_tree=dependency_tree,
            engine_constraints=declared_engine_floors(project_data.get("engines")),
            has_lockfile=lockfile is not None,
            declares_esm=project_data.get("type") == "module",
        )

    def run_npm_install(self, project_path: str, specs: Sequence[str], original_manifest: str) -> None:
        """Run `npm install` for *specs* without lifecycle scripts, restoring package.json if npm fails.

        Install scripts stay off for every install OSS IQ runs, so what gets installed cannot run
        code during the install itself.

        Args:
            project_path: The directory npm runs in.
            specs: Package specs to install; empty installs everything package.json declares.
            original_manifest: The text of package.json to restore on failure.

        Raises:
            PackageManagerExecutionError: npm exited non-zero.
        """
        try:
            subprocess.run(["npm", "install", "--ignore-scripts", *specs], cwd=project_path, check=True)
        except subprocess.CalledProcessError as exc:
            (Path(project_path) / MANIFEST_FILE).write_text(original_manifest, encoding="utf-8")
            raise PackageManagerExecutionError(f"npm install failed (exit {exc.returncode})") from exc

    def execute_update(self, plan: UpdatePlan) -> None:
        """Apply manifest changes then run npm install. Restores package.json on failure."""
        manifest_path = Path(plan.project_path) / MANIFEST_FILE
        original_content = manifest_path.read_text(encoding="utf-8")

        try:
            pkg = json.loads(original_content)
        except json.JSONDecodeError as exc:
            raise PackageManagerExecutionError(f"package.json is not valid JSON: {exc}") from exc
        apply_direct_specs(pkg, plan)
        write_transitive_overrides(pkg, plan)

        manifest_path.write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
        self.run_npm_install(plan.project_path, [], original_content)

    def install_package(self, package_name: str, version: str | None = None) -> int:
        """Run npm install to add a package to the project. Restores package.json on failure.

        `npm install <spec>` edits package.json itself, so there's no ossiq-side write to
        validate first - only the subprocess outcome to guard, the same way execute_update does.
        """
        spec = f"{package_name}@{version}" if version else package_name
        original_content = (Path(self.project_path) / MANIFEST_FILE).read_text(encoding="utf-8")
        self.run_npm_install(self.project_path, [spec], original_content)
        return 0

    def __repr__(self) -> str:
        return f"{self.package_manager_type.name} Package Manager"
