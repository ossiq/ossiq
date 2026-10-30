"""
Support of pnpm package manager: detection and a scan of package.json and pnpm-lock.yaml.

Applying updates and adding packages are refused by the base class until pnpm can run them, so
OSS IQ never falls back to `npm install` inside a pnpm project.
"""

import json
import logging
import os
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path

import requests

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.adapters.api_npm import PackageRegistryApiNpm
from ossiq.adapters.package_managers.npm import manifest
from ossiq.adapters.package_managers.npm.constants import MANIFEST_FILE
from ossiq.adapters.package_managers.npm.engines import declared_engine_floors
from ossiq.adapters.package_managers.pnpm.constants import WORKSPACE_FILE
from ossiq.adapters.package_managers.pnpm.lockfile import (
    DeclaredRanges,
    PnpmTreeBuilderV9,
    load_lockfile,
    registry_parents,
)
from ossiq.adapters.package_managers.pnpm.settings import pnpm_settings_layers, release_cutoff_from_pnpm_settings
from ossiq.adapters.package_managers.utils import find_lockfile_parser
from ossiq.domain.exceptions import ApplicationError, PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import PNPM, PNPM_LOCKFILE, PackageManagerType
from ossiq.domain.project import Dependency, Project
from ossiq.domain.release_cutoff import ReleaseCutoff
from ossiq.settings import Settings
from ossiq.tree.builder import NodeKey

logger = logging.getLogger(__name__)


def fetch_declared_ranges(parents: Iterable[NodeKey], settings: Settings) -> DeclaredRanges:
    """Fetch what each registry package declares for its dependencies, which pnpm-lock.yaml leaves out.

    The solver's hard clauses for transitive packages come from these ranges. Same contract as the
    PyPI enrichment: when the registry cannot answer, return nothing and let the scan carry on
    without transitive constraints. The scan fetches the same documents later, so they come from
    the HTTP cache by then.

    Args:
        parents: The (name, version) of each package to look up.
        settings: Scan settings, for the registry client.

    Returns:
        {(name, version): {dependency name: declared range}}, optional dependencies included.
    """
    parents = list(parents)
    if not parents:
        return {}
    registry = PackageRegistryApiNpm(settings)
    try:
        registry.packages_info_batch(list(dict.fromkeys(name for name, _ in parents)))
    except (ApplicationError, requests.RequestException) as exc:
        logger.debug("pnpm: declared ranges are unavailable: %s", exc)
        return {}
    return {
        (name, version): {
            **registry.package_version_optional_requires(name, version),
            **registry.package_version_requires(name, version),
        }
        for name, version in parents
    }


def declared_package_manager(project_data: dict) -> str | None:
    """Return the manager name package.json declares, or None when it declares none.

    Reads `packageManager` ("pnpm@10.4.1+sha512...") first, then `devEngines.packageManager`,
    which holds one object or a list of them.

    Args:
        project_data: The decoded package.json.

    Returns:
        The declared manager name, e.g. "pnpm" or "npm".
    """
    declared = project_data.get("packageManager")
    if isinstance(declared, str):
        return declared.partition("@")[0]

    dev_engines = project_data.get("devEngines")
    entry = dev_engines.get("packageManager") if isinstance(dev_engines, dict) else None
    if isinstance(entry, list):
        entry = entry[0] if entry else None
    return entry.get("name") if isinstance(entry, dict) else None


class PackageManagerJsPnpm(AbstractPackageManagerApi):
    """Package manager adapter for pnpm: reads package.json and pnpm-lock.yaml (lockfile v9)."""

    settings: Settings
    package_manager_type: PackageManagerType = PNPM
    project_path: str

    # Lockfile version -> the parser method; v9 is what pnpm 9 to 12 write.
    supported_versions: dict[str, str] = {"lockfileVersion == '9.0'": "parse_lockfile_v9"}

    @staticmethod
    def has_package_manager(project_path: str) -> bool:
        """Detect a pnpm project: what package.json declares wins, pnpm files are the fallback.

        A declaration wins over files because a stale pnpm-lock.yaml in an npm project must not
        hand that project to pnpm. An unreadable package.json is left to the npm adapter.
        """
        root = Path(project_path)
        try:
            data = json.loads((root / MANIFEST_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False

        declared = declared_package_manager(data)
        if declared:
            return declared == "pnpm"
        return (root / PNPM_LOCKFILE.name).exists() or (root / WORKSPACE_FILE).exists()

    def __init__(self, project_path: str, settings: Settings):
        super().__init__()
        self.settings = settings
        self.project_path = project_path

    def get_lockfile_parser(self, lockfile_version: str | None) -> Callable[..., Dependency]:
        """Find the parser for a lockfile version.

        Raises:
            PackageManagerLockfileParsingError: No parser handles that version.
        """
        handler_name = find_lockfile_parser(self.supported_versions, {"lockfileVersion": lockfile_version})
        if not handler_name or not hasattr(self, handler_name):
            raise PackageManagerLockfileParsingError(
                f"There's no parser for pnpm lockfile version `{lockfile_version}`"
            )
        return getattr(self, handler_name)

    def parse_lockfile_v9(self, lockfile_data: dict, project_name: str, project_data: dict) -> Dependency:
        """Lockfile parser for pnpm v9.

        Args:
            lockfile_data: The project document of pnpm-lock.yaml.
            project_name: The name of the project's own package.
            project_data: The decoded package.json, for the version and the overrides OSS IQ wrote.
        """
        root = (project_name, project_data.get("version", "0.0.0"))
        declared_ranges = fetch_declared_ranges(registry_parents(lockfile_data), self.settings)
        builder = PnpmTreeBuilderV9(lockfile_data, root, declared_ranges)
        ossiq_overrides: dict[str, str] = project_data.get("ossiq:metadata", {}).get("overrides", {})
        dependency_tree = builder.build_graph(project_name, ossiq_overrides)

        # No dependencies - no analysis, something wrong
        if not dependency_tree or (not dependency_tree.dependencies and not dependency_tree.optional_dependencies):
            raise PackageManagerLockfileParsingError("Could not parse pnpm lockfile")
        return dependency_tree

    def project_info(self) -> Project:
        """Extract dependencies from package.json and, when there is one, pnpm-lock.yaml."""
        root = Path(self.project_path)
        data = json.loads((root / MANIFEST_FILE).read_text(encoding="utf-8"))
        name = data.get("name", root.name)
        lockfile = root / PNPM_LOCKFILE.name

        if lockfile.exists():
            lockfile_data = load_lockfile(lockfile.read_text(encoding="utf-8"))
            parse_lockfile = self.get_lockfile_parser(lockfile_data.get("lockfileVersion"))
            dependency_tree = parse_lockfile(lockfile_data, name, data)
        else:
            dependency_tree = manifest.parse_package_json(data)

        return Project(
            package_manager_type=self.package_manager_type,
            name=name,
            project_path=self.project_path,
            dependency_tree=dependency_tree,
            engine_constraints=declared_engine_floors(data.get("engines")),
            has_lockfile=lockfile.exists(),
            declares_esm=data.get("type") == "module",
        )

    def release_cutoff(self) -> ReleaseCutoff | None:
        """Return the `minimumReleaseAge` cutoff `pnpm install` will enforce for this project.

        Reads what pnpm reads (the environment, `pnpm-workspace.yaml`, the global config), since
        `apply` runs pnpm with this process's environment.
        """
        layers = pnpm_settings_layers(Path(self.project_path), os.environ)
        return release_cutoff_from_pnpm_settings(layers, now=datetime.now(UTC))

    def __repr__(self) -> str:
        return f"{self.package_manager_type.name} Package Manager"
