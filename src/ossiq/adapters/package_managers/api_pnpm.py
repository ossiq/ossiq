"""
Support of pnpm package manager: detection and a manifest-only scan.

Applying updates and adding packages are refused by the base class until pnpm can run them, so
OSS IQ never falls back to `npm install` inside a pnpm project.
"""

import json
from pathlib import Path

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.adapters.package_managers.npm import manifest
from ossiq.adapters.package_managers.npm.constants import MANIFEST_FILE
from ossiq.adapters.package_managers.npm.engines import declared_engine_floors
from ossiq.domain.packages_manager import PNPM, PNPM_LOCKFILE, PackageManagerType
from ossiq.domain.project import Project
from ossiq.settings import Settings

WORKSPACE_FILE = "pnpm-workspace.yaml"


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
    """Package manager adapter for pnpm: reads package.json only, for now."""

    settings: Settings
    package_manager_type: PackageManagerType = PNPM
    project_path: str

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

    def project_info(self) -> Project:
        """Extract dependencies from package.json."""
        data = json.loads((Path(self.project_path) / MANIFEST_FILE).read_text(encoding="utf-8"))

        # shortcut: pnpm-lock.yaml is not read, so installed versions are guessed from declared
        # ranges; upgrade when the lockfile parser lands.
        return Project(
            package_manager_type=self.package_manager_type,
            name=data.get("name", Path(self.project_path).name),
            project_path=self.project_path,
            dependency_tree=manifest.parse_package_json(data),
            engine_constraints=declared_engine_floors(data.get("engines")),
            has_lockfile=False,
            declares_esm=data.get("type") == "module",
        )

    def __repr__(self) -> str:
        return f"{self.package_manager_type.name} Package Manager"
