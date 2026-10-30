"""
Support of pnpm package manager: detection, a scan of package.json and pnpm-lock.yaml, and
applying a plan or adding a package through pnpm itself, so OSS IQ never runs `npm install` inside
a pnpm project.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import subprocess
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import requests

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.adapters.api_npm import PackageRegistryApiNpm
from ossiq.adapters.package_managers.npm import manifest
from ossiq.adapters.package_managers.npm.constants import MANIFEST_FILE
from ossiq.adapters.package_managers.npm.engines import declared_engine_floors
from ossiq.adapters.package_managers.npm.writer import add_peer_repairs, apply_direct_specs
from ossiq.adapters.package_managers.pnpm.constants import WORKSPACE_FILE
from ossiq.adapters.package_managers.pnpm.lockfile import (
    DeclaredRanges,
    PnpmTreeBuilderV9,
    installed_copies,
    load_lockfile,
    registry_parents,
)
from ossiq.adapters.package_managers.pnpm.settings import pnpm_settings_layers, release_cutoff_from_pnpm_settings
from ossiq.adapters.package_managers.pnpm.writer import edit_workspace, load_workspace
from ossiq.adapters.package_managers.utils import find_lockfile_parser
from ossiq.domain.exceptions import (
    ApplicationError,
    PackageManagerExecutionError,
    PackageManagerLockfileParsingError,
    PackageManagerUpdateIncomplete,
)
from ossiq.domain.packages_manager import PNPM, PNPM_LOCKFILE, PackageManagerType
from ossiq.domain.project import Dependency, Project
from ossiq.domain.release_cutoff import ReleaseCutoff
from ossiq.settings import Settings
from ossiq.tree.builder import NodeKey

if TYPE_CHECKING:
    from ossiq.service.update import UpdatePlan

logger = logging.getLogger(__name__)

# Every file a pnpm command may rewrite in the project root; a failed run puts all of them back.
PROJECT_FILES = (MANIFEST_FILE, PNPM_LOCKFILE.name, WORKSPACE_FILE)

PNPM_MISSING_HINT = "Install pnpm 10 or newer and put it on PATH. The project files were left as they were."


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


@contextmanager
def restore_on_failure(root: Path) -> Iterator[None]:
    """Put the project files back as they were if the block raises, removing any it created.

    Catches BaseException, not Exception: an install interrupted with Ctrl-C leaves a half-written
    project too. Nothing is swallowed.

    Args:
        root: The project directory.
    """
    before = {name: (root / name).read_bytes() if (root / name).exists() else None for name in PROJECT_FILES}
    try:
        yield
    except BaseException:
        for name, content in before.items():
            if content is None:
                (root / name).unlink(missing_ok=True)
            else:
                (root / name).write_bytes(content)
        raise


def run_pnpm(project_path: str, command: str, *args: str) -> None:
    """Run `pnpm <command>` in *project_path* without lifecycle scripts.

    Install scripts stay off for every pnpm run OSS IQ makes, so what gets installed cannot run
    code during the install itself. Restoring the project is left to the caller.

    Args:
        project_path: The directory pnpm runs in.
        command: The pnpm command, e.g. "install" or "add".
        *args: Further arguments for the command.

    Raises:
        PackageManagerExecutionError: pnpm is not installed, or exited non-zero.
    """
    try:
        subprocess.run(["pnpm", command, "--ignore-scripts", *args], cwd=project_path, check=True)
    except FileNotFoundError as exc:
        raise PackageManagerExecutionError("pnpm was not found on PATH", hint=PNPM_MISSING_HINT) from exc
    except subprocess.CalledProcessError as exc:
        raise PackageManagerExecutionError(f"pnpm {command} failed (exit {exc.returncode})") from exc


def check_targets_landed(root: Path, plan: UpdatePlan) -> None:
    """Raise when the lockfile pnpm just wrote lacks a version the plan targets.

    pnpm exits 0 when an override the user wrote, or its release-age fallback, keeps a package off
    the planned version, so a clean exit alone does not mean the plan landed.
    shortcut: a target counts as landed when any copy of it is installed, so a nested copy that
    stayed put beside a moved one goes unreported; check per edge if that hides real misses.

    Args:
        root: The project directory, after the last install pass.
        plan: The plan that was applied.

    Raises:
        PackageManagerUpdateIncomplete: At least one target is not installed.
    """
    copies = installed_copies(load_lockfile((root / PNPM_LOCKFILE.name).read_text(encoding="utf-8")))
    missed = []
    for entry in plan.all_entries:
        if (entry.package_name, entry.recommended_version) in copies:
            continue
        have = sorted(version for name, version in copies if name == entry.package_name)
        missed.append(f"{entry.display_name} {entry.recommended_version} (installed: {', '.join(have) or 'none'})")
    if missed:
        raise PackageManagerUpdateIncomplete(f"pnpm did not install {'; '.join(missed)}")


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

    def execute_update(self, plan: UpdatePlan, on_pass: Callable[[int, int], None] | None = None) -> None:
        """Write the plan into package.json and pnpm-workspace.yaml, then `pnpm install`.

        Direct ranges go to package.json, or to the catalog entry for a `catalog:` dependency;
        transitive picks go to `overrides` in pnpm-workspace.yaml, with the record of what OSS IQ
        wrote kept in package.json. A plan with ordering constraints (see `assign_install_passes`)
        installs in passes, each cumulative; every pass but the last only writes the lockfile, so
        the last one installs. A failure in any pass restores package.json, pnpm-lock.yaml and
        pnpm-workspace.yaml.

        Args:
            plan: The plan to apply.
            on_pass: Called as `(number, total)` before each pass of a multi-pass plan.

        Raises:
            PackageManagerExecutionError: package.json or pnpm-workspace.yaml cannot be read as
                what they should be, pnpm is missing, or pnpm failed in some pass.
            PackageManagerUpdateIncomplete: pnpm succeeded but left some target uninstalled; the
                project files keep what was written.
        """
        root = Path(plan.project_path)
        original_content = (root / MANIFEST_FILE).read_text(encoding="utf-8")
        try:
            pkg = json.loads(original_content)
        except json.JSONDecodeError as exc:
            raise PackageManagerExecutionError(f"package.json is not valid JSON: {exc}") from exc

        workspace_path = root / WORKSPACE_FILE
        original_workspace = workspace_path.read_text(encoding="utf-8") if workspace_path.exists() else None
        load_workspace(original_workspace)  # a file that cannot be edited fails here, before any write

        total, number = plan.pass_count, 1
        try:
            with restore_on_failure(root):
                for number in range(1, total + 1):
                    if total > 1 and on_pass is not None:
                        on_pass(number, total)
                    step, draft = plan.through_pass(number), copy.deepcopy(pkg)
                    apply_direct_specs(draft, step)
                    add_peer_repairs(draft, step)
                    workspace_text = edit_workspace(original_workspace, draft, step)
                    if workspace_text is not None:
                        workspace_path.write_text(workspace_text, encoding="utf-8")
                    (root / MANIFEST_FILE).write_text(json.dumps(draft, indent=2) + "\n", encoding="utf-8")
                    flags = ["--no-frozen-lockfile", *(["--lockfile-only"] if number < total else [])]
                    run_pnpm(plan.project_path, "install", *flags)
        except PackageManagerExecutionError as exc:
            if total > 1:
                raise PackageManagerExecutionError(f"{exc} in pass {number} of {total}", hint=exc.hint) from exc
            raise
        # Outside the restore: the install succeeded, so what did land stays.
        check_targets_landed(root, plan)

    def install_package(self, package_name: str, version: str | None = None) -> int:
        """Run `pnpm add` for a package. Restores package.json, pnpm-lock.yaml and pnpm-workspace.yaml on failure.

        `pnpm add <spec>` edits package.json itself, so there is no OSS IQ-side write to validate
        first, only the outcome of the run to guard.

        Raises:
            PackageManagerExecutionError: pnpm is missing, or exited non-zero.
        """
        spec = f"{package_name}@{version}" if version else package_name
        with restore_on_failure(Path(self.project_path)):
            run_pnpm(self.project_path, "add", spec)
        return 0

    def __repr__(self) -> str:
        return f"{self.package_manager_type.name} Package Manager"
