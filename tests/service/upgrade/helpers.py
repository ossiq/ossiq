"""A fake npm-shaped project and package manager for driving the upgrade engine on real files."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from ossiq.domain.common import ConstraintType
from ossiq.domain.exceptions import PackageManagerExecutionError
from ossiq.domain.update_plan import UpdateEntry, UpdatePlan
from ossiq.service.update.models import PlanOptions
from ossiq.service.upgrade import engine
from ossiq.service.upgrade.engine import UpgradeEnv
from ossiq.service.upgrade.view import StepPreview, UpgradeView

# Green on the starting tree, red once vite moves: what a real suite does when an upgrade breaks it.
BREAKS_ON_UPGRADE = 'grep -q \'"vite": "1.0.0"\' package.json'
FIXABLE = f"{BREAKS_ON_UPGRADE} || test -f fixed"


class FakeManager:
    """npm-shaped: package.json holds `dependencies`, and an update rewrites the versions."""

    supports_upgrade_session = True
    package_manager_type = SimpleNamespace(name="npm")

    def __init__(self, root: Path) -> None:
        self.root = root
        self.synced = 0
        self.refuse = False

    def snapshot_files(self) -> tuple[str, ...]:
        return ("package.json",)

    def execute_update(self, plan: UpdatePlan) -> None:
        manifest = self.root / "package.json"
        deps = json.loads(manifest.read_text())
        for entry in plan.all_entries:
            deps[entry.identity] = entry.recommended_version
        manifest.write_text(json.dumps(deps))
        if self.refuse:
            raise PackageManagerExecutionError("npm install failed (exit 1)")

    def sync_environment(self) -> None:
        self.synced += 1


class Project:
    """A directory of `{package: version}`, a fake manager over it, and a planner reading both."""

    def __init__(self, root: Path, installed: dict[str, str], targets: dict[str, str]) -> None:
        self.root, self.targets, self.manager = root, targets, FakeManager(root)
        (root / "package.json").write_text(json.dumps(installed))

    def installed(self) -> dict[str, str]:
        return json.loads((self.root / "package.json").read_text())

    def plan(self, options: PlanOptions) -> tuple[Any, Any, UpdatePlan]:
        entries = [
            UpdateEntry(
                package_name=name,
                current_version=version,
                recommended_version=self.targets[name],
                is_direct=True,
                reason=None,
                constraint_type=ConstraintType.DECLARED,
            )
            for name, version in sorted(self.installed().items())
            if version != self.targets[name]
        ]
        plan = UpdatePlan(
            project_name="demo",
            project_path=str(self.root),
            registry_type="NPM",
            package_manager_name="npm",
            direct_entries=entries,
            transitive_entries=[],
        )
        sources = SimpleNamespace(
            packages_manager=self.manager,
            packages_registry=SimpleNamespace(difference_versions=lambda a, b: SimpleNamespace(diff_index=5)),
        )
        scan = SimpleNamespace(
            production_packages=[], optional_packages=[], transitive_packages=[], packages_registry="NPM"
        )
        return sources, scan, plan


def make_project(tmp_path: Path, monkeypatch: Any) -> Project:
    """The fake project, with the engine's package-manager lookup and preview pointed at fakes."""
    project = Project(tmp_path, {"vite": "1.0.0", "zod": "1.0.0"}, {"vite": "2.0.0", "zod": "2.0.0"})
    monkeypatch.setattr(engine, "find_manager", lambda settings, root, name: project.manager)
    monkeypatch.setattr(
        engine,
        "build_preview",
        lambda sources, scan, step, fetch: StepPreview(packages=(), engine_context=cast(Any, None)),
    )
    return project


def env_for(project: Project) -> UpgradeEnv:
    return UpgradeEnv(settings=cast(Any, None), plan=project.plan)


def options(project: Project) -> PlanOptions:
    return PlanOptions(project_path=str(project.root))


def start(project: Project, **kwargs: Any) -> UpgradeView:
    return engine.start(env_for(project), options(project), **kwargs)
