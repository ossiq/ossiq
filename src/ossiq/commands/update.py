"""Generate an atomic update script for solver-recommended package versions."""

import json
import os
from dataclasses import dataclass
from typing import Literal

import typer

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.messages import HELP_UPDATE_NO_RECOMMENDATIONS
from ossiq.service import project
from ossiq.service.update import build_update_plan
from ossiq.settings import Settings
from ossiq.ui.registry import get_renderer
from ossiq.ui.system import show_operation_progress
from ossiq.unit_of_work import uow_project

NPM_STATE_FILE = ".ossiq_npm_state.json"


@dataclass(frozen=True)
class CommandUpdateOptions:
    """Options for the update command."""

    project_path: str
    registry_type: Literal["npm", "pypi"] | None = None
    allow_prerelease: bool = False
    allow_prerelease_packages: tuple[str, ...] = ()
    production: bool = False
    security_only: bool = False
    ignore_packages: tuple[str, ...] = ()
    pin: bool = False
    npm_overrides_diff: bool = False


def handle_npm_overrides_diff(project_path: str) -> None:
    """Restore package.json overrides from saved state file and delete the state file."""
    state_path = os.path.join(project_path, NPM_STATE_FILE)
    manifest_path = os.path.join(project_path, "package.json")

    if not os.path.exists(state_path):
        typer.echo(f"State file not found: {state_path}", err=True)
        raise typer.Exit(1)

    with open(state_path) as f:
        state = json.load(f)
    with open(manifest_path) as f:
        pkg = json.load(f)

    recommended = set(state["recommended_packages"])
    restored = {k: v for k, v in state["original_overrides"].items() if k not in recommended}
    pkg["overrides"] = restored or {}

    with open(manifest_path, "w") as f:
        json.dump(pkg, f, indent=2)

    os.unlink(state_path)
    typer.echo(f"Overrides restored: {len(restored)} entries kept, {len(recommended)} recommended packages removed.")


def command_update(ctx: typer.Context, options: CommandUpdateOptions) -> None:
    """Generate atomic update script for solver-recommended package versions."""
    if options.npm_overrides_diff:
        handle_npm_overrides_diff(options.project_path)
        return

    settings: Settings = ctx.obj

    uow = uow_project.build_project_uow(
        settings,
        options.project_path,
        options.production,
        options.allow_prerelease,
        options.allow_prerelease_packages,
        options.registry_type,
        security_only=options.security_only,
        ignore_packages=options.ignore_packages,
    )

    with show_operation_progress(settings, "Resolving recommended versions...") as progress:
        with progress():
            scan_result = project.scan(uow)

    package_manager_name = uow.packages_manager.package_manager_type.name
    plan = build_update_plan(scan_result, package_manager_name, pin=options.pin)

    if not plan.direct_entries and not plan.transitive_entries:
        typer.echo(HELP_UPDATE_NO_RECOMMENDATIONS)
        return

    script = uow.packages_manager.generate_update_script(plan)

    renderer = get_renderer(Command.UPDATE, UserInterfaceType.CONSOLE, settings)
    renderer.render(data=plan, script=script)
