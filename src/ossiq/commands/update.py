"""Generate an atomic update script for solver-recommended package versions."""

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


def command_update(ctx: typer.Context, options: CommandUpdateOptions) -> None:
    """Generate atomic update script for solver-recommended package versions."""
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
    plan = build_update_plan(scan_result, package_manager_name)

    if not plan.direct_entries and not plan.transitive_entries:
        typer.echo(HELP_UPDATE_NO_RECOMMENDATIONS)
        return

    script = uow.packages_manager.generate_update_script(plan)

    renderer = get_renderer(Command.UPDATE, UserInterfaceType.CONSOLE, settings)
    renderer.render(data=plan, script=script)
