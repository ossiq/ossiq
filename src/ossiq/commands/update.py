"""Generate an atomic update script for solver-recommended package versions."""

from dataclasses import dataclass
from typing import Literal

import typer

from ossiq.domain.common import Command, ProjectPackagesRegistry, UserInterfaceType
from ossiq.messages import HELP_UPDATE_NO_RECOMMENDATIONS
from ossiq.service import project
from ossiq.service.update import build_update_plan
from ossiq.settings import Settings
from ossiq.ui.registry import get_renderer
from ossiq.ui.system import show_operation_progress
from ossiq.unit_of_work import uow_project

REGISTRY_TYPE_MAP = {
    "npm": ProjectPackagesRegistry.NPM,
    "pypi": ProjectPackagesRegistry.PYPI,
}


@dataclass(frozen=True)
class CommandUpdateOptions:
    """Options for the update command."""

    project_path: str
    registry_type: Literal["npm", "pypi"] | None = None
    allow_prerelease: bool = False
    allow_prerelease_packages: tuple[str, ...] = ()
    production: bool = False


def command_update(ctx: typer.Context, options: CommandUpdateOptions) -> None:
    """Generate atomic update script for solver-recommended package versions."""
    settings: Settings = ctx.obj

    uow = uow_project.ProjectUnitOfWork(
        settings=settings,
        project_path=options.project_path,
        production=options.production,
        allow_prerelease=options.allow_prerelease,
        allow_prerelease_packages=options.allow_prerelease_packages,
        narrow_package_registry=REGISTRY_TYPE_MAP.get(options.registry_type or ""),
        use_solver=True,
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
