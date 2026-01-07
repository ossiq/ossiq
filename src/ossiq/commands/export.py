"""
Project packages scan command
"""

from dataclasses import dataclass
from typing import Literal

import typer

from ossiq.domain.common import Command, ProjectPackagesRegistry, UserInterfaceType
from ossiq.service import project
from ossiq.settings import Settings
from ossiq.ui.registry import get_renderer
from ossiq.ui.system import show_operation_progress, show_settings
from ossiq.unit_of_work import uow_project


@dataclass(frozen=True)
class CommandExportOptions:
    project_path: str
    registry_type: Literal["npm", "pypi"] | None
    production: bool
    output_format: Literal["json", "csv"]
    output_destination: str


def commnad_export(ctx: typer.Context, options: CommandExportOptions):
    """
    Project data export command.
    """
    settings: Settings = ctx.obj
    registry_type_map = {
        "npm": ProjectPackagesRegistry.NPM,
        "pypi": ProjectPackagesRegistry.PYPI,
    }

    show_settings(
        ctx,
        "Export Settings",
        {
            "project_path": options.project_path,
            "output_format": options.output_format,
            "output_destination": options.output_destination,
            "narrow_registry_type": registry_type_map.get(options.registry_type),
        },
    )

    uow = uow_project.ProjectUnitOfWork(
        settings=settings,
        project_path=options.project_path,
        production=options.production,
        narrow_package_registry=registry_type_map.get(options.registry_type),
    )

    with show_operation_progress(settings, "Collecting project packages data...") as progress:
        with progress():
            project_scan = project.scan(uow)

    renderer = get_renderer(
        command=Command.EXPORT,
        user_interface_type=UserInterfaceType(options.output_format),
        settings=settings,
    )

    renderer.render(
        data=project_scan,
        destination=options.output_destination,
    )
