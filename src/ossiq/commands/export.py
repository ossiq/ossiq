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
    schema_version: str | None
    allow_prerelease: bool
    allow_prerelease_packages: tuple[str, ...]


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
            "narrow_registry_type": registry_type_map[options.registry_type] if options.registry_type else None,
        },
    )

    uow = uow_project.ProjectUnitOfWork(
        settings=settings,
        project_path=options.project_path,
        production=options.production,
        allow_prerelease=options.allow_prerelease,
        allow_prerelease_packages=options.allow_prerelease_packages,
        narrow_package_registry=registry_type_map[options.registry_type] if options.registry_type else None,
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
        schema_version=options.schema_version,
    )
