"""
Project packages scan command
"""

from dataclasses import dataclass
from typing import Literal

import typer

from ossiq import timeutil
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.presentation.system import show_operation_progress, show_settings
from ossiq.presentation.views import Command, get_presentation_view
from ossiq.service import project
from ossiq.settings import Settings
from ossiq.unit_of_work import uow_project


@dataclass(frozen=True)
class CommandScanOptions:
    project_path: str
    lag_threshold_days: str
    production: bool
    registry_type: Literal["npm", "pypi"]
    presentation: Literal["console", "html"]
    output_destination: str


def commnad_scan(ctx: typer.Context, options: CommandScanOptions):
    """
    Project scan command.
    """
    settings: Settings = ctx.obj
    threshold_parsed = timeutil.parse_relative_time_delta(options.lag_threshold_days)
    registry_type_map = {
        "npm": ProjectPackagesRegistry.NPM,
        "pypi": ProjectPackagesRegistry.PYPI,
    }

    show_settings(
        ctx,
        "Scan Settings",
        {
            "project_path": options.project_path,
            "lag_threshold_days": f"{threshold_parsed.days} days",
            "production": options.production,
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

    # FIXME: use similar pattern to UoW to "commit" output on exit
    presentation_view = get_presentation_view(Command.SCAN, options.presentation)

    presentation_view(
        project_scan,
        threshold_parsed.days,
        destination=options.output_destination,
    )
