"""
Project packages scan command
"""

from dataclasses import dataclass
from typing import Literal

import typer

from ossiq import timeutil
from ossiq.domain.common import Command, ProjectPackagesRegistry, UserInterfaceType
from ossiq.service import project
from ossiq.settings import Settings
from ossiq.ui.registry import get_renderer
from ossiq.ui.system import show_operation_progress, show_settings
from ossiq.unit_of_work import uow_project


@dataclass(frozen=True)
class CommandScanOptions:
    project_path: str
    lag_threshold_days: str
    production: bool
    allow_prerelease: bool
    allow_prerelease_packages: tuple[str, ...]
    registry_type: Literal["npm", "pypi"] | None
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

    # Get renderer using new registry pattern (mirrors package manager adapter pattern)
    renderer = get_renderer(
        command=Command.SCAN, user_interface_type=UserInterfaceType(options.presentation), settings=settings
    )

    renderer.render(
        data=project_scan,
        lag_threshold_days=threshold_parsed.days,
        destination=options.output_destination,
    )
