"""
Project packages scan command
"""

from dataclasses import dataclass
from typing import Literal

import typer

from ossiq import timeutil
from ossiq.domain.common import Command, UserInterfaceType
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
    full_output: bool = False
    security_only: bool = False
    ignore_packages: tuple[str, ...] = ()


def commnad_scan(ctx: typer.Context, options: CommandScanOptions):
    """
    Project scan command.
    """
    settings: Settings = ctx.obj
    threshold_parsed = timeutil.parse_relative_time_delta(options.lag_threshold_days)
    show_settings(
        ctx,
        "Scan Settings",
        {
            "project_path": options.project_path,
            "lag_threshold_days": f"{threshold_parsed.days} days",
            "production": options.production,
            "security": options.security_only,
            "narrow_registry_type": uow_project.REGISTRY_TYPE_MAP.get(options.registry_type or ""),
            "ignore_packages": options.ignore_packages or None,
        },
    )

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
        full=options.full_output,
    )
