"""
Project packages status command
"""

from dataclasses import dataclass
from typing import Literal

import typer

from ossiq import timeutil
from ossiq.domain.common import Command, UserInterfaceType
from ossiq.service import project
from ossiq.settings import Settings
from ossiq.sources import project_sources
from ossiq.ui.registry import get_renderer
from ossiq.ui.system import show_scan_progress, show_settings


@dataclass(frozen=True)
class CommandStatusOptions:
    project_path: str
    lag_threshold_days: str = "1y"
    production: bool = False
    allow_prerelease: bool = False
    allow_prerelease_packages: tuple[str, ...] = ()
    registry_type: Literal["npm", "pypi"] | None = None
    presentation: Literal["console", "html"] = "console"
    output_destination: str = "./ossiq_scan_report_{project_name}.html"
    security_only: bool = False
    ignore_packages: tuple[str, ...] = ()


def command_status(ctx: typer.Context, options: CommandStatusOptions):
    """
    Project status command.
    """
    settings: Settings = ctx.obj
    threshold_parsed = timeutil.parse_relative_time_delta(options.lag_threshold_days)
    show_settings(
        ctx,
        "Status Settings",
        {
            "project_path": options.project_path,
            "lag_threshold_days": f"{threshold_parsed.days} days",
            "production": options.production,
            "security": options.security_only,
            "narrow_registry_type": project_sources.REGISTRY_TYPE_MAP.get(options.registry_type or ""),
            "ignore_packages": options.ignore_packages or None,
        },
    )

    sources = project_sources.build_project_sources(
        settings,
        options.project_path,
        options.production,
        options.allow_prerelease,
        options.allow_prerelease_packages,
        options.registry_type,
        security_only=options.security_only,
        ignore_packages=options.ignore_packages,
    )

    with show_scan_progress(settings) as on_step:
        project_scan = project.scan(sources, on_step=on_step)

    renderer = get_renderer(
        command=Command.STATUS, user_interface_type=UserInterfaceType(options.presentation), settings=settings
    )

    renderer.render(
        data=project_scan,
        lag_threshold_days=threshold_parsed.days,
        destination=options.output_destination,
        full=True,
    )
