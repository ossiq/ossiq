"""
Project packages status command
"""

from dataclasses import dataclass
from typing import Literal

import typer

from ossiq import timeutil
from ossiq.domain.common import Command, UserInterfaceType
from ossiq.service.completeness import check_security_data_complete
from ossiq.service.project.scan import scan
from ossiq.settings import Settings
from ossiq.sources import project_sources
from ossiq.strategy.overrides import StrategyPlan
from ossiq.strategy.pyramid import DEFAULT_STRATEGY, UpdateStrategy
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
    update_strategy: UpdateStrategy = DEFAULT_STRATEGY
    strategy_overrides: tuple[tuple[str, UpdateStrategy], ...] = ()
    ignore_packages: tuple[str, ...] = ()
    output_format: Literal["console", "agent"] = "console"
    full: bool = False
    allow_partial: bool = False


def command_status(ctx: typer.Context, options: CommandStatusOptions) -> None:
    """
    Project status command.
    """
    settings: Settings = ctx.obj
    output_ui = UserInterfaceType(options.output_format)
    is_agent = output_ui == UserInterfaceType.AGENT
    threshold_parsed = timeutil.parse_relative_time_delta(options.lag_threshold_days)
    strategy = StrategyPlan(default=options.update_strategy, overrides=dict(options.strategy_overrides))

    if not is_agent:
        show_settings(
            ctx,
            "Status Settings",
            {
                "project_path": options.project_path,
                "lag_threshold_days": f"{threshold_parsed.days} days",
                "production": options.production,
                "update_strategy": options.update_strategy.value,
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
        strategy=strategy,
        ignore_packages=options.ignore_packages,
    )

    # Agent format prints JSON to stdout, so the progress stepper must stay silent.
    if is_agent:
        project_scan = scan(sources)
    else:
        with show_scan_progress(settings) as progress:
            project_scan = scan(sources, progress=progress)

    check_security_data_complete(
        project_scan.data_completeness,
        options.update_strategy,
        allow_partial=options.allow_partial,
    )

    renderer = get_renderer(command=Command.STATUS, user_interface_type=output_ui, settings=settings)

    renderer.render(
        data=project_scan,
        lag_threshold_days=threshold_parsed.days,
        full=options.full,
        update_strategy=options.update_strategy.value,
    )
