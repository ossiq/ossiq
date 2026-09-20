"""Single package deep-dive command."""

from dataclasses import dataclass
from typing import Literal

import typer
from rich.console import Console

from ossiq.domain.common import Command, ProjectPackagesRegistry, UserInterfaceType
from ossiq.service.package import build_installed_detail, fetch_prospective_detail, matches
from ossiq.service.project.scan import scan
from ossiq.settings import Settings
from ossiq.sources import project_sources
from ossiq.strategy.overrides import StrategyPlan
from ossiq.strategy.pyramid import DEFAULT_STRATEGY, UpdateStrategy
from ossiq.ui.registry import get_renderer
from ossiq.ui.system import show_operation_progress, show_scan_progress


@dataclass(frozen=True)
class CommandInfoOptions:
    project_path: str
    package_name: str
    registry_type: Literal["npm", "pypi"] | None
    allow_prerelease: bool = False
    allow_prerelease_packages: tuple[str, ...] = ()
    ignore_packages: tuple[str, ...] = ()
    output_format: Literal["console", "agent"] = "console"
    update_strategy: UpdateStrategy = DEFAULT_STRATEGY
    strategy_overrides: tuple[tuple[str, UpdateStrategy], ...] = ()


def command_info(ctx: typer.Context, options: CommandInfoOptions) -> None:
    """Single package deep-dive command."""
    settings: Settings = ctx.obj
    registry_type_map = {
        "npm": ProjectPackagesRegistry.NPM,
        "pypi": ProjectPackagesRegistry.PYPI,
    }

    output_ui = UserInterfaceType(options.output_format)
    is_agent = output_ui == UserInterfaceType.AGENT

    sources = project_sources.ProjectSources(
        settings=settings,
        project_path=options.project_path,
        production=False,
        narrow_package_registry=registry_type_map.get(options.registry_type or ""),
        allow_prerelease=options.allow_prerelease,
        allow_prerelease_packages=options.allow_prerelease_packages,
        strategy=StrategyPlan(default=options.update_strategy, overrides=dict(options.strategy_overrides)),
        ignore_packages=options.ignore_packages,
    )

    # Agent format prints JSON to stdout, so progress and warnings must stay silent.
    if is_agent:
        scan_result = scan(sources)
    else:
        with show_scan_progress(settings) as progress:
            scan_result = scan(sources, progress=progress)

    if scan_result.manifest_lock_divergent and not is_agent:
        Console().print(
            f"[yellow]Warning:[/yellow] pyproject.toml and uv.lock are out of sync for: "
            f"[bold]{', '.join(scan_result.manifest_lock_divergent)}[/bold]. "
            "Run [bold]uv lock[/bold] to regenerate the lockfile."
        )

    all_records = scan_result.production_packages + scan_result.optional_packages + scan_result.transitive_packages
    matched = [r for r in all_records if matches(r, options.package_name)]

    if matched:
        detail = build_installed_detail(matched, scan_result, options.package_name, sources, settings)
    elif is_agent:
        detail = fetch_prospective_detail(options.package_name, sources, settings)
    else:
        # Package not in this project — run the prospective flow.
        # sources.__enter__ was already called inside scan(), so packages_registry is live.
        with show_operation_progress(settings, f"Fetching prospective info for {options.package_name}...") as progress:
            with progress():
                detail = fetch_prospective_detail(options.package_name, sources, settings)

    renderer = get_renderer(
        command=Command.INFO,
        user_interface_type=output_ui,
        settings=settings,
    )
    renderer.render(data=detail)
