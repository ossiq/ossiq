"""Gated package add command."""

from dataclasses import dataclass
from typing import Literal

import typer

from ossiq.domain.common import Command, ProjectPackagesRegistry, UserInterfaceType
from ossiq.service.package import fetch_prospective_detail
from ossiq.settings import Settings
from ossiq.sources import project_sources
from ossiq.ui.registry import get_renderer
from ossiq.ui.system import show_error, show_operation_progress


@dataclass(frozen=True)
class CommandAddOptions:
    project_path: str
    package_name: str
    registry_type: Literal["npm", "pypi"] | None
    version: str | None = None
    force: bool = False


def command_add(ctx: typer.Context, options: CommandAddOptions) -> None:
    """Gated package add: shows health insights and warnings before installing."""
    settings: Settings = ctx.obj
    registry_type_map = {
        "npm": ProjectPackagesRegistry.NPM,
        "pypi": ProjectPackagesRegistry.PYPI,
    }

    sources = project_sources.ProjectSources(
        settings=settings,
        project_path=options.project_path,
        production=False,
        narrow_package_registry=registry_type_map.get(options.registry_type or ""),
    )

    with show_operation_progress(settings, f"Fetching package info for {options.package_name}...") as progress:
        with progress():
            with sources:
                detail = fetch_prospective_detail(options.package_name, sources, settings)

    packages_manager = sources.packages_manager

    renderer = get_renderer(
        command=Command.ADD,
        user_interface_type=UserInterfaceType.CONSOLE,
        settings=settings,
    )
    renderer.render(data=detail)

    critical_warnings = [w for w in detail.warnings if w.severity == "critical"]
    if critical_warnings and not options.force:
        show_error(
            f"Package '{options.package_name}' has critical warnings. Use --force to proceed anyway.",
            title="Blocked",
        )
        raise typer.Exit(1)

    version = options.version or (detail.insight.recommended_version if detail.insight else None)
    display_spec = f"{options.package_name}=={version}" if version else options.package_name
    if not typer.confirm(f"\nAdd {display_spec} to your project?"):
        raise typer.Abort()

    result = packages_manager.install_package(options.package_name, version)
    if result != 0:
        raise typer.Exit(result)
