"""CLI handlers for NPM helper sub-commands."""

from typing import Annotated

import typer

from ossiq.adapters.package_managers.api_npm import PackageManagerJsNpm
from ossiq.commands.plan import parse_override_specs
from ossiq.messages import HELP_OVERRIDE_PACKAGE, HELP_PIN_ALL, HELP_REWRITE_VERSIONS, HELP_SECURITY_ONLY
from ossiq.service import project
from ossiq.service.update import build_update_plan
from ossiq.settings import Settings
from ossiq.ui.system import show_operation_progress
from ossiq.unit_of_work import uow_project

npm_helpers_app = typer.Typer(name="npm", help="NPM helper utilities")


@npm_helpers_app.command("apply-state")
def npm_apply_state(
    ctx: typer.Context,
    project_path: Annotated[str, typer.Argument()] = ".",
    allow_prerelease: Annotated[
        bool, typer.Option("--allow-prerelease", help="Include pre-release versions in drift calculations")
    ] = False,
    allow_prerelease_package: Annotated[
        list[str] | None,
        typer.Option("--allow-prerelease-package", help="Allow pre-release for a specific package (repeatable)"),
    ] = None,
    production: Annotated[bool, typer.Option("--production", help="Consider production dependencies only")] = False,
    security: Annotated[
        bool,
        typer.Option("--security", is_flag=True, help=HELP_SECURITY_ONLY),
    ] = False,
    ignore: Annotated[
        list[str] | None,
        typer.Option("--ignore", "-i", help="Exclude package from solver recommendations (repeatable)"),
    ] = None,
    pin_all: Annotated[bool, typer.Option("--pin-all", is_flag=True, help=HELP_PIN_ALL)] = False,
    rewrite_versions: Annotated[
        bool, typer.Option("--rewrite-versions", is_flag=True, help=HELP_REWRITE_VERSIONS)
    ] = False,
    override: Annotated[list[str] | None, typer.Option("--override", help=HELP_OVERRIDE_PACKAGE)] = None,
) -> None:
    """Apply final package.json specifiers and transitive overrides for manual npm install."""
    settings: Settings = ctx.obj
    overrides = parse_override_specs(override)

    uow = uow_project.build_project_uow(
        settings,
        project_path,
        production,
        allow_prerelease,
        tuple(allow_prerelease_package or []),
        "npm",
        security_only=security,
        ignore_packages=tuple(ignore or []),
        rewrite_versions=rewrite_versions,
    )

    with show_operation_progress(settings, "Resolving recommended versions...") as progress:
        with progress():
            scan_result = project.scan(uow)

    package_manager_name = uow.packages_manager.package_manager_type.name
    plan = build_update_plan(
        scan_result,
        package_manager_name,
        pin_all=pin_all,
        cooldown_period=settings.cooldown_period,
        security_only=security,
        forced_overrides=dict(overrides),
    )

    assert isinstance(uow.packages_manager, PackageManagerJsNpm)
    message = uow.packages_manager.apply_state(plan)
    typer.echo(message)
