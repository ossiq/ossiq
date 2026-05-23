"""CLI handlers for NPM helper sub-commands (freeze-state, restore-state, overrides-diff)."""

from typing import Annotated

import typer

from ossiq.adapters.package_managers.api_npm import PackageManagerJsNpm
from ossiq.service import project
from ossiq.service.update import build_update_plan
from ossiq.settings import Settings
from ossiq.ui.system import show_operation_progress
from ossiq.unit_of_work import uow_project

npm_helpers_app = typer.Typer(name="npm", help="NPM helper utilities")


@npm_helpers_app.command("freeze-state")
def npm_freeze_state(
    ctx: typer.Context,
    project_path: str,
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
        typer.Option(
            "--security", is_flag=True, help="Narrow transitive recommendations to CVE-carrying packages only"
        ),
    ] = False,
    ignore: Annotated[
        list[str] | None,
        typer.Option("--ignore", "-i", help="Exclude package from solver recommendations (repeatable)"),
    ] = None,
    pin_all: Annotated[
        bool, typer.Option("--pin-all", is_flag=True, help="Write ==new_version for all updated direct deps")
    ] = False,
    rewrite_versions: Annotated[
        bool,
        typer.Option(
            "--rewrite-versions",
            is_flag=True,
            help="Include PINNED (==x.y.z) deps in the update and rewrite their specifiers",
        ),
    ] = False,
) -> None:
    """Lock full dependency tree in package.json overrides and save state for safe update."""
    settings: Settings = ctx.obj

    uow = uow_project.build_project_uow(
        settings,
        project_path,
        production,
        allow_prerelease,
        tuple(allow_prerelease_package or []),
        "npm",
        security_only=security,
        ignore_packages=tuple(ignore or []),
    )

    with show_operation_progress(settings, "Resolving recommended versions...") as progress:
        with progress():
            scan_result = project.scan(uow)

    package_manager_name = uow.packages_manager.package_manager_type.name
    plan = build_update_plan(scan_result, package_manager_name, pin_all=pin_all, rewrite_versions=rewrite_versions)

    assert isinstance(uow.packages_manager, PackageManagerJsNpm)
    uow.packages_manager.freeze_state(plan)
    typer.echo(f"State saved. Overrides written: {len(plan.installed_versions)} packages locked.")


@npm_helpers_app.command("restore-state")
def npm_restore_state(
    ctx: typer.Context,
    project_path: str,
) -> None:
    """Restore original package.json overrides after npm install and delete state file."""
    settings: Settings = ctx.obj
    npm_pm = PackageManagerJsNpm(project_path, settings)
    try:
        message = npm_pm.restore_state(project_path)
        typer.echo(message)
    except FileNotFoundError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1) from None


@npm_helpers_app.command("overrides-diff")
def npm_overrides_diff(
    ctx: typer.Context,
    project_path: str,
) -> None:
    """Show diff between current package.json overrides and original (read-only)."""
    settings: Settings = ctx.obj
    npm_pm = PackageManagerJsNpm(project_path, settings)
    try:
        diff = npm_pm.overrides_diff(project_path)
        typer.echo(diff)
    except FileNotFoundError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1) from None
