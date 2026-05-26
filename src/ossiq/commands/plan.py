"""Plan and preview solver-recommended package version changes."""

import shlex
import subprocess
from dataclasses import dataclass
from typing import Literal

import typer

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.messages import HELP_PLAN_NO_RECOMMENDATIONS
from ossiq.service import project
from ossiq.service.update import UpdatePlan, build_update_plan
from ossiq.settings import Settings
from ossiq.ui.registry import get_renderer
from ossiq.ui.system import show_operation_progress
from ossiq.unit_of_work import uow_project
from ossiq.unit_of_work.uow_project import ProjectUnitOfWork


@dataclass(frozen=True)
class CommandPlanOptions:
    """Options for the plan/apply subcommands."""

    project_path: str
    registry_type: Literal["npm", "pypi"] | None = None
    allow_prerelease: bool = False
    allow_prerelease_packages: tuple[str, ...] = ()
    production: bool = False
    security_only: bool = False
    ignore_packages: tuple[str, ...] = ()
    pin_all: bool = False
    rewrite_versions: bool = False


def build_npm_freeze_args(options: CommandPlanOptions) -> str:
    """Build CLI flags for embedding in the generated script's freeze-state invocation."""
    args = ["--registry-type npm"]
    for pkg in options.ignore_packages:
        args.append(f"--ignore {shlex.quote(pkg)}")
    if options.pin_all:
        args.append("--pin-all")
    if options.rewrite_versions:
        args.append("--rewrite-versions")
    if options.allow_prerelease:
        args.append("--allow-prerelease")
    for pkg in options.allow_prerelease_packages:
        args.append(f"--allow-prerelease-package {shlex.quote(pkg)}")
    if options.production:
        args.append("--production")
    if options.security_only:
        args.append("--security")
    return " ".join(args)


def prepare_plan(ctx: typer.Context, options: CommandPlanOptions) -> tuple[ProjectUnitOfWork, UpdatePlan] | None:
    """Scan the project and build the update plan. Returns None when nothing needs updating."""
    settings: Settings = ctx.obj

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

    with show_operation_progress(settings, "Resolving recommended versions...") as progress:
        with progress():
            scan_result = project.scan(uow)

    package_manager_name = uow.packages_manager.package_manager_type.name
    plan = build_update_plan(
        scan_result,
        package_manager_name,
        pin_all=options.pin_all,
        rewrite_versions=options.rewrite_versions,
    )

    if not plan.direct_entries and not plan.transitive_entries:
        typer.echo(HELP_PLAN_NO_RECOMMENDATIONS)
        return None

    return uow, plan


def command_plan(ctx: typer.Context, options: CommandPlanOptions, script: bool = False) -> None:
    """Show the plan table, or emit the bash script when --script is set."""
    result = prepare_plan(ctx, options)
    if result is None:
        return

    uow, plan = result
    cli_extra_args = build_npm_freeze_args(options) if plan.registry_type == "npm" else ""
    bash_script = uow.packages_manager.generate_update_script(plan, cli_extra_args=cli_extra_args)

    if script:
        typer.echo(bash_script)
        return

    renderer = get_renderer(Command.PLAN, UserInterfaceType.CONSOLE, ctx.obj)
    renderer.render(data=plan, script="")


def command_apply(ctx: typer.Context, options: CommandPlanOptions, yes: bool = False) -> None:
    """Show the plan, confirm, then run updates in-process with rollback on failure."""
    result = prepare_plan(ctx, options)
    if result is None:
        return

    uow, plan = result
    renderer = get_renderer(Command.PLAN, UserInterfaceType.CONSOLE, ctx.obj)
    renderer.render(data=plan, script="")

    if not yes:
        n = len(plan.all_entries)
        confirmed = typer.confirm(f"Proceed with {n} update{'s' if n != 1 else ''}?", default=False)
        if not confirmed:
            raise typer.Exit(0)

    try:
        uow.packages_manager.execute_update(plan)
    except subprocess.CalledProcessError as e:
        typer.echo(f"Update failed: {e}", err=True)
        raise typer.Exit(1) from None

    typer.echo("Update complete.")
