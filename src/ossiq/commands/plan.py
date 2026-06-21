"""Plan and preview solver-recommended package version changes."""

import shlex
import subprocess
from dataclasses import dataclass
from typing import Literal

import typer

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.messages import (
    ERROR_OVERRIDE_DUPLICATE,
    ERROR_OVERRIDE_IGNORE_CONFLICT,
    ERROR_OVERRIDE_SPEC_INVALID,
    ERROR_OVERRIDE_UNKNOWN_PACKAGES,
    HELP_APPLY_RERUN_HINT,
    HELP_PLAN_NO_RECOMMENDATIONS,
    HELP_PLAN_NO_SECURITY_RECOMMENDATIONS,
    WARNING_OVERRIDE_VERSION_UNKNOWN,
)
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
    overrides: tuple[tuple[str, str], ...] = ()


def parse_override_specs(raw: list[str] | tuple[str, ...] | None) -> tuple[tuple[str, str], ...]:
    """Parse --override values of the form `package==version` into (name, version) pairs.

    Supports scoped npm names (@scope/pkg==1.2.3). Raises typer.BadParameter on a malformed
    spec or when the same package is given two conflicting versions.
    """
    parsed: dict[str, str] = {}
    for value in raw or []:
        name, separator, version = value.partition("==")
        name = name.strip()
        version = version.strip()
        if not separator or not name or not version:
            raise typer.BadParameter(ERROR_OVERRIDE_SPEC_INVALID.format(value=value))
        if name in parsed and parsed[name] != version:
            raise typer.BadParameter(ERROR_OVERRIDE_DUPLICATE.format(package=name))
        parsed[name] = version
    return tuple(parsed.items())


def check_override_ignore_conflict(overrides: tuple[tuple[str, str], ...], ignore_packages: tuple[str, ...]) -> None:
    """Reject any package that is both forced via --override and excluded via --ignore."""
    conflicted = sorted({name for name, _ in overrides} & set(ignore_packages))
    if conflicted:
        raise typer.BadParameter(ERROR_OVERRIDE_IGNORE_CONFLICT.format(packages=", ".join(conflicted)))


def build_npm_apply_args(options: CommandPlanOptions) -> str:
    """Build CLI flags for embedding in the generated script's apply-state invocation."""
    args = ["--registry-type npm"]
    for pkg in options.ignore_packages:
        args.append(f"--ignore {shlex.quote(pkg)}")
    if options.pin_all:
        args.append("--pin-all")
    if options.rewrite_versions:
        args.append("--rewrite-versions")
    for name, version in options.overrides:
        args.append(f"--override {shlex.quote(f'{name}=={version}')}")
    if options.allow_prerelease:
        args.append("--allow-prerelease")
    for pkg in options.allow_prerelease_packages:
        args.append(f"--allow-prerelease-package {shlex.quote(pkg)}")
    if options.production:
        args.append("--production")
    if options.security_only:
        args.append("--security")
    return " ".join(args)


def npm_cli_extra_args(plan: UpdatePlan, options: CommandPlanOptions) -> str:
    """Apply-state CLI flags for npm plans; empty for other ecosystems.

    registry_type comes from ProjectPackagesRegistry ("NPM"/"PYPI"), so compare case-insensitively.
    """
    if plan.registry_type.lower() != "npm":
        return ""
    return build_npm_apply_args(options)


def warn_unknown_override_versions(uow: ProjectUnitOfWork, overrides: tuple[tuple[str, str], ...]) -> None:
    """Warn when a forced version is absent from the registry (cache is warm after the scan)."""
    for name, version in overrides:
        known_versions = {pv.version for pv in uow.packages_registry.package_versions(name)}
        if known_versions and version not in known_versions:
            typer.echo(WARNING_OVERRIDE_VERSION_UNKNOWN.format(package=name, version=version), err=True)


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
        rewrite_versions=options.rewrite_versions,
    )

    with show_operation_progress(settings, "Resolving recommended versions...") as progress:
        with progress():
            scan_result = project.scan(uow)

    package_manager_name = uow.packages_manager.package_manager_type.name
    plan = build_update_plan(
        scan_result,
        package_manager_name,
        pin_all=options.pin_all,
        cooldown_period=uow.settings.cooldown_period,
        security_only=options.security_only,
        forced_overrides=dict(options.overrides),
    )

    if plan.unknown_override_packages:
        packages = ", ".join(plan.unknown_override_packages)
        typer.echo(ERROR_OVERRIDE_UNKNOWN_PACKAGES.format(packages=packages), err=True)
        raise typer.Exit(2)

    if options.overrides:
        warn_unknown_override_versions(uow, options.overrides)

    if not plan.direct_entries and not plan.transitive_entries and not plan.held_for_cooldown:
        if options.security_only:
            typer.echo(HELP_PLAN_NO_SECURITY_RECOMMENDATIONS)
        else:
            typer.echo(HELP_PLAN_NO_RECOMMENDATIONS)
        return None

    return uow, plan


def command_plan(ctx: typer.Context, options: CommandPlanOptions, script: bool = False) -> None:
    """Show the plan table, or emit the bash script when --script is set."""
    result = prepare_plan(ctx, options)
    if result is None:
        return

    uow, plan = result
    bash_script = uow.packages_manager.generate_update_script(plan, cli_extra_args=npm_cli_extra_args(plan, options))

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

    if not plan.all_entries:
        return

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
    typer.echo(HELP_APPLY_RERUN_HINT)
