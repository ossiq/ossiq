"""Plan and preview solver-recommended package version changes."""

from dataclasses import dataclass, field
from typing import Literal

import typer

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.messages import (
    ERROR_OVERRIDE_DUPLICATE,
    ERROR_OVERRIDE_IGNORE_CONFLICT,
    ERROR_OVERRIDE_SPEC_INVALID,
    ERROR_OVERRIDE_UNKNOWN_PACKAGES,
    ERROR_STRATEGY_OVERRIDE_IGNORE_CONFLICT,
    HELP_APPLY_RERUN_HINT,
    HELP_PLAN_HIGHER_TIER_FOOTER,
    HELP_PLAN_NO_RECOMMENDATIONS,
    HELP_PLAN_NO_RECOMMENDATIONS_FOR_TIER,
    HELP_PLAN_WIDENING_CONFIRM_HEADER,
    WARNING_OVERRIDE_VERSION_UNKNOWN,
    WARNING_STRATEGY_OVERRIDE_SHADOWED_BY_OVERRIDE,
    WARNING_STRATEGY_OVERRIDE_UNKNOWN_PACKAGE,
)
from ossiq.service.project.scan import scan
from ossiq.service.update import UpdateEntry, UpdatePlan, build_update_plan
from ossiq.settings import Settings
from ossiq.sources import project_sources
from ossiq.sources.project_sources import ProjectSources
from ossiq.strategy.overrides import StrategyPlan
from ossiq.strategy.pyramid import DEFAULT_STRATEGY, PYRAMID, UpdateStrategy, tier_index
from ossiq.ui.registry import get_renderer
from ossiq.ui.system import show_error, show_scan_progress


@dataclass(frozen=True)
class CommandPlanOptions:
    """Options for the plan/apply subcommands."""

    project_path: str
    registry_type: Literal["npm", "pypi"] | None = None
    allow_prerelease: bool = False
    allow_prerelease_packages: tuple[str, ...] = ()
    production: bool = False
    update_strategy: UpdateStrategy = DEFAULT_STRATEGY
    strategy_overrides: tuple[tuple[str, UpdateStrategy], ...] = ()
    ignore_packages: tuple[str, ...] = ()
    pin_all: bool = False
    rewrite_versions: bool = False
    overrides: tuple[tuple[str, str], ...] = field(default_factory=tuple)


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


def check_strategy_override_ignore_conflict(
    strategy_overrides: tuple[tuple[str, UpdateStrategy], ...], ignore_packages: tuple[str, ...]
) -> None:
    """Reject any package that is both given a --strategy-override and excluded via --ignore."""
    conflicted = sorted({name for name, _ in strategy_overrides} & set(ignore_packages))
    if conflicted:
        raise typer.BadParameter(ERROR_STRATEGY_OVERRIDE_IGNORE_CONFLICT.format(packages=", ".join(conflicted)))


def warn_unknown_override_versions(sources: ProjectSources, overrides: tuple[tuple[str, str], ...]) -> None:
    """Warn when a forced version is absent from the registry (cache is warm after the scan)."""
    for name, version in overrides:
        known_versions = {pv.version for pv in sources.packages_registry.package_versions(name)}
        if known_versions and version not in known_versions:
            typer.echo(WARNING_OVERRIDE_VERSION_UNKNOWN.format(package=name, version=version), err=True)


def warn_strategy_overrides(
    plan: UpdatePlan,
    strategy_overrides: tuple[tuple[str, UpdateStrategy], ...],
    forced_overrides: tuple[tuple[str, str], ...],
) -> None:
    """Warn on stderr for a --strategy-override naming an unknown package, or shadowed by --override.

    Not an error — a monorepo may share one flag set across projects (mirrors
    warn_unknown_override_versions), and --override winning over --strategy-override is documented
    policy, not a mistake worth failing the run over.
    """
    forced_names = {name for name, _ in forced_overrides}
    known_names = set(plan.installed_versions)
    for name, _tier in strategy_overrides:
        if name in forced_names:
            typer.echo(WARNING_STRATEGY_OVERRIDE_SHADOWED_BY_OVERRIDE.format(package=name), err=True)
        elif name not in known_names:
            typer.echo(WARNING_STRATEGY_OVERRIDE_UNKNOWN_PACKAGE.format(package=name), err=True)


def prepare_plan(ctx: typer.Context, options: CommandPlanOptions) -> tuple[ProjectSources, UpdatePlan] | None:
    """Scan the project and build the update plan. Returns None when nothing needs updating."""
    settings: Settings = ctx.obj

    strategy = StrategyPlan(default=options.update_strategy, overrides=dict(options.strategy_overrides))

    sources = project_sources.build_project_sources(
        settings,
        options.project_path,
        options.production,
        options.allow_prerelease,
        options.allow_prerelease_packages,
        options.registry_type,
        strategy=strategy,
        ignore_packages=options.ignore_packages,
        rewrite_versions=options.rewrite_versions,
    )

    with show_scan_progress(settings) as on_step:
        scan_result = scan(sources, on_step=on_step)

    package_manager_name = sources.packages_manager.package_manager_type.name
    plan = build_update_plan(
        scan_result,
        package_manager_name,
        pin_all=options.pin_all,
        cooldown_period=sources.settings.cooldown_period,
        strategy=strategy,
        forced_overrides=dict(options.overrides),
    )

    if plan.unknown_override_packages:
        packages = ", ".join(plan.unknown_override_packages)
        show_error(ERROR_OVERRIDE_UNKNOWN_PACKAGES.format(packages=packages))
        raise typer.Exit(2)

    if options.overrides:
        warn_unknown_override_versions(sources, options.overrides)
    if options.strategy_overrides:
        warn_strategy_overrides(plan, options.strategy_overrides, options.overrides)

    if (
        not plan.direct_entries
        and not plan.transitive_entries
        and not plan.held_for_cooldown
        and not plan.held_for_widening
    ):
        if options.update_strategy == DEFAULT_STRATEGY:
            typer.echo(HELP_PLAN_NO_RECOMMENDATIONS)
        else:
            typer.echo(HELP_PLAN_NO_RECOMMENDATIONS_FOR_TIER.format(tier=options.update_strategy.value))
        return None

    return sources, plan


def render_higher_tier_footer(plan: UpdatePlan) -> None:
    """Print "N more updates available under --update-strategy X" for each higher tier that
    would move a withheld package, lowest tier first."""
    for tier in PYRAMID:
        count = plan.available_at_higher_tier.get(tier)
        if not count or tier_index(tier) <= tier_index(plan.strategy):
            continue
        plural = "s" if count != 1 else ""
        typer.echo(HELP_PLAN_HIGHER_TIER_FOOTER.format(count=count, plural=plural, tier=tier.value))


def command_plan(ctx: typer.Context, options: CommandPlanOptions) -> None:
    """Show the plan table."""
    result = prepare_plan(ctx, options)
    if result is None:
        return

    plan = result[1]
    renderer = get_renderer(Command.PLAN, UserInterfaceType.CONSOLE, ctx.obj)
    renderer.render(data=plan, script="")
    render_higher_tier_footer(plan)


def confirm_widening(plan: UpdatePlan) -> bool:
    """Second, apt-style confirmation for entries that widen the declared constraint."""
    widening_entries: list[UpdateEntry] = [e for e in plan.all_entries if e.widens_constraint]
    if not widening_entries:
        return True

    typer.echo(HELP_PLAN_WIDENING_CONFIRM_HEADER.format(tier=plan.strategy.value))
    for entry in widening_entries:
        typer.echo(
            f"  {entry.package_name}  {entry.version_defined or '(none)'} -> {entry.recommended_version}"
            f"  [{'direct' if entry.is_direct else 'transitive'}]"
        )
    return typer.confirm("Proceed with these constraint-widening updates?", default=False)


def command_apply(ctx: typer.Context, options: CommandPlanOptions, yes: bool = False) -> None:
    """Show the plan, confirm, then run updates in-process with rollback on failure."""
    result = prepare_plan(ctx, options)
    if result is None:
        return

    sources, plan = result
    renderer = get_renderer(Command.PLAN, UserInterfaceType.CONSOLE, ctx.obj)
    renderer.render(data=plan, script="")
    render_higher_tier_footer(plan)

    if not plan.all_entries:
        return

    if not yes:
        n = len(plan.all_entries)
        confirmed = typer.confirm(f"Proceed with {n} update{'s' if n != 1 else ''}?", default=False)
        if not confirmed:
            raise typer.Exit(0)
        if not confirm_widening(plan):
            raise typer.Exit(0)

    sources.packages_manager.execute_update(plan)
    typer.echo("Update complete.")
    typer.echo(HELP_APPLY_RERUN_HINT)
