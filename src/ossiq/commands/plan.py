"""Plan and preview solver-recommended package version changes."""

from dataclasses import dataclass, field
from typing import Literal

import typer

from ossiq.domain.common import (
    Command,
    NameValueSpecError,
    UserInterfaceType,
    normalize_dist_name,
    parse_name_value_specs,
)
from ossiq.messages import (
    ERROR_OVERRIDE_DUPLICATE,
    ERROR_OVERRIDE_IGNORE_CONFLICT,
    ERROR_OVERRIDE_SPEC_INVALID,
    ERROR_OVERRIDE_UNKNOWN_PACKAGES,
    ERROR_STRATEGY_OVERRIDE_IGNORE_CONFLICT,
    HELP_APPLY_RERUN_HINT,
    HELP_PLAN_ACKNOWLEDGE_CONFIRM_HEADER,
    HELP_PLAN_HIGHER_TIER_FOOTER,
    HELP_PLAN_NO_RECOMMENDATIONS,
    HELP_PLAN_NO_RECOMMENDATIONS_FOR_TIER,
    WARNING_OVERRIDE_VERSION_UNKNOWN,
    WARNING_STRATEGY_OVERRIDE_SHADOWED_BY_OVERRIDE,
    WARNING_STRATEGY_OVERRIDE_UNKNOWN_PACKAGE,
)
from ossiq.service.project.scan import scan
from ossiq.service.update import UpdatePlan, build_update_plan
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

    CLI-boundary wrapper over the shared parser: names are normalised the same way
    `--strategy-override` and `--ignore` normalise them, so one spelling can't resolve to two
    different packages depending on which flag introduced it. Scoped npm names
    (@scope/pkg==1.2.3) survive intact.

    Args:
        raw: The raw --override values, or None when the option was never given.

    Returns:
        (canonical_name, version) pairs.

    Raises:
        typer.BadParameter: On a malformed spec, or a package given two conflicting versions.
    """
    try:
        return parse_name_value_specs(raw, separator="==", flag="--override", value_parser=str)
    except NameValueSpecError as exc:
        if exc.package is not None:
            raise typer.BadParameter(ERROR_OVERRIDE_DUPLICATE.format(package=exc.package)) from exc
        raise typer.BadParameter(ERROR_OVERRIDE_SPEC_INVALID.format(value=exc.value)) from exc


def check_override_ignore_conflict(overrides: tuple[tuple[str, str], ...], ignore_packages: tuple[str, ...]) -> None:
    """Reject any package that is both forced via --override and excluded via --ignore.

    Both sides are compared canonically — the override names already are, and ProjectSources
    normalizes --ignore the same way, so `--override Foo==1.0 --ignore foo` is the conflict it
    looks like.
    """
    ignored = {normalize_dist_name(p) for p in ignore_packages}
    conflicted = sorted({name for name, _ in overrides} & ignored)
    if conflicted:
        raise typer.BadParameter(ERROR_OVERRIDE_IGNORE_CONFLICT.format(packages=", ".join(conflicted)))


def check_strategy_override_ignore_conflict(
    strategy_overrides: tuple[tuple[str, UpdateStrategy], ...], ignore_packages: tuple[str, ...]
) -> None:
    """Reject any package that is both given a --strategy-override and excluded via --ignore.

    Canonical on both sides, for the same reason as check_override_ignore_conflict.
    """
    ignored = {normalize_dist_name(p) for p in ignore_packages}
    conflicted = sorted({name for name, _ in strategy_overrides} & ignored)
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

    with show_scan_progress(settings) as progress:
        scan_result = scan(sources, progress=progress)

    package_manager_name = sources.packages_manager.package_manager_type.name
    plan = build_update_plan(
        scan_result,
        package_manager_name,
        pin_all=options.pin_all,
        cooldown_period=sources.settings.cooldown_period,
        strategy=strategy,
        forced_overrides=dict(options.overrides),
        rewrite_versions=options.rewrite_versions,
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


def confirm_acknowledged(plan: UpdatePlan) -> bool:
    """Second, apt-style confirmation for entries that need explicit acknowledgement.

    Two distinct reasons land here:

    - the pick sits outside the declared constraint, so applying it rewrites the manifest's range;
    - the pick's major line is a known API/module-system break, which means every installable
      release was gated and `build_candidates`' escape hatch admitted the newest anyway rather
      than blanking the recommendation.

    The second case used to pass through silently whenever the pick happened to sit inside the
    declared range: `uuid@>11.0.0` admits ESM-only 14.0.2, so `widens_constraint` was False and
    nothing asked. Both reasons are now named per entry.

    Args:
        plan: The plan about to be applied.

    Returns:
        True when there is nothing to acknowledge, or the user confirmed.
    """
    flagged = [e for e in plan.all_entries if e.widens_constraint or e.carries_known_break]
    if not flagged:
        return True

    typer.echo(HELP_PLAN_ACKNOWLEDGE_CONFIRM_HEADER.format(tier=plan.strategy.value))
    for entry in flagged:
        reasons = []
        if entry.widens_constraint:
            reasons.append(f"widens {entry.version_defined or '(none)'}")
        if entry.carries_known_break:
            reasons.append("known break")
        typer.echo(
            f"  {entry.display_name}  {entry.version_defined or '(none)'} -> {entry.recommended_version}"
            f"  [{'direct' if entry.is_direct else 'transitive'}]  ({', '.join(reasons)})"
        )
    return typer.confirm("Proceed with these updates?", default=False)


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
        if not confirm_acknowledged(plan):
            raise typer.Exit(0)

    sources.packages_manager.execute_update(plan)
    typer.echo("Update complete.")
    typer.echo(HELP_APPLY_RERUN_HINT)
