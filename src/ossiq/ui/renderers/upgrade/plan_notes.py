"""What an update plan says besides its steps: what it holds back, what it forces and what it adds.

Shared by the upgrade console renderer and, until it goes, the plan renderer. Each function prints to
the console it is given, so a caller keeps control of where the output lands.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from ossiq.domain.common import rung_scope_label
from ossiq.domain.update_plan import TransitiveImpact, UpdateEntry, UpdatePlan
from ossiq.messages import (
    HELP_PLAN_FORCED_WARNING,
    HELP_PLAN_HELD_BY_PACKAGE_MANAGER_HEADER,
    HELP_PLAN_HELD_BY_PEERS_HEADER,
    HELP_PLAN_HELD_BY_POLICY_HEADER,
    HELP_PLAN_HELD_BY_USER_OVERRIDES_HEADER,
    HELP_PLAN_HELD_FOR_COOLDOWN_HEADER,
    HELP_PLAN_HELD_FOR_WIDENING_HEADER,
    HELP_PLAN_HIGHER_TIER_FOOTER,
    HELP_PLAN_NEW_DEP_FRESH_WARNING,
    HELP_PLAN_NEW_DEP_HELD_BY_MANAGER,
)
from ossiq.ui.renderers.impact_utils import format_cutoff, is_fresh_new_dep, new_transitive_deps_table


def age_cell(entry: UpdateEntry) -> str:
    """Age of the entry's target in days, or a dash when the registry gave no publish date."""
    return f"{entry.reason.age_days}d" if entry.reason and entry.reason.age_days is not None else "—"


def new_dependency_impacts(plan: UpdatePlan) -> list[TransitiveImpact]:
    """The packages a direct update would bring into the tree that are not installed yet."""
    return [i for entry in plan.direct_entries for i in entry.transitive_impacts if i.current_version is None]


def render_plan_notes(console: Console, plan: UpdatePlan) -> None:
    """Print the forced-version warning, the new dependencies, every hold and the higher-tier footer."""
    render_forced_warning(console, plan)
    render_new_dependencies(console, plan)
    render_holds(console, plan)
    render_higher_tier_footer(console, plan)


def render_holds(console: Console, plan: UpdatePlan) -> None:
    render_held_for_cooldown(console, plan)
    render_held_for_widening(console, plan)
    render_held_by_user_overrides(console, plan)
    render_held_by_peers(console, plan)
    render_held_by_policy(console, plan)


def render_forced_warning(console: Console, plan: UpdatePlan) -> None:
    """Warn that a forced version skips the solver's compatibility checks and the cooldown."""
    if any(entry.is_forced for entry in plan.all_entries):
        console.print(f"[yellow]{HELP_PLAN_FORCED_WARNING}[/yellow]")
        console.print()


def render_new_dependencies(console: Console, plan: UpdatePlan) -> None:
    """List the packages the plan adds to the tree, and say when one is younger than the cooldown."""
    impacts = new_dependency_impacts(plan)
    table = new_transitive_deps_table(impacts, cooldown_period=plan.cooldown_period)
    if not table:
        return
    console.print(table)
    console.print()
    if any(is_fresh_new_dep(i, plan.cooldown_period) for i in impacts):
        if plan.enforces_cooldown_on_install:
            notice = HELP_PLAN_NEW_DEP_HELD_BY_MANAGER.format(
                manager=plan.package_manager_name.lower(), days=plan.cooldown_period
            )
            console.print(f"[dim]{notice}[/dim]")
        else:
            warning = HELP_PLAN_NEW_DEP_FRESH_WARNING.format(days=plan.cooldown_period)
            console.print(f"[yellow]{warning}[/yellow]")
        console.print()


def render_higher_tier_footer(console: Console, plan: UpdatePlan) -> None:
    """Print "N more updates available under --update-strategy X" for each higher tier that
    would move a withheld package, lowest tier first."""
    for tier, count in plan.higher_tier_counts:
        plural = "s" if count != 1 else ""
        console.print(HELP_PLAN_HIGHER_TIER_FOOTER.format(count=count, plural=plural, tier=tier.value))


def render_held_for_cooldown(console: Console, plan: UpdatePlan) -> None:
    """List recommendations withheld because their target version is too young to move to.

    OSS IQ's cooldown and the package manager's release cutoff get separate tables: only the
    first is OSS IQ's call, and naming the wrong one sends the user to the wrong setting.
    """
    by_cooldown = [e for e in plan.held_for_cooldown if e.held_by is None]
    by_package_manager = [e for e in plan.held_for_cooldown if e.held_by is not None]

    if by_cooldown:
        console.print(f"[yellow]{HELP_PLAN_HELD_FOR_COOLDOWN_HEADER.format(days=plan.cooldown_period)}[/yellow]")
        table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
        table.add_column("Package", style="bold")
        table.add_column("Current", style="red")
        table.add_column("Recommended", style="green")
        table.add_column("Age", style="dim")
        table.add_column("Type", style="dim")
        for entry in by_cooldown:
            dep_type = "direct" if entry.is_direct else "transitive"
            versions = (entry.current_version, entry.recommended_version)
            table.add_row(entry.display_name, *versions, age_cell(entry), dep_type)
        console.print(table)
        console.print()

    if by_package_manager:
        header = HELP_PLAN_HELD_BY_PACKAGE_MANAGER_HEADER.format(setting=by_package_manager[0].held_by)
        console.print(f"[yellow]{header}[/yellow]")
        table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
        table.add_column("Package", style="bold")
        table.add_column("Current", style="red")
        table.add_column("Waiting on", style="green")
        table.add_column("Age", style="dim")
        table.add_column("Cutoff", style="dim")
        for entry in by_package_manager:
            cutoff = format_cutoff(entry.held_cutoff) if entry.held_cutoff is not None else "—"
            versions = (entry.current_version, entry.recommended_version)
            table.add_row(entry.display_name, *versions, age_cell(entry), cutoff)
        console.print(table)
        console.print()


def render_held_for_widening(console: Console, plan: UpdatePlan) -> None:
    """List recommendations withheld because reaching them requires widening the declared range."""
    if not plan.held_for_widening:
        return

    console.print(f"[yellow]{HELP_PLAN_HELD_FOR_WIDENING_HEADER}[/yellow]")
    table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
    table.add_column("Package", style="bold")
    table.add_column("Current", style="red")
    table.add_column("Declared", style="dim")
    table.add_column("Reachable", style="green")
    table.add_column("Scope", style="dim")
    table.add_column("Type", style="dim")
    for entry in plan.held_for_widening:
        dep_type = "direct" if entry.is_direct else "transitive"
        scope = rung_scope_label(entry.from_rung)
        table.add_row(
            entry.display_name,
            entry.current_version,
            entry.version_defined or "—",
            entry.recommended_version,
            scope,
            dep_type,
        )
    console.print(table)
    console.print()


def render_held_by_user_overrides(console: Console, plan: UpdatePlan) -> None:
    """List the overrides the user wrote that kept an update out of the plan."""
    if not plan.held_by_user_overrides:
        return

    console.print(f"[yellow]{HELP_PLAN_HELD_BY_USER_OVERRIDES_HEADER}[/yellow]")
    table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
    table.add_column("Override", style="bold")
    table.add_column("Forces", style="green")
    table.add_column("Declared in", style="dim")
    table.add_column("Keeps back", style="dim")
    for hold in plan.held_by_user_overrides:
        name = f"{hold.package}@{hold.key}" if hold.key else hold.package
        table.add_row(name, hold.value, hold.source_file or "—", ", ".join(hold.blocked))
    console.print(table)
    console.print()


def render_held_by_peers(console: Console, plan: UpdatePlan) -> None:
    """List the packages whose newer release an installed package's peer range rules out."""
    if not plan.held_by_peers:
        return

    console.print(f"[yellow]{HELP_PLAN_HELD_BY_PEERS_HEADER}[/yellow]")
    table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
    table.add_column("Package", style="bold")
    table.add_column("Refused", style="green")
    table.add_column("Peer-required by", style="dim")
    table.add_column("Range", style="dim")
    for hold in plan.held_by_peers:
        requirer = f"{hold.requirer} (+{hold.others} more)" if hold.others else hold.requirer
        table.add_row(hold.package, hold.blocked_version, requirer, hold.spec)
    console.print(table)
    console.print()


def render_held_by_policy(console: Console, plan: UpdatePlan) -> None:
    """List the packages whose newer release the user's supply-chain policy rules out."""
    if not plan.held_by_policy:
        return

    console.print(f"[yellow]{HELP_PLAN_HELD_BY_POLICY_HEADER}[/yellow]")
    table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
    table.add_column("Package", style="bold")
    table.add_column("Refused", style="green")
    table.add_column("Why", style="dim")
    for hold in plan.held_by_policy:
        table.add_row(hold.package, hold.blocked_version, hold.reason)
    console.print(table)
    console.print()
