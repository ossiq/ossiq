"""Assemble an UpdatePlan from a solver-enriched scan."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping

from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.policy import Policy
from ossiq.domain.version import PeerDependency
from ossiq.service.install_passes import assign_install_passes
from ossiq.service.project.models import ScanResult
from ossiq.service.update.entries import entry_from_record, transitive_entries_for
from ossiq.service.update.holds import (
    hold_for_cooldown,
    hold_for_widening,
    peer_holds,
    policy_holds,
    split_user_override_holds,
)
from ossiq.service.update.models import UpdatePlan
from ossiq.service.update.overrides import apply_forced_overrides
from ossiq.strategy.overrides import StrategyPlan
from ossiq.strategy.pyramid import DEFAULT_STRATEGY, UpdateStrategy


def build_update_plan(
    scan_result: ScanResult,
    package_manager_name: str,
    pin_all: bool = False,
    cooldown_period: int = 0,
    strategy: StrategyPlan | None = None,
    forced_overrides: dict[str, str] | None = None,
    rewrite_versions: bool = False,
    peers_of: Callable[[str, str], Mapping[str, PeerDependency]] | None = None,
    enforces_cooldown_on_install: bool = False,
    policy: Policy | None = None,
) -> UpdatePlan:
    """Build an UpdatePlan from the scan's solver recommendations that differ from the installed versions.

    Withheld packages are listed on the plan (held_for_cooldown, held_for_widening,
    held_by_user_overrides, held_by_peers) so it can name what it skipped and why. Which packages carry a
    recommendation was decided upstream by `service.project.strategy.apply_update_strategy`; this
    function filters only by widening authorization and cooldown.

    Args:
        scan_result: The scan, already enriched with solver recommendations.
        package_manager_name: The package manager that will apply the plan.
        pin_all: Carried onto the plan unchanged.
        cooldown_period: Days a target version must age before it is applied. Younger recommendations
            go to held_for_cooldown unless they fix a CVE, and so do direct records that
            `apply_update_strategy` left blank for the same reason (rebuilt by
            cooldown_entry_from_record).
        strategy: The tier in force, plus per-package tiers. Defaults to DEFAULT_STRATEGY.
        forced_overrides: {package: version} from --override. Replaces any solver recommendation for
            that package, bypassing the strategy and the cooldown; packages absent from the dependency
            tree go to unknown_override_packages.
        rewrite_versions: --rewrite-versions; lets `==x.y.z` pins through the widening hold (see
            is_held_for_widening).
        peers_of: npm only. Looks up the peers a published release declares. With it, entries are
            spread over the install passes that keep every peer range satisfiable mid-install (see
            assign_install_passes); without it the plan is one pass.
        enforces_cooldown_on_install: The package manager's capability flag, carried onto the plan for
            the renderers.
        policy: The project's policy, with exception names in the registry's spelling. A release it
            waives the cooldown for is never held for it.
    """
    plan = strategy or StrategyPlan(default=DEFAULT_STRATEGY)
    direct_records = scan_result.production_packages + scan_result.optional_packages
    all_records = direct_records + scan_result.transitive_packages
    installed_versions = {r.package_name: r.installed_version for r in all_records}
    direct = [
        entry_from_record(r, is_direct=True)
        for r in direct_records
        if r.recommended_version and r.recommended_version != r.installed_version
    ]

    available_at_higher_tier: Counter[UpdateStrategy] = Counter(
        r.strategy_selection.available_at
        for r in direct_records
        if r.strategy_selection is not None and r.strategy_selection.available_at is not None
    )

    transitive = transitive_entries_for(scan_result, direct_records)
    forced_names = set(forced_overrides or {})
    direct, transitive, user_holds = split_user_override_holds(
        scan_result, direct_records, direct, transitive, forced_names
    )
    direct, transitive, unknown_overrides = apply_forced_overrides(
        scan_result, direct_records, direct, transitive, forced_overrides
    )
    # Widening before cooldown: widening entries never reach the writers, so one must not also be counted
    # as held for cooldown.
    direct, transitive, widening = hold_for_widening(direct, transitive, plan, rewrite_versions)
    direct, transitive, held = hold_for_cooldown(
        direct, transitive, direct_records, forced_names, cooldown_period, policy
    )

    update_plan = UpdatePlan(
        project_name=scan_result.project_name,
        project_path=scan_result.project_path,
        registry_type=scan_result.packages_registry,
        package_manager_name=package_manager_name,
        direct_entries=direct,
        transitive_entries=transitive,
        pin_all=pin_all,
        installed_versions=installed_versions,
        held_for_cooldown=held,
        cooldown_period=cooldown_period,
        enforces_cooldown_on_install=enforces_cooldown_on_install,
        unknown_override_packages=tuple(unknown_overrides),
        held_for_widening=widening,
        strategy=plan.default,
        strategy_overrides=dict(plan.overrides),
        available_at_higher_tier=dict(available_at_higher_tier),
        held_by_user_overrides=user_holds,
        held_by_peers=peer_holds(direct_records),
        held_by_policy=policy_holds(direct_records),
        peer_repairs=list(scan_result.peer_repairs),
    )
    if peers_of is None:
        return update_plan
    return assign_install_passes(update_plan, peers_of, ProjectPackagesRegistry(scan_result.packages_registry))
