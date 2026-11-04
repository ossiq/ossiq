"""Decide which entries the plan withholds and why: cooldown, widening, user overrides, peers."""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable

from ossiq.domain.common import ConstraintType, OverrideHold, PeerHold
from ossiq.domain.policy import Policy, PolicyRule
from ossiq.domain.provenance import PolicyHold
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.service.update.entries import cooldown_entry_from_record
from ossiq.service.update.models import UpdateEntry
from ossiq.strategy.overrides import StrategyPlan
from ossiq.strategy.pyramid import UpdateStrategy, tier_reaches


def is_held_for_cooldown(entry: UpdateEntry, cooldown_period: int, policy: Policy | None = None) -> bool:
    """Return whether the entry's target version is younger than the cooldown period.

    Forced, security and cooldown-bypassed entries are exempt, and so is a release the policy
    waives. This is a backstop: `select_target` already settles direct records (see
    apply_update_strategy), so it mostly catches transitive entries, whose solver picks carry only a
    soft freshness penalty.
    """
    if entry.is_forced or entry.is_security or entry.cooldown_bypassed:
        return False
    if policy is not None and policy.waives(PolicyRule.COOLDOWN, entry.package_name, entry.recommended_version):
        return False
    if entry.reason is None or entry.reason.age_days is None:
        return False
    return entry.reason.age_days < cooldown_period


def is_held_for_widening(entry: UpdateEntry, strategy: UpdateStrategy, *, rewrite_versions: bool = False) -> bool:
    """Return whether the entry must widen its declared range further than its tier reaches.

    `--override` entries (`is_forced`) and entries that a CVE or end-of-life motive escalated
    (`widening_authorized`) are never held, and neither is anything under `latest`, whose reach already
    includes widening. `rewrite_versions` also exempts `==x.y.z` pins, because widening them is the
    flag's purpose, but not npm aliases, whose inner constraint can't be rewritten (as in
    clamp_recommendations).
    """
    if entry.is_forced or entry.widening_authorized or not entry.widens_constraint or entry.from_rung is None:
        return False
    if (
        rewrite_versions
        and entry.constraint_type == ConstraintType.PINNED
        and not (entry.version_defined or "").startswith("npm:")
    ):
        return False
    return not tier_reaches(strategy, entry.from_rung)


def user_override_hold(record: ScanRecord | None, entry: UpdateEntry) -> OverrideHold | None:
    """Return the user's override that blocks an entry, or None if none does.

    Only npm and pnpm overrides count: they are the ones where the scan knows the value an override
    forces, so only there can the plan say an update is blocked.
    """
    if record is None:
        return None
    info = record.constraint_info
    if not info.is_user_override or info.override_value is None:
        return None
    return OverrideHold(
        package=entry.package_name,
        value=info.override_value,
        key=info.override_key,
        source_file=info.source_file,
        blocked=(f"{entry.package_name}@{entry.recommended_version}",),
    )


def peer_holds(records: Iterable[ScanRecord]) -> list[PeerHold]:
    """Return the newest peer-refused release of each package, sorted by package name.

    `rejected_candidates` run from the lowest rung to the highest, so the last peer hold is the
    furthest the package was kept back.
    """
    holds = [
        hold
        for record in records
        for hold in [next((rc.held_by_peer for rc in reversed(record.rejected_candidates) if rc.held_by_peer), None)]
        if hold is not None
    ]
    return sorted(holds, key=lambda hold: hold.package)


def policy_holds(records: Iterable[ScanRecord]) -> list[PolicyHold]:
    """Return the newest policy-refused release of each package, sorted by package name.

    `rejected_candidates` run from the lowest rung to the highest, so the last policy hold is the
    furthest the package was kept back.
    """
    holds = [
        PolicyHold(package=record.package_name, blocked_version=rc.version, reason=rc.reason)
        for record in records
        for rc in [next((rc for rc in reversed(record.rejected_candidates) if rc.held_by_policy), None)]
        if rc is not None
    ]
    return sorted(holds, key=lambda hold: hold.package)


def merge_override_holds(holds: Iterable[OverrideHold]) -> list[OverrideHold]:
    """One hold per override, however many updates it kept back, in a stable order."""
    merged: dict[tuple[str, str | None, str], OverrideHold] = {}
    for hold in holds:
        key = (hold.package, hold.key, hold.value)
        known = merged.get(key)
        merged[key] = (
            hold
            if known is None
            else dataclasses.replace(known, blocked=tuple(dict.fromkeys((*known.blocked, *hold.blocked))))
        )
    return sorted(merged.values(), key=lambda h: (h.package, h.key or "", h.value))


def split_user_override_holds(
    scan_result: ScanResult,
    direct_records: list[ScanRecord],
    direct: list[UpdateEntry],
    transitive: list[UpdateEntry],
    forced_names: set[str],
) -> tuple[list[UpdateEntry], list[UpdateEntry], list[OverrideHold]]:
    """Drop the entries a user-written override blocks, and return the holds that name them.

    A user-written override is theirs to release, so the update is held instead of promising a bump that
    never lands. Writers skip a transitive package an override governs. On a direct package the override
    beats the spec they write: pnpm resolves against it, npm refuses a differing spec.

    Args:
        scan_result: Supplies the transitive records the holds are looked up in.
        direct_records: The scan's direct records, which carry the rejected candidates.
        direct: Direct entries to filter.
        transitive: Transitive entries to filter.
        forced_names: `--override` names in either spelling; a forced version replaces its entry later.

    Returns:
        The unheld direct entries, the unheld transitive entries, and the merged holds.
    """
    user_holds = [rc.held_by_override for r in direct_records for rc in r.rejected_candidates if rc.held_by_override]
    direct_by_identity = {r.identity_name: r for r in direct_records}
    unheld_direct: list[UpdateEntry] = []
    for entry in direct:
        hold = user_override_hold(direct_by_identity.get(entry.identity), entry)
        # A `$name` value follows the manifest's own spec, so the bump carries it along; a forced
        # version replaces this entry below, so it is not held either.
        if hold is None or hold.value.startswith("$") or {entry.identity, entry.package_name} & forced_names:
            unheld_direct.append(entry)
        else:
            user_holds.append(hold)
    records_by_name = {r.package_name: r for r in scan_result.transitive_packages}
    unheld_transitive: list[UpdateEntry] = []
    for entry in transitive:
        hold = user_override_hold(records_by_name.get(entry.package_name), entry)
        if hold is None:
            unheld_transitive.append(entry)
        else:
            user_holds.append(hold)
    return unheld_direct, unheld_transitive, merge_override_holds(user_holds)


def hold_for_widening(
    direct: list[UpdateEntry],
    transitive: list[UpdateEntry],
    strategy_plan: StrategyPlan,
    rewrite_versions: bool,
) -> tuple[list[UpdateEntry], list[UpdateEntry], list[UpdateEntry]]:
    """Take out the entries that need a wider declared range than their tier reaches.

    Returns:
        The direct entries and transitive entries that remain, and the held entries sorted by package name.
    """
    widening = sorted(
        [
            e
            for e in direct + transitive
            if is_held_for_widening(e, strategy_plan.for_package(e.package_name), rewrite_versions=rewrite_versions)
        ],
        key=lambda e: e.package_name,
    )
    # Subtract by identity, not registry name: npm aliases of one package share a `package_name`, and
    # subtracting by it would drop a sibling alias from the plan along with its acknowledgement prompt.
    widening_ids = {e.identity for e in widening}
    return (
        [e for e in direct if e.identity not in widening_ids],
        [e for e in transitive if e.identity not in widening_ids],
        widening,
    )


def hold_for_cooldown(
    direct: list[UpdateEntry],
    transitive: list[UpdateEntry],
    direct_records: list[ScanRecord],
    forced_names: set[str],
    cooldown_period: int,
    policy: Policy | None = None,
) -> tuple[list[UpdateEntry], list[UpdateEntry], list[UpdateEntry]]:
    """Take out the entries younger than the cooldown, and add the direct records it left without one.

    Args:
        direct: Direct entries to filter.
        transitive: Transitive entries to filter.
        direct_records: The scan's direct records, searched for those with no recommendation left.
        forced_names: `--override` names in either spelling; a forced version is never held.
        cooldown_period: The cooldown in days.
        policy: The project's policy; a release it waives the cooldown for is never held.

    Returns:
        The direct entries and transitive entries that remain, and the held entries sorted by package name.
    """
    # Two sources, one list: entries with a fresh recommendation (transitive picks from the solver's soft
    # penalty), and direct records `select_target` left blank because everything reachable was fresh.
    # The latter never became entries and would otherwise vanish from the plan.
    cooldown_blanked = [
        cooldown_entry_from_record(r, r.strategy_selection.cooldown_hold)
        for r in direct_records
        if r.strategy_selection is not None
        and r.strategy_selection.cooldown_hold is not None
        and r.package_name not in forced_names
        and r.identity_name not in forced_names
    ]
    held = sorted(
        [e for e in direct + transitive if is_held_for_cooldown(e, cooldown_period, policy)] + cooldown_blanked,
        key=lambda e: e.package_name,
    )
    # By identity for the same reason as in hold_for_widening.
    held_ids = {e.identity for e in held}
    return (
        [e for e in direct if e.identity not in held_ids],
        [e for e in transitive if e.identity not in held_ids],
        held,
    )
