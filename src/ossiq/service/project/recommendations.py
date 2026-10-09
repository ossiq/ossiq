"""
Applying solver output (recommendations and conflicts) onto ScanRecord instances.
"""

from collections.abc import Callable, Mapping
from datetime import datetime

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import ConstraintType, EngineContext, RecommendationRung, RejectedCandidate
from ossiq.domain.release_cutoff import ReleaseCutoff
from ossiq.service.project.models import ScanRecord
from ossiq.service.project.strategy import describe_rejection, peer_hold
from ossiq.service.project.target_facts import annotate_target_facts, clear_target_facts
from ossiq.service.update_impact import ImpactKind, incoming_peer_edges, simulate_single
from ossiq.solver import dependencies_solver
from ossiq.solver.universe import filter_eligible_versions
from ossiq.solver.version_matchers import satisfies_all_constraints, version_satisfies_constraint
from ossiq.timeutil import age_days_from_iso


def apply_conflicts(
    output: dependencies_solver.SolverOutput,
    records: list[ScanRecord],
) -> None:
    """Write solver conflict info onto ScanRecord instances in-place."""
    if not output.conflicts:
        return
    by_name = {c.package_name: c for c in output.conflicts}
    for record in records:
        conflict = by_name.get(record.package_name)
        if conflict is not None:
            record.constraint_conflict = conflict.conflicting_constraints


def apply_solver_rejections(
    output: dependencies_solver.SolverOutput,
    records: list[ScanRecord],
) -> None:
    """Write solver rejection info onto ScanRecord instances in-place.

    Populates rejected_candidates for transitive records whose recommendation was dropped by
    apply_requires_consistency's final sweep, so the console/export layers can explain a blank
    recommendation instead of staying silent about it (see ScanRecord.rejected_candidates).
    """
    if not output.rejected:
        return
    by_name = {r.package_name: r for r in records}
    for pkg, rejected in output.rejected.items():
        record = by_name.get(pkg)
        if record is not None:
            record.rejected_candidates = [rejected]


def apply_recommendations(
    records: list[ScanRecord],
    output: dependencies_solver.SolverOutput,
    *,
    skip_current: bool = False,
    registry: AbstractPackageRegistryApi | None = None,
    project_declares_esm: bool = False,
    engine_context: EngineContext | None = None,
) -> None:
    """Write solver recommendations back onto ScanRecord instances in-place.

    When `registry` is given, also annotates the target-compatibility cluster via
    `target_facts.annotate_target_facts` — the shared writer. This is the only place a transitive
    record's recommendation is finalized in the main scan pipeline; direct records go through
    `service.project.strategy.apply_update_strategy` afterward, so passing `registry` here for
    them would just be redone work.
    """
    engine_context = engine_context or EngineContext()
    for record in records:
        rec = output.recommendations.get(record.package_name)
        if rec is not None and (not skip_current or rec != record.installed_version):
            record.recommended_version = rec
            record.recommended_version_reason = output.reasons.get(record.package_name)
            record.recommended_from_rung = RecommendationRung.SOLVER
            if registry is not None:
                annotate_target_facts(
                    record,
                    rec,
                    list(registry.package_versions(record.package_name)),
                    registry.package_registry,
                    engine_context=engine_context,
                    project_declares_esm=project_declares_esm,
                )


def clamp_recommendations(
    records: list[ScanRecord],
    registry: AbstractPackageRegistryApi,
    *,
    allow_prerelease: bool,
    now: datetime | None = None,
    rewrite_pinned: bool = False,
    cooldown_period: int = 0,
    release_cutoff: ReleaseCutoff | None = None,
    validator: Callable[[str, str], bool] | None = None,
) -> None:
    """Re-fit recommendations that violate a record's own version constraint.

    The solver keys by canonical name, so npm aliases of one package share a single
    recommendation; clamp each record to the newest eligible version inside its own range,
    and never below the record's own installed version (a wide alias like ``npm:ms@*`` can
    inherit a sibling's downgrade that still satisfies its range).
    Mirrors the solver's soft cooldown: prefer versions older than cooldown_period,
    fall back to a fresher one only when nothing aged satisfies the range. Never re-fits past the
    package manager's `release_cutoff`, which the installer enforces rather than prefers.

    A re-fit holds to everything the original pick had to: the record's other hard constraints
    (`all_constraints`), and `validator` (the impact check the solver's picks pass), so a pick moved
    back into its range cannot land on a release that breaks a peer.
    """
    for record in records:
        rec = record.recommended_version
        if rec is None or not record.version_constraint:
            continue
        is_alias = record.version_constraint.startswith("npm:")
        if rewrite_pinned and record.constraint_info.type == ConstraintType.PINNED and not is_alias:
            continue  # rewrite mode deliberately recommends beyond == pins; alias pins can't be rewritten
        in_constraint = version_satisfies_constraint(rec, record.version_constraint, registry.package_registry)
        is_downgrade = registry.compare_versions(rec, record.installed_version) < 0
        if in_constraint and not is_downgrade:
            continue
        eligible = filter_eligible_versions(
            list(registry.package_versions(record.package_name)),
            record.installed_version,
            allow_prerelease,
            registry,
            now,
            release_cutoff.cutoff_for(record.package_name) if release_cutoff else None,
        )
        in_range = [
            pv
            for pv in eligible
            if version_satisfies_constraint(pv.version, record.version_constraint, registry.package_registry)
            and satisfies_all_constraints(pv.version, record.all_constraints, registry.package_registry)
        ]
        aged = [
            pv
            for pv in in_range
            if (age := age_days_from_iso(pv.published_date_iso, now=now)) is not None and age >= cooldown_period
        ]
        # Newest-first order, aged before fresh; the validator is the costly check, so it runs
        # lazily and only down to the first release that passes.
        fitted = next(
            (
                pv
                for pv in [*aged, *(pv for pv in in_range if pv not in aged)]
                if validator is None or validator(record.package_name, pv.version)
            ),
            None,
        )
        record.recommended_version = fitted.version if fitted else None
        record.recommended_version_reason = None  # reason described the unclamped pick
        record.recommended_from_rung = RecommendationRung.IN_RANGE if fitted else None


def settle_transitive_picks(
    records: list[ScanRecord],
    registry: AbstractPackageRegistryApi,
    *,
    allow_prerelease: bool,
    installed_names: set[str],
    now: datetime | None = None,
    release_cutoff: ReleaseCutoff | None = None,
    direct_versions: Mapping[str, str] | None = None,
) -> None:
    """Walk each transitive pick's own requirements, keeping it only when what it drags along can follow.

    The transitive solver picks versions name by name. Where copies nest (npm), a pick that pins its
    family exactly (typescript-eslint and its @typescript-eslint/*) would otherwise move alone,
    leaving the family split between stale hoisted copies and new nested ones. Each pick is
    simulated like a direct update: the copies it has to move in place are kept as OVERRIDE_BUMP
    impacts on the record for the plan, and a pick whose family or peers cannot follow is dropped,
    with the reason recorded as a rejected candidate.

    Args:
        records: The transitive records, after the solver's picks were applied.
        registry: Registry with the scan's warm cache.
        allow_prerelease: Whether the walk may project prereleases.
        installed_names: Every package installed anywhere in the tree.
        now: Reference time for the projections.
        release_cutoff: The package manager's own limit on release age.
        direct_versions: {name: installed version} for direct dependencies, which peers may name.
    """
    if registry.one_copy_per_name:
        return
    by_name = {record.package_name: record for record in records}
    for record in records:
        pick = record.recommended_version
        if not pick or pick == record.installed_version:
            continue
        impact = simulate_single(
            record.package_name,
            pick,
            by_name,
            registry,
            allow_prerelease,
            installed_names=installed_names,
            now=now,
            installed_version=record.installed_version,
            release_cutoff=release_cutoff,
            incoming_peers=incoming_peer_edges(record.installed_copies, record.installed_version),
            direct_versions=direct_versions,
        )
        if impact.is_actionable:
            record.update_transitive_impacts = [
                i for i in impact.transitive_impacts if i.kind == ImpactKind.OVERRIDE_BUMP
            ]
            continue
        headline, detail = describe_rejection(impact, by_name)
        record.rejected_candidates = [
            *record.rejected_candidates,
            RejectedCandidate(version=pick, reason=headline, detail=detail, held_by_peer=peer_hold(impact)),
        ]
        record.recommended_version = None
        record.recommended_version_reason = None
        record.recommended_from_rung = None
        record.update_transitive_impacts = []
        clear_target_facts(record)
