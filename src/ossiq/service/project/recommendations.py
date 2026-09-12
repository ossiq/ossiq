"""
Applying solver output (recommendations and conflicts) onto ScanRecord instances.
"""

from datetime import datetime

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import ConstraintType
from ossiq.service.project.models import ScanRecord
from ossiq.solver import dependencies_solver
from ossiq.solver.universe import filter_eligible_versions
from ossiq.solver.version_matchers import version_satisfies_constraint
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


def apply_recommendations(
    records: list[ScanRecord],
    output: dependencies_solver.SolverOutput,
    *,
    skip_current: bool = False,
) -> None:
    """Write solver recommendations back onto ScanRecord instances in-place."""
    for record in records:
        rec = output.recommendations.get(record.package_name)
        if rec is not None and (not skip_current or rec != record.installed_version):
            record.recommended_version = rec
            record.recommended_version_reason = output.reasons.get(record.package_name)


def apply_version_ladder_fallback(records: list[ScanRecord]) -> None:
    """B2: when recommended_version is stuck at (or below) installed_version, fall back down the
    version ladder instead of leaving the caller with nothing to act on.

    Root cause this addresses: the solver only ever proposes versions inside the declared
    constraint, so an exact pin (or a global solver conflict) leaves recommended_version at
    None/installed even when a perfectly good newer release exists just outside the pin. B1, B3
    and B7 are downstream symptoms of that same gap.

    Ladder, most-preferred first:
      1. latest_version  - but only when it shares installed_version's major. Crossing a breaking
         major without knowing whether it's API-compatible is exactly the pydantic-1.x-to-2.x
         trap this bug report opens with; that judgment call is B5's job, not implemented yet, so
         this step never silently proposes a different major.
      2. latest_in_major - newest release within the major you're already on.
      3. latest_in_range - newest release the declared constraint itself allows (usually just
         installed_version again for an exact pin — kept as the last resort so the field is never
         simply abandoned).

    Sets recommended_version_exceeds_range when the pick isn't the solver's own in-constraint
    choice, so downstream consumers (next_action, the MCP/agent format, the export) know reaching
    it needs a manifest edit, not just a lockfile bump. Runs unconditionally — including when the
    solver found nothing at all — since a global solver conflict is exactly the situation where a
    fallback matters most. Leaves the record untouched when the solver already found an in-range
    move, or when installed_version is genuinely the newest version that exists anywhere.
    """
    for record in records:
        stuck = record.recommended_version is None or record.recommended_version == record.installed_version
        if not stuck:
            continue

        same_major_latest = (
            record.latest_version if record.latest_version == record.latest_in_major else None
        )
        pick = same_major_latest or record.latest_in_major or record.latest_in_range
        if not pick or pick == record.installed_version:
            continue

        record.recommended_version = pick
        record.recommended_version_exceeds_range = True


def clamp_recommendations(
    records: list[ScanRecord],
    registry: AbstractPackageRegistryApi,
    *,
    allow_prerelease: bool,
    now: datetime | None = None,
    rewrite_pinned: bool = False,
    cooldown_period: int = 0,
) -> None:
    """Re-fit recommendations that violate a record's own version constraint.

    The solver keys by canonical name, so npm aliases of one package share a single
    recommendation; clamp each record to the newest eligible version inside its own range,
    and never below the record's own installed version (a wide alias like ``npm:ms@*`` can
    inherit a sibling's downgrade that still satisfies its range).
    Mirrors the solver's soft cooldown: prefer versions older than cooldown_period,
    fall back to a fresher one only when nothing aged satisfies the range.
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
        )
        in_range = [
            pv
            for pv in eligible
            if version_satisfies_constraint(pv.version, record.version_constraint, registry.package_registry)
        ]
        aged = [
            pv
            for pv in in_range
            if (age := age_days_from_iso(pv.published_date_iso, now=now)) is not None and age >= cooldown_period
        ]
        fitted = aged[0] if aged else (in_range[0] if in_range else None)
        record.recommended_version = fitted.version if fitted else None
        record.recommended_version_reason = None  # reason described the unclamped pick
