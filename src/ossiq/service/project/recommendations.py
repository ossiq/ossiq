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
