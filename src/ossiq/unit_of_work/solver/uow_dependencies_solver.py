"""HPDR solver adapter: chains SolvablePool -> ConstraintEncoder -> HPDRKernel."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.cve import CVE
from ossiq.domain.project import ConstraintSource
from ossiq.unit_of_work.solver.driver import ConflictSet
from ossiq.unit_of_work.solver.driver_pysat import PySATDriver
from ossiq.unit_of_work.solver.encoder import ConstraintEncoder
from ossiq.unit_of_work.solver.kernel import HPDRKernel
from ossiq.unit_of_work.solver.problem import SolverProblem
from ossiq.unit_of_work.solver.reason import RecommendationReason, build_reason
from ossiq.unit_of_work.solver.universe import DepLike, SolvablePool
from ossiq.unit_of_work.solver.version_matchers import satisfies_all_constraints, version_satisfies_constraint
from ossiq.unit_of_work.solver.weights import VERY_FRESH_THRESHOLD_DAYS

logger = logging.getLogger(__name__)


class TransitiveRecord(Protocol):
    """Structural interface for transitive ScanRecord objects passed to solve_transitive."""

    package_name: str
    installed_version: str
    version_constraint: str | None
    constraint_info: ConstraintSource
    cve: list[CVE]
    version_age_days: int | None
    all_constraints: list[str]


@dataclass(frozen=True)
class ConstraintConflict:
    """A package for which no valid version satisfies all collected constraints."""

    package_name: str
    conflicting_constraints: list[str]


@dataclass(frozen=True)
class SolverOutput:
    """Combined result of the HPDR solver: recommendations and their rationales."""

    recommendations: dict[str, str]
    reasons: dict[str, RecommendationReason]
    conflicts: list[ConstraintConflict] = field(default_factory=list)


EMPTY_OUTPUT = SolverOutput(recommendations={}, reasons={})


def _apply_fallback(
    output: SolverOutput,
    problem: SolverProblem,
    validator: Callable[[str, str], bool],
) -> SolverOutput:
    """Replace solver picks that fail validation with the next-best acceptable candidate.

    Iterates problem.candidates in descending preference order (newest-first as produced
    by SolvablePool.build). Skips L1-violating and CVE versions — mirroring the hard
    rejections the encoder would have applied. Drops a package entirely when no candidate
    passes the validator.
    """
    constraints_by_name = {c.package_name: c for c in problem.constraints}
    new_recs: dict[str, str] = {}
    new_reasons: dict[str, RecommendationReason] = {}

    for pkg, version in output.recommendations.items():
        if validator(pkg, version):
            new_recs[pkg] = version
            new_reasons[pkg] = output.reasons[pkg]
            continue

        constraint = constraints_by_name.get(pkg)
        all_specs = list(constraint.all_constraints) if constraint else []
        declared = constraint.version_constraint if constraint else None

        fallback = next(
            (
                cv.version
                for cv in problem.candidates.get(pkg, ())
                if cv.version != version
                and not cv.has_cve
                and version_satisfies_constraint(cv.version, declared)
                and satisfies_all_constraints(cv.version, all_specs)
                and validator(pkg, cv.version)
            ),
            None,
        )

        if fallback is not None:
            new_recs[pkg] = fallback
            new_reasons[pkg] = build_reason(pkg, fallback, problem, penalize_fresh_days=VERY_FRESH_THRESHOLD_DAYS)

    return SolverOutput(recommendations=new_recs, reasons=new_reasons)


def _detect_conflicts(problem: SolverProblem) -> list[ConstraintConflict]:
    """Return one ConstraintConflict per package that has no viable candidate under its full constraint set."""
    result = []
    for constraint in problem.constraints:
        all_specs = [s for s in constraint.all_constraints if s]
        if constraint.version_constraint:
            all_specs = [constraint.version_constraint, *all_specs]
        if not all_specs:
            continue
        candidates = problem.candidates.get(constraint.package_name, ())
        viable = [
            cv
            for cv in candidates
            if not cv.has_cve and not cv.is_yanked and satisfies_all_constraints(cv.version, all_specs)
        ]
        if not viable:
            result.append(ConstraintConflict(constraint.package_name, all_specs))
    return result


def _run_solve(
    label: str,
    deps: Sequence[DepLike],
    registry: AbstractPackageRegistryApi,
    engine_context: dict[str, str],
    *,
    allow_prerelease: bool = False,
    cve_affected: dict[str, set[str]] | None = None,
    now: datetime | None = None,
) -> tuple[SolverOutput, SolverProblem]:
    """Run the SolvablePool → ConstraintEncoder → HPDRKernel pipeline.

    Returns (SolverOutput, SolverProblem) so callers can apply post-processing
    (e.g. fallback validation). Returns (EMPTY_OUTPUT, empty problem) on conflict.
    """
    logger.debug("%s: building pool for %d deps", label, len(deps))
    problem = SolvablePool.build(
        deps,
        registry,
        engine_context,
        cve_affected=cve_affected or {},
        allow_prerelease=allow_prerelease,
        _now=now,
    )
    logger.debug("%s: pool built — packages=%d", label, len(problem.constraints))
    encoded = ConstraintEncoder(penalize_fresh_days=VERY_FRESH_THRESHOLD_DAYS).encode(problem)
    logger.debug("%s: encoded — hard=%d soft=%d", label, len(encoded.hard_clauses), len(encoded.soft_clauses))
    result = HPDRKernel(PySATDriver()).solve(encoded)

    if isinstance(result, ConflictSet):
        logger.debug("%s: solver returned ConflictSet: %s", label, result.unsatisfied_clauses)
        conflicts = _detect_conflicts(problem)
        return SolverOutput(recommendations={}, reasons={}, conflicts=conflicts), problem

    recommendations = dict(result.selected)
    logger.debug("%s: selected %d recommendations", label, len(recommendations))
    reasons = {
        pkg: build_reason(pkg, ver, problem, penalize_fresh_days=VERY_FRESH_THRESHOLD_DAYS)
        for pkg, ver in recommendations.items()
    }
    return SolverOutput(recommendations=recommendations, reasons=reasons), problem


def solve_direct(
    deps: Sequence[DepLike],
    registry: AbstractPackageRegistryApi,
    engine_context: dict[str, str],
    *,
    allow_prerelease: bool = False,
    post_solve_validator: Callable[[str, str], bool] | None = None,
    _now: datetime | None = None,
) -> SolverOutput:
    """Run HPDR solver over direct dependencies.

    Args:
        deps: Direct dependency descriptors satisfying the DepLike Protocol
              (canonical_name, version, version_constraint, constraint_info).
        registry: Registry instance with warm cache from the preceding scan pass.
        engine_context: Project engine versions for L2 clause generation.
                        Pass {} in Phase 4 — populating from project metadata is Phase 5+.
        allow_prerelease: When True, include pre-release candidates.

    Returns:
        SolverOutput with recommendations and per-package rationales.
        Returns empty SolverOutput when solver cannot select any version or deps is empty.
    """
    if not deps:
        return EMPTY_OUTPUT

    output, problem = _run_solve(
        "solve_direct", deps, registry, engine_context, allow_prerelease=allow_prerelease, now=_now
    )
    if post_solve_validator is not None and output.recommendations:
        return _apply_fallback(output, problem, post_solve_validator)
    return output


@dataclass(frozen=True)
class TransitiveDependency:
    """Minimal DepLike adapter built from a transitive ScanRecord."""

    canonical_name: str
    version: str
    version_constraint: str | None
    constraint_info: ConstraintSource
    all_constraints: list[str] = field(default_factory=list)


def solve_transitive(
    transitive_records: Sequence[TransitiveRecord],
    registry: AbstractPackageRegistryApi,
    engine_context: dict[str, str],
    *,
    allow_prerelease: bool = False,
    now: datetime | None = None,
) -> SolverOutput:
    """Run HPDR solver over transitive dependencies.

    Caller is responsible for pre-filtering (e.g. CVE-only or all-transitive).
    CVE-affected candidate versions receive L5 hard-forbidden clauses.
    Candidate versions < VERY_FRESH_THRESHOLD_DAYS old receive L6 (1M) soft penalty.

    Args:
        transitive_records: Sequence satisfying TransitiveRecord (i.e. ScanRecord objects).
        registry: Registry instance with warm cache from the preceding scan pass.
        engine_context: Project engine versions. Pass {} — populating deferred to Phase 6+.
        allow_prerelease: When True, include pre-release candidates.

    Returns:
        SolverOutput with recommendations and per-package rationales.
        Returns empty SolverOutput when deps is empty or solver conflicts.
    """
    logger.debug("solve_transitive: received %d records", len(transitive_records))
    if not transitive_records:
        return EMPTY_OUTPUT

    # 1. Deduplicate by package_name — keep first occurrence (same as direct pass).
    unique_records = list({r.package_name: r for r in transitive_records}.values())

    # 2. Build CVE-affected-versions map: {canonical_name: {version, ...}}.
    cve_affected: dict[str, set[str]] = {}
    for r in unique_records:
        for cve in r.cve:
            cve_affected.setdefault(r.package_name, set()).update(cve.affected_versions)

    # 3. Convert to DepLike-compatible adapters.
    deps: list[TransitiveDependency] = [
        TransitiveDependency(
            canonical_name=r.package_name,
            version=r.installed_version,
            version_constraint=r.version_constraint,
            constraint_info=r.constraint_info,
            all_constraints=list(r.all_constraints),
        )
        for r in unique_records
    ]

    # 4. Build -> encode -> solve.
    output, _ = _run_solve(
        "solve_transitive",
        deps,
        registry,
        engine_context,
        allow_prerelease=allow_prerelease,
        cve_affected=cve_affected,
        now=now,
    )
    return output
