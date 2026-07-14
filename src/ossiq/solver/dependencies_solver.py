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
from ossiq.solver.driver import ConflictSet
from ossiq.solver.driver_glucose import GlucoseDriver
from ossiq.solver.encoder import ConstraintEncoder
from ossiq.solver.kernel import HPDRKernel
from ossiq.solver.problem import SolverProblem
from ossiq.solver.reason import RecommendationReason, build_reason
from ossiq.solver.universe import DepLike, SolvablePool
from ossiq.solver.version_matchers import satisfies_all_constraints, version_satisfies_constraint
from ossiq.solver.weights import VERY_FRESH_THRESHOLD_DAYS

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

MAX_CONSISTENCY_ROUNDS = 3


def apply_fallback(
    output: SolverOutput,
    problem: SolverProblem,
    validator: Callable[[str, str], bool],
    *,
    cooldown_period: int = VERY_FRESH_THRESHOLD_DAYS,
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
                and version_satisfies_constraint(cv.version, declared, problem.registry)
                and satisfies_all_constraints(cv.version, all_specs, problem.registry)
                and validator(pkg, cv.version)
            ),
            None,
        )

        if fallback is not None:
            logger.debug("apply_fallback: %s demoted %s -> %s", pkg, version, fallback)
            new_recs[pkg] = fallback
            new_reasons[pkg] = build_reason(pkg, fallback, problem, penalize_fresh_days=cooldown_period)
        else:
            logger.debug("apply_fallback: %s==%s dropped — no acceptable fallback candidate", pkg, version)

    return SolverOutput(recommendations=new_recs, reasons=new_reasons, conflicts=output.conflicts)


def build_requires_validator(
    problem: SolverProblem,
    registry: AbstractPackageRegistryApi,
    recommendations: dict[str, str],
    external_targets: dict[str, str],
) -> Callable[[str, str], bool]:
    """Reject candidates whose requirements conflict with other pinned or held versions.

    A recommended version is acceptable only when every dependency it declares is satisfied by
    the version that dependency will end up at: its own recommendation within this solve, or an
    external target (e.g. direct-dep versions when solving transitives). Dependencies outside
    the solution are skipped — the package manager resolves them freely.
    """

    def validate(pkg: str, version: str) -> bool:
        for dep, spec in registry.package_version_requires(pkg, version).items():
            if not spec or dep == pkg:
                continue
            target = recommendations.get(dep) or external_targets.get(dep)
            if target is None:
                continue
            # TODO: strict check is conservative — a dep whose recommendation equals its installed
            #       version is not pinned in the plan, so the resolver may still move it in-range.
            if not version_satisfies_constraint(target, spec, problem.registry):
                logger.debug("requires check: %s==%s needs %s%s, held at %s", pkg, version, dep, spec, target)
                return False
        return True

    return validate


def apply_requires_consistency(
    output: SolverOutput,
    problem: SolverProblem,
    registry: AbstractPackageRegistryApi,
    *,
    extra_validator: Callable[[str, str], bool] | None = None,
    external_targets: dict[str, str] | None = None,
    cooldown_period: int = VERY_FRESH_THRESHOLD_DAYS,
) -> SolverOutput:
    """Demote or drop recommendations until the joint set is requires-consistent.

    Runs apply_fallback in a bounded fixpoint loop: each round rebuilds the requires validator
    from the previous round's recommendations, because a demotion can invalidate picks that were
    validated against the pre-demotion version. A final drop-only sweep guarantees the returned
    set is consistent even if the loop stops at its round cap.
    """
    targets = external_targets or {}

    def combine(requires_validator: Callable[[str, str], bool]) -> Callable[[str, str], bool]:
        if extra_validator is None:
            return requires_validator
        return lambda pkg, version: extra_validator(pkg, version) and requires_validator(pkg, version)

    for _ in range(MAX_CONSISTENCY_ROUNDS):
        requires_validator = build_requires_validator(problem, registry, output.recommendations, targets)
        new_output = apply_fallback(output, problem, combine(requires_validator), cooldown_period=cooldown_period)
        if new_output.recommendations == output.recommendations:
            return new_output
        output = new_output

    requires_validator = build_requires_validator(problem, registry, output.recommendations, targets)
    consistent = {pkg: ver for pkg, ver in output.recommendations.items() if requires_validator(pkg, ver)}
    return SolverOutput(
        recommendations=consistent,
        reasons={pkg: output.reasons[pkg] for pkg in consistent},
        conflicts=output.conflicts,
    )


def detect_conflicts(problem: SolverProblem) -> list[ConstraintConflict]:
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
            if not cv.has_cve
            and not cv.is_yanked
            and satisfies_all_constraints(cv.version, all_specs, problem.registry)
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
    cooldown_period: int = VERY_FRESH_THRESHOLD_DAYS,
    rewrite_pinned: bool = False,
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
        rewrite_pinned=rewrite_pinned,
    )
    logger.debug("%s: pool built — packages=%d", label, len(problem.constraints))
    encoded = ConstraintEncoder(penalize_fresh_days=cooldown_period).encode(problem)
    logger.debug("%s: encoded — hard=%d soft=%d", label, len(encoded.hard_clauses), len(encoded.soft_clauses))
    result = HPDRKernel(GlucoseDriver()).solve(encoded)

    if isinstance(result, ConflictSet):
        logger.debug("%s: solver returned ConflictSet: %s", label, result.unsatisfied_clauses)
        conflicts = detect_conflicts(problem)
        return SolverOutput(recommendations={}, reasons={}, conflicts=conflicts), problem

    recommendations = dict(result.selected)
    logger.debug("%s: selected %d recommendations", label, len(recommendations))
    reasons = {
        pkg: build_reason(pkg, ver, problem, penalize_fresh_days=cooldown_period)
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
    cooldown_period: int = VERY_FRESH_THRESHOLD_DAYS,
    rewrite_pinned: bool = False,
) -> SolverOutput:
    """Run HPDR solver over direct dependencies.

    Args:
        deps: Direct dependency descriptors satisfying the DepLike Protocol
              (canonical_name, version, version_constraint, constraint_info).
        registry: Registry instance with warm cache from the preceding scan pass.
        engine_context: Project engine versions for L2 clause generation.
                        Pass {} in Phase 4 — populating from project metadata is Phase 5+.
        allow_prerelease: When True, include pre-release candidates.
        rewrite_pinned: When True, PINNED (==x.y.z) deps become solver-eligible
                        so their pinned version can be rewritten.

    Returns:
        SolverOutput with recommendations and per-package rationales.
        Returns empty SolverOutput when solver cannot select any version or deps is empty.
        Recommendations are post-validated for joint requires-consistency: a pick whose
        declared requirements conflict with another pick is demoted or dropped.
    """
    if not deps:
        return EMPTY_OUTPUT

    output, problem = _run_solve(
        "solve_direct",
        deps,
        registry,
        engine_context,
        allow_prerelease=allow_prerelease,
        now=_now,
        cooldown_period=cooldown_period,
        rewrite_pinned=rewrite_pinned,
    )
    if not output.recommendations:
        return output
    return apply_requires_consistency(
        output,
        problem,
        registry,
        extra_validator=post_solve_validator,
        cooldown_period=cooldown_period,
    )


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
    cooldown_period: int = VERY_FRESH_THRESHOLD_DAYS,
    external_targets: dict[str, str] | None = None,
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
        external_targets: {package: version} pins outside this solve (direct-dep installed
                          versions and recommendations). A transitive pick whose requirements
                          conflict with these is demoted or dropped.

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
    output, problem = _run_solve(
        "solve_transitive",
        deps,
        registry,
        engine_context,
        allow_prerelease=allow_prerelease,
        cve_affected=cve_affected,
        now=now,
        cooldown_period=cooldown_period,
    )
    if not output.recommendations:
        return output
    return apply_requires_consistency(
        output,
        problem,
        registry,
        external_targets=external_targets,
        cooldown_period=cooldown_period,
    )
