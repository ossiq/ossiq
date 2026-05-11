"""Recommendation rationale: explains why a solver-selected version was chosen."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ossiq.unit_of_work.solver.problem import SolverProblem
from ossiq.unit_of_work.solver.version_matchers import has_engine_mismatch, version_satisfies_constraint

RejectionCause = Literal["constraint_mismatch", "cve", "engine_mismatch", "deprecated", "very_fresh", "lower_semver"]


@dataclass(frozen=True)
class VersionRejection:
    """A single candidate version that was not selected and why."""

    version: str
    cause: RejectionCause
    detail: str


@dataclass(frozen=True)
class RecommendationReason:
    """Human-readable explanation of why a solver-selected version was chosen."""

    selected_version: str
    constraint: str | None
    hard_rejections: list[VersionRejection]
    soft_rejections: list[VersionRejection]
    lower_semver_alternatives: list[VersionRejection]
    age_days: int | None
    is_latest: bool


def _empty_reason(selected_version: str, constraint: str | None = None) -> RecommendationReason:
    return RecommendationReason(
        selected_version=selected_version,
        constraint=constraint,
        hard_rejections=[],
        soft_rejections=[],
        lower_semver_alternatives=[],
        age_days=None,
        is_latest=False,
    )


def build_reason(
    pkg: str,
    selected_version: str,
    problem: SolverProblem,
    penalize_fresh_days: int = 0,
) -> RecommendationReason:
    """Explain why selected_version was chosen for pkg by re-applying encoder predicates.

    Iterates over all candidates newer than selected_version and categorises each as:
    - hard-rejected (L1 constraint mismatch, L5 CVE) — could never be selected
    - soft-rejected (L2 engine mismatch, L4 deprecated, L6 very fresh) — penalised enough to lose
    - age-preference loss (L3) — eligible but selected had higher age_weight; no entry emitted

    Reuses version_satisfies_constraint() and has_engine_mismatch() from version_matchers.py.
    """
    constraint = next((c for c in problem.constraints if c.package_name == pkg), None)
    candidates = problem.candidates.get(pkg, ())

    if not candidates:
        return _empty_reason(selected_version, constraint.version_constraint if constraint else None)

    # Find the index of the selected version in candidates (newest->oldest order).
    selected_index: int | None = None
    for i, cv in enumerate(candidates):
        if cv.version == selected_version:
            selected_index = i
            break

    if selected_index is None:
        return _empty_reason(selected_version, constraint.version_constraint if constraint else None)

    version_constraint = constraint.version_constraint if constraint else None
    hard_rejections: list[VersionRejection] = []
    soft_rejections: list[VersionRejection] = []

    for cv in candidates[:selected_index]:
        # L1 hard: constraint mismatch
        if not version_satisfies_constraint(cv.version, version_constraint):
            hard_rejections.append(
                VersionRejection(
                    version=cv.version,
                    cause="constraint_mismatch",
                    detail=f"outside {version_constraint}",
                )
            )
            continue

        # L5 hard: known CVE
        if cv.has_cve:
            hard_rejections.append(
                VersionRejection(
                    version=cv.version,
                    cause="cve",
                    detail="has known CVE",
                )
            )
            continue

        # Soft checks — highest-weight cause wins (1M > 10K).
        # L2 (1M): engine mismatch
        if has_engine_mismatch(cv, problem.engine_context):
            soft_rejections.append(
                VersionRejection(
                    version=cv.version,
                    cause="engine_mismatch",
                    detail="engine requirement mismatch",
                )
            )
            continue

        # L6 (1M): very fresh supply-chain risk
        if penalize_fresh_days > 0 and cv.age_days is not None and cv.age_days < penalize_fresh_days:
            soft_rejections.append(
                VersionRejection(
                    version=cv.version,
                    cause="very_fresh",
                    detail=f"{cv.age_days} days old (supply-chain risk)",
                )
            )
            continue

        # L4 (10K): deprecated
        if cv.is_deprecated:
            soft_rejections.append(
                VersionRejection(
                    version=cv.version,
                    cause="deprecated",
                    detail="deprecated",
                )
            )
            continue

        # L3 semver-rank: selected has higher rank — no rejection entry needed.

    # Lower-semver alternatives: eligible candidates ranked below selected (lower version).
    # These lost purely because they have a lower semver rank, not due to any hard/soft rejection.
    lower_semver_alternatives: list[VersionRejection] = []
    for cv in candidates[selected_index + 1 :]:
        if not version_satisfies_constraint(cv.version, version_constraint):
            continue
        if cv.has_cve:
            continue
        lower_semver_alternatives.append(
            VersionRejection(
                version=cv.version,
                cause="lower_semver",
                detail=f"lower semver than {selected_version}",
            )
        )
        if len(lower_semver_alternatives) >= 5:
            break

    return RecommendationReason(
        selected_version=selected_version,
        constraint=version_constraint,
        hard_rejections=hard_rejections,
        soft_rejections=soft_rejections,
        lower_semver_alternatives=lower_semver_alternatives,
        age_days=candidates[selected_index].age_days,
        is_latest=selected_index == 0,
    )
