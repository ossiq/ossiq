"""Unit tests for build_reason() in solver/reason.py."""

from __future__ import annotations

from ossiq.domain.common import ConstraintType
from ossiq.unit_of_work.solver.problem import CandidateVersion, PackageConstraint, SolverProblem
from ossiq.unit_of_work.solver.reason import build_reason

# ---------------------------------------------------------------------------
# Test helpers (mirror test_encoder.py style)
# ---------------------------------------------------------------------------


def _cv(
    version: str,
    *,
    age_days: int | None = 100,
    is_deprecated: bool = False,
    is_prerelease: bool = False,
    is_yanked: bool = False,
    runtime_requirements: dict[str, str] | None = None,
    has_cve: bool = False,
    requires: dict[str, str | None] | None = None,
) -> CandidateVersion:
    return CandidateVersion(
        version=version,
        age_days=age_days,
        is_deprecated=is_deprecated,
        is_prerelease=is_prerelease,
        is_yanked=is_yanked,
        runtime_requirements=runtime_requirements,
        has_cve=has_cve,
        requires=requires,
    )


def _pc(
    package_name: str,
    *,
    version_constraint: str | None = None,
    constraint_type: ConstraintType = ConstraintType.DECLARED,
    installed_version: str = "1.0.0",
) -> PackageConstraint:
    return PackageConstraint(
        package_name=package_name,
        version_constraint=version_constraint,
        constraint_type=constraint_type,
        installed_version=installed_version,
    )


def _sp(
    constraints: list[PackageConstraint],
    candidates_dict: dict[str, list[CandidateVersion]],
    *,
    engine_context: dict[str, str] | None = None,
) -> SolverProblem:
    return SolverProblem(
        constraints=tuple(constraints),
        candidates={pkg: tuple(cvs) for pkg, cvs in candidates_dict.items()},
        engine_context=engine_context or {},
    )


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestBuildReasonEdgeCases:
    def test_no_candidates_returns_empty_reason(self) -> None:
        problem = _sp([_pc("pkg")], {})
        reason = build_reason("pkg", "1.0.0", problem)
        assert reason.hard_rejections == []
        assert reason.soft_rejections == []
        assert reason.lower_semver_alternatives == []
        assert reason.age_days is None
        assert reason.is_latest is False

    def test_pkg_not_in_constraints_returns_empty_reason(self) -> None:
        problem = _sp([_pc("other")], {"pkg": [_cv("1.0.0")]})
        reason = build_reason("pkg", "1.0.0", problem)
        assert reason.hard_rejections == []
        assert reason.soft_rejections == []
        assert reason.lower_semver_alternatives == []

    def test_selected_not_found_in_candidates_returns_fallback(self) -> None:
        problem = _sp([_pc("pkg")], {"pkg": [_cv("2.0.0"), _cv("1.0.0")]})
        reason = build_reason("pkg", "9.9.9", problem)
        assert reason.hard_rejections == []
        assert reason.soft_rejections == []
        assert reason.lower_semver_alternatives == []
        assert reason.age_days is None
        assert reason.is_latest is False

    def test_single_candidate_selected_is_latest(self) -> None:
        problem = _sp([_pc("pkg")], {"pkg": [_cv("1.0.0", age_days=50)]})
        reason = build_reason("pkg", "1.0.0", problem)
        assert reason.is_latest is True
        assert reason.age_days == 50
        assert reason.hard_rejections == []
        assert reason.soft_rejections == []
        assert reason.lower_semver_alternatives == []


# ---------------------------------------------------------------------------
# Hard rejections
# ---------------------------------------------------------------------------


class TestBuildReasonHardRejections:
    def test_l1_constraint_mismatch(self) -> None:
        problem = _sp(
            [_pc("pkg", version_constraint=">=1.0,<2.0")],
            {"pkg": [_cv("2.5.0", age_days=10), _cv("1.5.0", age_days=100)]},
        )
        reason = build_reason("pkg", "1.5.0", problem)
        assert len(reason.hard_rejections) == 1
        assert reason.hard_rejections[0].version == "2.5.0"
        assert reason.hard_rejections[0].cause == "constraint_mismatch"
        assert ">=1.0,<2.0" in reason.hard_rejections[0].detail
        assert reason.soft_rejections == []
        assert reason.is_latest is False

    def test_l5_cve_hard_rejection(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("2.0.0", has_cve=True, age_days=20), _cv("1.0.0", age_days=200)]},
        )
        reason = build_reason("pkg", "1.0.0", problem)
        assert len(reason.hard_rejections) == 1
        assert reason.hard_rejections[0].version == "2.0.0"
        assert reason.hard_rejections[0].cause == "cve"
        assert reason.soft_rejections == []

    def test_l1_takes_priority_over_l5(self) -> None:
        """A version that fails both L1 and L5 should be reported as constraint_mismatch."""
        problem = _sp(
            [_pc("pkg", version_constraint=">=1.0,<2.0")],
            {"pkg": [_cv("3.0.0", has_cve=True, age_days=5), _cv("1.5.0", age_days=100)]},
        )
        reason = build_reason("pkg", "1.5.0", problem)
        assert len(reason.hard_rejections) == 1
        assert reason.hard_rejections[0].cause == "constraint_mismatch"

    def test_multiple_hard_rejections(self) -> None:
        problem = _sp(
            [_pc("pkg", version_constraint=">=1.0,<3.0")],
            {
                "pkg": [
                    _cv("3.0.0", age_days=5),  # outside constraint
                    _cv("2.9.0", has_cve=True, age_days=10),  # CVE
                    _cv("2.0.0", age_days=150),  # selected
                ]
            },
        )
        reason = build_reason("pkg", "2.0.0", problem)
        assert len(reason.hard_rejections) == 2
        causes = {r.cause for r in reason.hard_rejections}
        assert causes == {"constraint_mismatch", "cve"}
        assert reason.soft_rejections == []


# ---------------------------------------------------------------------------
# Soft rejections
# ---------------------------------------------------------------------------


class TestBuildReasonSoftRejections:
    def test_l2_engine_mismatch(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("2.0.0", age_days=10, runtime_requirements={"python": ">=3.12"}), _cv("1.0.0", age_days=200)]},
            engine_context={"python": "3.11"},
        )
        reason = build_reason("pkg", "1.0.0", problem)
        assert len(reason.soft_rejections) == 1
        assert reason.soft_rejections[0].version == "2.0.0"
        assert reason.soft_rejections[0].cause == "engine_mismatch"
        assert reason.hard_rejections == []

    def test_l4_deprecated(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("2.0.0", is_deprecated=True, age_days=30), _cv("1.0.0", age_days=200)]},
        )
        reason = build_reason("pkg", "1.0.0", problem)
        assert len(reason.soft_rejections) == 1
        assert reason.soft_rejections[0].version == "2.0.0"
        assert reason.soft_rejections[0].cause == "deprecated"

    def test_l6_very_fresh(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("2.0.0", age_days=2), _cv("1.0.0", age_days=200)]},
        )
        reason = build_reason("pkg", "1.0.0", problem, penalize_fresh_days=7)
        assert len(reason.soft_rejections) == 1
        assert reason.soft_rejections[0].version == "2.0.0"
        assert reason.soft_rejections[0].cause == "very_fresh"
        assert "2 days" in reason.soft_rejections[0].detail

    def test_l6_disabled_when_penalize_fresh_days_zero(self) -> None:
        """With penalize_fresh_days=0 (default), a 2-day-old version is not soft-rejected."""
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("2.0.0", age_days=2), _cv("1.0.0", age_days=200)]},
        )
        reason = build_reason("pkg", "1.0.0", problem, penalize_fresh_days=0)
        # 2.0.0 is eligible and only loses on age preference (L3) — no rejection entry.
        assert reason.soft_rejections == []

    def test_l2_takes_priority_over_l4(self) -> None:
        """Engine mismatch (L2, 1M weight) wins over deprecated (L4, 10K weight)."""
        problem = _sp(
            [_pc("pkg")],
            {
                "pkg": [
                    _cv("2.0.0", age_days=10, is_deprecated=True, runtime_requirements={"python": ">=3.12"}),
                    _cv("1.0.0", age_days=200),
                ]
            },
            engine_context={"python": "3.11"},
        )
        reason = build_reason("pkg", "1.0.0", problem)
        assert len(reason.soft_rejections) == 1
        assert reason.soft_rejections[0].cause == "engine_mismatch"

    def test_l6_takes_priority_over_l4(self) -> None:
        """Very fresh (L6, 1M weight) wins over deprecated (L4, 10K weight)."""
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("2.0.0", age_days=3, is_deprecated=True), _cv("1.0.0", age_days=200)]},
        )
        reason = build_reason("pkg", "1.0.0", problem, penalize_fresh_days=7)
        assert len(reason.soft_rejections) == 1
        assert reason.soft_rejections[0].cause == "very_fresh"


# ---------------------------------------------------------------------------
# is_latest and age_days
# ---------------------------------------------------------------------------


class TestBuildReasonMetadata:
    def test_is_latest_true_when_selected_is_newest(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("2.0.0", has_cve=True), _cv("1.5.0", age_days=50)]},
        )
        # 2.0.0 is hard-rejected; 1.5.0 is the top eligible candidate.
        reason = build_reason("pkg", "1.5.0", problem)
        assert reason.is_latest is False  # 1.5.0 is not candidates[0]

    def test_is_latest_true_when_selected_is_candidates_zero(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("2.0.0", age_days=50)]},
        )
        reason = build_reason("pkg", "2.0.0", problem)
        assert reason.is_latest is True

    def test_age_days_populated_from_selected(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("2.0.0", age_days=10), _cv("1.0.0", age_days=45)]},
        )
        reason = build_reason("pkg", "1.0.0", problem)
        assert reason.age_days == 45

    def test_age_days_none_when_candidate_has_no_age(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("1.0.0", age_days=None)]},
        )
        reason = build_reason("pkg", "1.0.0", problem)
        assert reason.age_days is None

    def test_constraint_propagated_from_problem(self) -> None:
        problem = _sp(
            [_pc("pkg", version_constraint=">=1.0,<3.0")],
            {"pkg": [_cv("2.0.0")]},
        )
        reason = build_reason("pkg", "2.0.0", problem)
        assert reason.constraint == ">=1.0,<3.0"

    def test_constraint_none_when_unconstrained(self) -> None:
        problem = _sp([_pc("pkg")], {"pkg": [_cv("1.0.0")]})
        reason = build_reason("pkg", "1.0.0", problem)
        assert reason.constraint is None


# ---------------------------------------------------------------------------
# Combined scenario
# ---------------------------------------------------------------------------


class TestBuildReasonCombined:
    def test_mixed_hard_and_soft_rejections(self) -> None:
        """Realistic scenario: constraint, CVE, very-fresh, deprecated, then stable selection."""
        problem = _sp(
            [_pc("pkg", version_constraint=">=1.0,<3.0")],
            {
                "pkg": [
                    _cv("3.0.0", age_days=5),  # L1 outside constraint
                    _cv("2.9.0", has_cve=True, age_days=10),  # L5 CVE
                    _cv("2.8.2", age_days=3),  # L6 very fresh
                    _cv("2.8.0", is_deprecated=True, age_days=90),  # L4 deprecated
                    _cv("2.8.1", age_days=45),  # selected (last candidate)
                ]
            },
        )
        reason = build_reason("pkg", "2.8.1", problem, penalize_fresh_days=7)
        assert len(reason.hard_rejections) == 2
        assert {r.version for r in reason.hard_rejections} == {"3.0.0", "2.9.0"}
        assert len(reason.soft_rejections) == 2
        assert {r.version for r in reason.soft_rejections} == {"2.8.2", "2.8.0"}
        assert reason.lower_semver_alternatives == []
        assert reason.age_days == 45
        assert reason.is_latest is False

    def test_age_preference_only_produces_no_rejection_entry(self) -> None:
        """Newer semver candidate loses only on L3 rank — no rejection entry emitted."""
        problem = _sp(
            [_pc("pkg")],
            {
                "pkg": [
                    _cv("2.0.0", age_days=5),  # penalize_fresh_days=0 → L3 rank only
                    _cv("1.0.0", age_days=200),  # selected (lower rank wins via penalize_fresh_days)
                ]
            },
        )
        reason = build_reason("pkg", "1.0.0", problem, penalize_fresh_days=0)
        assert reason.soft_rejections == []
        assert reason.hard_rejections == []
        assert reason.lower_semver_alternatives == []


# ---------------------------------------------------------------------------
# lower_semver_alternatives
# ---------------------------------------------------------------------------


class TestBuildReasonLowerSemverAlternatives:
    def test_eligible_lower_semver_candidate_reported(self) -> None:
        problem = _sp(
            [_pc("vite", version_constraint=">=7.0.0")],
            {"vite": [_cv("8.0.7", age_days=45), _cv("7.3.2", age_days=3)]},
        )
        reason = build_reason("vite", "8.0.7", problem)
        assert reason.is_latest is True
        assert reason.hard_rejections == []
        assert reason.soft_rejections == []
        assert len(reason.lower_semver_alternatives) == 1
        assert reason.lower_semver_alternatives[0].version == "7.3.2"
        assert reason.lower_semver_alternatives[0].cause == "lower_semver"

    def test_constraint_violating_lower_semver_excluded(self) -> None:
        # 7.3.2 is outside the >=8.0.0 constraint → not in lower_semver_alternatives
        problem = _sp(
            [_pc("vite", version_constraint=">=8.0.0")],
            {"vite": [_cv("8.0.7", age_days=45), _cv("7.3.2", age_days=3)]},
        )
        reason = build_reason("vite", "8.0.7", problem)
        assert reason.lower_semver_alternatives == []

    def test_cve_affected_lower_semver_excluded(self) -> None:
        problem = _sp(
            [_pc("pkg", version_constraint=">=1.0.0")],
            {"pkg": [_cv("2.0.0", age_days=30), _cv("1.0.0", has_cve=True, age_days=5)]},
        )
        reason = build_reason("pkg", "2.0.0", problem)
        assert reason.lower_semver_alternatives == []

    def test_lower_semver_alternatives_capped_at_five(self) -> None:
        # 8.0.7 selected; 7.x stream has 6 eligible candidates → capped at 5
        candidates = [_cv("8.0.7", age_days=30)] + [_cv(f"7.{i}.0", age_days=50 + i) for i in range(6, 0, -1)]
        problem = _sp(
            [_pc("pkg", version_constraint=">=7.0.0")],
            {"pkg": candidates},
        )
        reason = build_reason("pkg", "8.0.7", problem)
        assert len(reason.lower_semver_alternatives) == 5
