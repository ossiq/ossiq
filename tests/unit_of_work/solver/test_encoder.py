from __future__ import annotations

from ossiq.domain.common import ConstraintType
from ossiq.unit_of_work.solver.driver import SolverResult
from ossiq.unit_of_work.solver.driver_pysat import PySATDriver
from ossiq.unit_of_work.solver.encoder import ConstraintEncoder
from ossiq.unit_of_work.solver.problem import CandidateVersion, PackageConstraint, SolverProblem
from ossiq.unit_of_work.solver.weights import W_DEPRECATED, W_ENGINE, age_weight

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _cv(
    version: str,
    *,
    age_days: int | None = 100,
    is_deprecated: bool = False,
    is_prerelease: bool = False,
    is_yanked: bool = False,
    runtime_requirements: dict[str, str] | None = None,
) -> CandidateVersion:
    return CandidateVersion(
        version=version,
        age_days=age_days,
        is_deprecated=is_deprecated,
        is_prerelease=is_prerelease,
        is_yanked=is_yanked,
        runtime_requirements=runtime_requirements,
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
# TestWeightConstants
# ---------------------------------------------------------------------------


class TestWeightConstants:
    def test_weight_constants_values(self) -> None:
        assert W_ENGINE == 1_000_000
        assert W_DEPRECATED == 10_000

    def test_age_weight_zero_days(self) -> None:
        assert age_weight(0) == 100_000

    def test_age_weight_large_age_clamped(self) -> None:
        assert age_weight(200_000) == 1
        assert age_weight(100_000) == 1

    def test_age_weight_none_returns_one(self) -> None:
        assert age_weight(None) == 1


# ---------------------------------------------------------------------------
# TestConstraintEncoderL1Hard
# ---------------------------------------------------------------------------


class TestConstraintEncoderL1Hard:
    def test_none_constraint_all_candidates_eligible(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("1.0.0"), _cv("2.0.0")]},
        )
        enc = ConstraintEncoder().encode(problem)
        # No unit hard clauses (length-1 clauses with negative literal)
        unit_negated = [c for c in enc.hard_clauses if len(c) == 1 and c[0] < 0]
        assert unit_negated == []
        # ALO clause should contain both vars
        alo_clauses = [c for c in enc.hard_clauses if len(c) == 2 and all(v > 0 for v in c)]
        assert len(alo_clauses) == 1

    def test_out_of_range_version_hard_forbidden(self) -> None:
        problem = _sp(
            [_pc("pkg", version_constraint=">=2.0,<3.0")],
            {"pkg": [_cv("1.5.0"), _cv("2.5.0")]},
        )
        enc = ConstraintEncoder().encode(problem)
        # Find vid for "1.5.0"
        vid_15 = next(vid for vid, (_, v) in enc.var_map.items() if v == "1.5.0")
        assert [-vid_15] in enc.hard_clauses

    def test_in_range_version_is_eligible(self) -> None:
        problem = _sp(
            [_pc("pkg", version_constraint=">=2.0,<3.0")],
            {"pkg": [_cv("1.5.0"), _cv("2.5.0")]},
        )
        enc = ConstraintEncoder().encode(problem)
        vid_25 = next(vid for vid, (_, v) in enc.var_map.items() if v == "2.5.0")
        # Must appear in ALO, not negated
        unit_negated = [c for c in enc.hard_clauses if len(c) == 1 and c[0] < 0]
        assert [-vid_25] not in unit_negated
        alo_clauses = [c for c in enc.hard_clauses if vid_25 in c and all(v > 0 for v in c)]
        assert alo_clauses

    def test_pypi_compound_specifier(self) -> None:
        problem = _sp(
            [_pc("pkg", version_constraint=">=1.0,<3.0")],
            {"pkg": [_cv("0.9.0"), _cv("1.5.0"), _cv("3.1.0")]},
        )
        enc = ConstraintEncoder().encode(problem)
        vid_09 = next(vid for vid, (_, v) in enc.var_map.items() if v == "0.9.0")
        vid_31 = next(vid for vid, (_, v) in enc.var_map.items() if v == "3.1.0")
        vid_15 = next(vid for vid, (_, v) in enc.var_map.items() if v == "1.5.0")
        assert [-vid_09] in enc.hard_clauses
        assert [-vid_31] in enc.hard_clauses
        # ALO should contain only vid_15
        alo = [c for c in enc.hard_clauses if len(c) >= 1 and all(v > 0 for v in c)]
        assert any(c == [vid_15] for c in alo)

    def test_npm_caret_specifier(self) -> None:
        problem = _sp(
            [_pc("pkg", version_constraint="^2.0.0")],
            {"pkg": [_cv("1.9.9"), _cv("2.5.0"), _cv("3.0.0")]},
        )
        enc = ConstraintEncoder().encode(problem)
        vid_199 = next(vid for vid, (_, v) in enc.var_map.items() if v == "1.9.9")
        vid_300 = next(vid for vid, (_, v) in enc.var_map.items() if v == "3.0.0")
        vid_250 = next(vid for vid, (_, v) in enc.var_map.items() if v == "2.5.0")
        assert [-vid_199] in enc.hard_clauses
        assert [-vid_300] in enc.hard_clauses
        alo = [c for c in enc.hard_clauses if len(c) >= 1 and all(v > 0 for v in c)]
        assert any(c == [vid_250] for c in alo)


# ---------------------------------------------------------------------------
# TestConstraintEncoderStructural
# ---------------------------------------------------------------------------


class TestConstraintEncoderStructural:
    def test_alo_clause_present_for_eligible_candidates(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("1.0.0"), _cv("2.0.0")]},
        )
        enc = ConstraintEncoder().encode(problem)
        positive_clauses = [c for c in enc.hard_clauses if all(v > 0 for v in c)]
        # Exactly one ALO clause with both vars
        assert len(positive_clauses) == 1
        assert len(positive_clauses[0]) == 2

    def test_amo_pairwise_clauses(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("1.0.0"), _cv("2.0.0"), _cv("3.0.0")]},
        )
        enc = ConstraintEncoder().encode(problem)
        amo = [c for c in enc.hard_clauses if len(c) == 2 and all(v < 0 for v in c)]
        assert len(amo) == 3  # C(3,2)

    def test_no_candidates_produces_no_clauses(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {},  # no entry for "pkg"
        )
        enc = ConstraintEncoder().encode(problem)
        assert enc.hard_clauses == []
        assert enc.soft_clauses == []
        assert enc.var_map == {}

    def test_zero_eligible_after_l1_filter_skips_alo(self) -> None:
        # All candidates fail constraint → only unit hard clauses, no ALO
        problem = _sp(
            [_pc("pkg", version_constraint=">=5.0")],
            {"pkg": [_cv("1.0.0"), _cv("2.0.0")]},
        )
        enc = ConstraintEncoder().encode(problem)
        positive_clauses = [c for c in enc.hard_clauses if all(v > 0 for v in c)]
        assert positive_clauses == []
        unit_negated = [c for c in enc.hard_clauses if len(c) == 1 and c[0] < 0]
        assert len(unit_negated) == 2


# ---------------------------------------------------------------------------
# TestConstraintEncoderSoftClauses
# ---------------------------------------------------------------------------


class TestConstraintEncoderSoftClauses:
    def test_l2_engine_mismatch_adds_penalty_clause(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("1.0.0", runtime_requirements={"python": ">=3.12"})]},
            engine_context={"python": "3.11.9"},
        )
        enc = ConstraintEncoder().encode(problem)
        vid = next(iter(enc.var_map))
        assert (W_ENGINE, [-vid]) in enc.soft_clauses

    def test_l2_engine_compatible_no_penalty(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("1.0.0", runtime_requirements={"python": ">=3.8"})]},
            engine_context={"python": "3.11.9"},
        )
        enc = ConstraintEncoder().encode(problem)
        engine_penalties = [(w, c) for w, c in enc.soft_clauses if w == W_ENGINE]
        assert engine_penalties == []

    def test_l2_none_runtime_requirements_no_penalty(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("1.0.0", runtime_requirements=None)]},
            engine_context={"python": "3.11.9"},
        )
        enc = ConstraintEncoder().encode(problem)
        engine_penalties = [(w, c) for w, c in enc.soft_clauses if w == W_ENGINE]
        assert engine_penalties == []

    def test_l3_freshness_weight_from_age_days(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("1.0.0", age_days=500)]},
        )
        enc = ConstraintEncoder().encode(problem)
        vid = next(iter(enc.var_map))
        assert (99_500, [vid]) in enc.soft_clauses

    def test_l3_freshness_none_age_gets_weight_one(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("1.0.0", age_days=None)]},
        )
        enc = ConstraintEncoder().encode(problem)
        vid = next(iter(enc.var_map))
        assert (1, [vid]) in enc.soft_clauses

    def test_l4_deprecated_adds_penalty_clause(self) -> None:
        problem = _sp(
            [_pc("pkg")],
            {"pkg": [_cv("1.0.0", is_deprecated=True)]},
        )
        enc = ConstraintEncoder().encode(problem)
        vid = next(iter(enc.var_map))
        assert (W_DEPRECATED, [-vid]) in enc.soft_clauses


# ---------------------------------------------------------------------------
# TestConstraintEncoderRoundtrip (real RC2 — no mocks)
# ---------------------------------------------------------------------------


class TestConstraintEncoderRoundtrip:
    def test_roundtrip_selects_freshest_version(self) -> None:
        problem = _sp(
            [_pc("pkg", version_constraint=">=1.0")],
            {"pkg": [_cv("1.0.0", age_days=365), _cv("2.0.0", age_days=100), _cv("3.0.0", age_days=10)]},
        )
        enc = ConstraintEncoder().encode(problem)
        result = PySATDriver().solve(enc)
        assert isinstance(result, SolverResult)
        assert result.selected == [("pkg", "3.0.0")]

    def test_roundtrip_engine_incompatible_loses_to_older_compatible(self) -> None:
        # "3.0.0": freshest (age=0, weight=100_000) but needs python>=3.13 → engine penalty 1_000_000
        # "2.0.0": older (age=200, weight=99_800), compatible
        # Cost selecting 3.0.0: miss 2.0.0 (99_800) + engine mismatch (1_000_000) = 1_099_800
        # Cost selecting 2.0.0: miss 3.0.0 (100_000)
        problem = _sp(
            [_pc("pkg", version_constraint=">=1.0")],
            {
                "pkg": [
                    _cv("3.0.0", age_days=0, runtime_requirements={"python": ">=3.13"}),
                    _cv("2.0.0", age_days=200),
                ]
            },
            engine_context={"python": "3.11.9"},
        )
        enc = ConstraintEncoder().encode(problem)
        result = PySATDriver().solve(enc)
        assert isinstance(result, SolverResult)
        assert result.selected == [("pkg", "2.0.0")]

    def test_roundtrip_deprecated_loses_to_non_deprecated(self) -> None:
        # "2.0.0": age=50, deprecated → freshness bonus 99_950, deprecated penalty 10_000
        # "1.9.0": age=100, clean → freshness bonus 99_900
        # Cost selecting 2.0.0: miss 1.9.0 (99_900) + deprecated (10_000) = 109_900
        # Cost selecting 1.9.0: miss 2.0.0 (99_950)
        problem = _sp(
            [_pc("pkg", version_constraint=">=1.0")],
            {
                "pkg": [
                    _cv("2.0.0", age_days=50, is_deprecated=True),
                    _cv("1.9.0", age_days=100),
                ]
            },
        )
        enc = ConstraintEncoder().encode(problem)
        result = PySATDriver().solve(enc)
        assert isinstance(result, SolverResult)
        assert result.selected == [("pkg", "1.9.0")]
