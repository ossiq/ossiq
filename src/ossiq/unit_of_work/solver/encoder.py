from __future__ import annotations

from dataclasses import dataclass, field

from packaging.utils import canonicalize_name

from ossiq.unit_of_work.solver.driver import EncodedProblem
from ossiq.unit_of_work.solver.driver_pysat import VarAllocator
from ossiq.unit_of_work.solver.problem import CandidateVersion, SolverProblem
from ossiq.unit_of_work.solver.version_matchers import has_engine_mismatch, version_satisfies_constraint
from ossiq.unit_of_work.solver.weights import W_DEPRECATED, W_ENGINE, W_VERY_FRESH, age_weight


def _ladder_amo(eligible_vids: list[int], alloc: VarAllocator) -> list[list[int]]:
    """Return hard clauses enforcing At-Most-One over eligible_vids using ladder encoding.

    Uses the Sinz (2005) sequential-counter encoding: n-1 auxiliary variables and
    3n-4 clauses (linear), replacing the O(n²) pairwise encoding.
    """
    n = len(eligible_vids)
    if n <= 1:
        return []
    s = [alloc.allocate_fresh() for _ in range(n - 1)]
    x = eligible_vids
    clauses: list[list[int]] = [[-x[0], s[0]], [-x[n - 1], -s[n - 2]]]
    for i in range(1, n - 1):
        clauses.extend([[-x[i], s[i]], [-x[i], -s[i - 1]], [-s[i - 1], s[i]]])
    return clauses


@dataclass
class PackageState:
    """Intermediate per-package state shared across encoding passes."""

    candidates: tuple[CandidateVersion, ...]
    all_vids: list[int]
    eligible_vids: list[int] = field(default_factory=list)
    eligible_set: set[int] = field(default_factory=set)


class ConstraintEncoder:
    """Translates a SolverProblem into an EncodedProblem (hard + soft WCNF clauses)."""

    def __init__(self, penalize_fresh_days: int = 0) -> None:
        """Configure the encoder.

        Args:
            penalize_fresh_days: When > 0, candidate versions with age_days < this value
                                 receive a W_VERY_FRESH (1M) soft penalty (L6). Default 0 disables L6.
        """
        self.penalize_fresh_days = penalize_fresh_days

    def encode(self, problem: SolverProblem) -> EncodedProblem:
        """Encode a SolverProblem into hard and soft clauses for the MaxSAT solver."""
        alloc = VarAllocator()
        pkg_state, var_map = self.allocate_variables(problem, alloc)
        hard_clauses, soft_clauses = self.encode_package_clauses(problem, pkg_state, alloc)
        hard_clauses.extend(self.encode_implication_clauses(problem, pkg_state))
        return EncodedProblem(hard_clauses=hard_clauses, soft_clauses=soft_clauses, var_map=var_map)

    def allocate_variables(
        self, problem: SolverProblem, alloc: VarAllocator
    ) -> tuple[dict[str, PackageState], dict[int, tuple[str, str]]]:
        """Pass 1: allocate one SAT variable per (package, version) candidate.

        Returns pkg_state with empty eligible_vids/eligible_set and the var_map.
        """
        var_map: dict[int, tuple[str, str]] = {}
        pkg_state: dict[str, PackageState] = {}

        for constraint in problem.constraints:
            pkg = constraint.package_name
            candidates = problem.candidates.get(pkg, ())
            if not candidates:
                continue
            all_vids: list[int] = []
            for cv in candidates:
                vid = alloc.allocate(pkg, cv.version)
                var_map[vid] = (pkg, cv.version)
                all_vids.append(vid)
            pkg_state[pkg] = PackageState(candidates=candidates, all_vids=all_vids)

        return pkg_state, var_map

    def encode_package_clauses(
        self,
        problem: SolverProblem,
        pkg_state: dict[str, PackageState],
        alloc: VarAllocator,
    ) -> tuple[list[list[int]], list[tuple[int, list[int]]]]:
        """Pass 2: emit per-package hard (L1, L5, AMO, ALO) and soft (L2–L6) clauses.

        Mutates pkg_state in-place to populate eligible_vids and eligible_set.
        """
        hard_clauses: list[list[int]] = []
        soft_clauses: list[tuple[int, list[int]]] = []

        for constraint in problem.constraints:
            pkg = constraint.package_name
            if pkg not in pkg_state:
                continue
            state = pkg_state[pkg]

            # L1 + L5: forbid out-of-constraint and CVE-affected versions
            eligible_vids: list[int] = []
            for cv, vid in zip(state.candidates, state.all_vids, strict=True):
                if not version_satisfies_constraint(cv.version, constraint.version_constraint):
                    hard_clauses.append([-vid])  # L1 constraint mismatch
                elif cv.has_cve:
                    hard_clauses.append([-vid])  # L5 CVE hard-forbidden
                else:
                    eligible_vids.append(vid)

            state.eligible_vids = eligible_vids
            state.eligible_set = set(eligible_vids)

            # Structural: ladder AMO + ALO over eligible candidates
            hard_clauses.extend(_ladder_amo(eligible_vids, alloc))
            if eligible_vids:
                hard_clauses.append(list(eligible_vids))  # ALO; skip if empty (UNSAT by design)

            # Soft clauses — eligible candidates only
            for cv, vid in zip(state.candidates, state.all_vids, strict=True):
                if vid not in state.eligible_set:
                    continue
                if has_engine_mismatch(cv, problem.engine_context):
                    soft_clauses.append((W_ENGINE, [-vid]))  # L2
                soft_clauses.append((age_weight(cv.age_days), [vid]))  # L3
                if cv.is_deprecated:
                    soft_clauses.append((W_DEPRECATED, [-vid]))  # L4
                # L6: very fresh — strongly discourage supply-chain risks
                if self.penalize_fresh_days > 0 and cv.age_days is not None and cv.age_days < self.penalize_fresh_days:
                    soft_clauses.append((W_VERY_FRESH, [-vid]))
                # L7: health score — reserved, not implemented

        return hard_clauses, soft_clauses

    def encode_implication_clauses(
        self,
        problem: SolverProblem,
        pkg_state: dict[str, PackageState],
    ) -> list[list[int]]:
        """Pass 3: emit inter-package implication clauses from CandidateVersion.requires."""
        hard_clauses: list[list[int]] = []

        for constraint in problem.constraints:
            pkg = constraint.package_name
            if pkg not in pkg_state:
                continue
            state = pkg_state[pkg]

            for cv, vid in zip(state.candidates, state.all_vids, strict=True):
                if vid not in state.eligible_set or cv.requires is None:
                    continue
                for dep_pkg_raw, dep_constraint in cv.requires.items():
                    dep_pkg = canonicalize_name(dep_pkg_raw)
                    if dep_pkg not in pkg_state:
                        continue  # dependency not in this problem — skip
                    dep_state = pkg_state[dep_pkg]
                    compatible = [
                        dep_vid
                        for dep_cv, dep_vid in zip(dep_state.candidates, dep_state.all_vids, strict=True)
                        if dep_vid in dep_state.eligible_set
                        and version_satisfies_constraint(dep_cv.version, dep_constraint)
                    ]
                    if not compatible:
                        continue  # no satisfying candidate — skip conservatively
                    hard_clauses.append([-vid] + compatible)  # implication: A@v → ∃ compatible B

        return hard_clauses
