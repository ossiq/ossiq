from __future__ import annotations

import logging
from dataclasses import dataclass, field

from packaging.utils import canonicalize_name

from ossiq.unit_of_work.solver.driver import EncodedProblem
from ossiq.unit_of_work.solver.driver_pysat import VarAllocator
from ossiq.unit_of_work.solver.problem import CandidateVersion, SolverProblem
from ossiq.unit_of_work.solver.version_matchers import has_engine_mismatch, version_satisfies_constraint
from ossiq.unit_of_work.solver.weights import W_DEPRECATED, W_ENGINE, W_VERY_FRESH, semver_rank_weight

logger = logging.getLogger(__name__)


def ladder_amo(eligible_vids: list[int], alloc: VarAllocator) -> list[list[int]]:
    """Enforce At-Most-One over eligible_vids via the Sinz (2005) ladder encoding.

    Uses n-1 auxiliary carry variables that propagate a "someone was already picked"
    flag down the chain. Any later candidate colliding with a raised flag makes the
    formula unsatisfiable, ensuring only one version is selected.
    Uses ~3n clauses instead of the O(n²) pairwise approach.
    """
    n = len(eligible_vids)
    if n <= 1:
        return []

    x = eligible_vids
    carry = [alloc.allocate_fresh() for _ in range(n - 1)]
    clauses: list[list[int]] = []

    # Boundary: first candidate raises carry[0]; last requires carry[n-2] still unset
    clauses.append([-x[0], carry[0]])
    clauses.append([-x[n - 1], -carry[n - 2]])

    # Middle candidates: raise carry, assert no earlier pick, propagate carry forward
    for i in range(1, n - 1):
        clauses.append([-x[i], carry[i]])  # if picked -> raise carry
        clauses.append([-x[i], -carry[i - 1]])  # if picked -> nobody before was picked
        clauses.append([-carry[i - 1], carry[i]])  # propagate carry forward

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
        logger.debug(
            "ConstraintEncoder.encode: packages=%d penalize_fresh_days=%d",
            len(problem.constraints),
            self.penalize_fresh_days,
        )
        alloc = VarAllocator()
        pkg_state, var_map = self.allocate_variables(problem, alloc)
        logger.debug("Pass 1 complete: allocated %d SAT variables", len(var_map))
        hard_clauses, soft_clauses = self.encode_package_clauses(problem, pkg_state, alloc)
        logger.debug("Pass 2 complete: hard_clauses=%d soft_clauses=%d", len(hard_clauses), len(soft_clauses))
        impl_clauses = self.encode_implication_clauses(problem, pkg_state)
        logger.debug("Pass 3 complete: implication_clauses=%d", len(impl_clauses))
        hard_clauses.extend(impl_clauses)
        logger.debug("Encoding done: total hard=%d soft=%d", len(hard_clauses), len(soft_clauses))
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
                logger.debug("Pass 1: %s skipped — no candidates in registry", pkg)
                continue
            all_vids: list[int] = []
            for cv in candidates:
                vid = alloc.allocate(pkg, cv.version)
                var_map[vid] = (pkg, cv.version)
                all_vids.append(vid)
            logger.debug("Pass 1: %s allocated %d vars", pkg, len(all_vids))
            pkg_state[pkg] = PackageState(candidates=candidates, all_vids=all_vids)

        return pkg_state, var_map

    def encode_package_clauses(
        self,
        problem: SolverProblem,
        pkg_state: dict[str, PackageState],
        alloc: VarAllocator,
    ) -> tuple[list[list[int]], list[tuple[int, list[int]]]]:
        """Pass 2: emit per-package hard (L1, L5, AMO, ALO) and soft (L2-L6) clauses.

        Mutates pkg_state in-place to populate eligible_vids and eligible_set.
        """
        hard_clauses: list[list[int]] = []
        soft_clauses: list[tuple[int, list[int]]] = []

        for constraint in problem.constraints:
            pkg = constraint.package_name
            if pkg not in pkg_state:
                continue
            state = pkg_state[pkg]

            # L1 + L5: forbid out-of-constraint and CVE-affected versions.
            # When all_constraints is populated (transitive deps with multiple parents),
            # a version must satisfy every parent's specifier — diamond-dep correctness.
            # Falls back to the single version_constraint for direct deps and simple transitives.
            l1_constraints = constraint.all_constraints or (
                (constraint.version_constraint,) if constraint.version_constraint else ()
            )
            eligible_vids: list[int] = []
            l1_forbidden = 0
            l5_forbidden = 0
            for cv, vid in zip(state.candidates, state.all_vids, strict=True):
                if any(not version_satisfies_constraint(cv.version, c, problem.registry) for c in l1_constraints):
                    hard_clauses.append([-vid])  # L1 constraint mismatch (any parent violated)
                    l1_forbidden += 1
                elif cv.has_cve:
                    hard_clauses.append([-vid])  # L5 CVE hard-forbidden
                    l5_forbidden += 1
                else:
                    eligible_vids.append(vid)

            state.eligible_vids = eligible_vids
            state.eligible_set = set(eligible_vids)
            eligible_rank: dict[int, int] = {vid: rank for rank, vid in enumerate(eligible_vids)}

            logger.debug(
                "Pass 2: %s candidates=%d eligible=%d l1_constraint_forbidden=%d l5_cve_forbidden=%d",
                pkg,
                len(state.candidates),
                len(eligible_vids),
                l1_forbidden,
                l5_forbidden,
            )
            if not eligible_vids:
                logger.debug("Pass 2: %s has NO eligible candidates — will be UNSAT", pkg)

            # Structural: ladder AMO + ALO over eligible candidates
            hard_clauses.extend(ladder_amo(eligible_vids, alloc))
            if eligible_vids:
                hard_clauses.append(list(eligible_vids))  # ALO; skip if empty (UNSAT by design)

            # Soft clauses — eligible candidates only
            for cv, vid in zip(state.candidates, state.all_vids, strict=True):
                if vid not in state.eligible_set:
                    continue
                if has_engine_mismatch(cv, problem.engine_context):
                    soft_clauses.append((W_ENGINE, [-vid]))  # L2
                soft_clauses.append((semver_rank_weight(eligible_rank[vid]), [vid]))  # L3: semver rank
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
        # Cache version_satisfies_constraint results: (version, constraint) -> bool.
        # The same pair is evaluated O(packages × deps) times across all candidates.
        sat_cache: dict[tuple[str, str | None], bool] = {}

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
                    compatible = []
                    for dep_cv, dep_vid in zip(dep_state.candidates, dep_state.all_vids, strict=True):
                        if dep_vid not in dep_state.eligible_set:
                            continue
                        key = (dep_cv.version, dep_constraint)
                        satisfies = sat_cache.get(key)
                        if satisfies is None:
                            satisfies = version_satisfies_constraint(dep_cv.version, dep_constraint, problem.registry)
                            sat_cache[key] = satisfies
                        if satisfies:
                            compatible.append(dep_vid)
                    if not compatible:
                        continue  # no satisfying candidate — skip conservatively
                    hard_clauses.append([-vid] + compatible)  # implication: A@v -> ∃ compatible B

        return hard_clauses
