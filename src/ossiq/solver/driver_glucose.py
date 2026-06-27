"""Glucose3 SAT driver with greedy sequential assumption strategy."""

from __future__ import annotations

import logging
import threading

from pysat.solvers import Glucose42

from ossiq.solver.driver import AbstractSolverDriver, ConflictSet, EncodedProblem, SolverResult

logger = logging.getLogger(__name__)

SOLVER_TIMEOUT_SECONDS: int = 10


def compute_preferred_vids(problem: EncodedProblem) -> list[int]:
    """Return one preferred vid per package, ordered by net soft-clause weight.

    For each package, the vid with the highest net soft score is preferred:
    - L3 positive clauses (weight, [+vid]) add weight (reward for selection)
    - L2/L4/L6 negative clauses (weight, [-vid]) subtract weight (penalty)

    Only eligible vids appear in soft_clauses, so ineligible candidates are
    never selected as the preferred vid.
    """
    net_score: dict[int, int] = {}
    for weight, clause in problem.soft_clauses:
        if len(clause) != 1:
            continue
        lit = clause[0]
        vid = abs(lit)
        if vid not in problem.var_map:
            continue
        net_score[vid] = net_score.get(vid, 0) + (weight if lit > 0 else -weight)

    pkg_best: dict[str, int] = {}
    for vid, score in net_score.items():
        pkg, _ = problem.var_map[vid]
        current = pkg_best.get(pkg)
        if current is None or score > net_score.get(current, 0):
            pkg_best[pkg] = vid

    return list(pkg_best.values())


class GlucoseDriver(AbstractSolverDriver):
    """Solver driver backed by Glucose3 SAT with greedy sequential assumptions.

    Replaces RC2Stratified MaxSAT.  For each package the highest-net-soft-weight
    version is greedily committed as a SAT assumption (if compatible with already-
    committed choices).  This encodes the "pick newest, avoid deprecated/penalised"
    preference without the NP-hard optimisation cost of MaxSAT.
    """

    def solve(self, problem: EncodedProblem) -> SolverResult | ConflictSet:
        """Solve hard clauses using Glucose3, guided by sequential soft-weight assumptions."""
        result_holder: list[SolverResult | ConflictSet] = []

        def run() -> None:
            preferred_vids = compute_preferred_vids(problem)

            with Glucose42(bootstrap_with=problem.hard_clauses) as solver:
                # Greedily commit the preferred vid for each package: if adding it
                # remains satisfiable alongside already-committed choices, lock it in.
                committed: list[int] = []
                for vid in preferred_vids:
                    if solver.solve(assumptions=committed + [vid]):
                        committed.append(vid)

                # Final solve with all committed preferred vids.
                sat = solver.solve(assumptions=committed)
                if not sat:
                    result_holder.append(ConflictSet(unsatisfied_clauses=["unsat"]))
                    return

                model = solver.get_model() or []
                selected_vars = [v for v in model if v > 0 and v in problem.var_map]
                selected = [problem.var_map[v] for v in sorted(selected_vars)]
                result_holder.append(SolverResult(selected=selected))

        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(timeout=SOLVER_TIMEOUT_SECONDS)

        if not result_holder:
            logger.warning("GlucoseDriver: solver timed out after %ds — returning ConflictSet", SOLVER_TIMEOUT_SECONDS)
            return ConflictSet(unsatisfied_clauses=["timeout"])

        return result_holder[0]

    def name(self) -> str:
        return "glucose3-sequential-assumptions"
