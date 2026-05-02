from __future__ import annotations

from pysat.examples.rc2 import RC2  # type: ignore[import]
from pysat.formula import WCNF  # type: ignore[import]

from ossiq.unit_of_work.solver.driver import AbstractSolverDriver, ConflictSet, EncodedProblem, SolverResult


class VarAllocator:
    """Bijective mapping between (package_name, version) pairs and positive integer SAT variable IDs."""

    def __init__(self) -> None:
        self._forward: dict[tuple[str, str], int] = {}
        self._reverse: dict[int, tuple[str, str]] = {}
        self._next: int = 1

    def allocate(self, package: str, version: str) -> int:
        """Return the variable ID for (package, version), allocating a new one if needed."""
        key = (package, version)
        if key not in self._forward:
            self._forward[key] = self._next
            self._reverse[self._next] = key
            self._next += 1
        return self._forward[key]

    def decode(self, var_id: int) -> tuple[str, str]:
        """Return the (package_name, version) pair for a given variable ID."""
        return self._reverse[var_id]

    @property
    def next_id(self) -> int:
        """The next variable ID that will be allocated."""
        return self._next


class PySATDriver(AbstractSolverDriver):
    """Solver driver backed by pysat RC2 (Weighted Partial MaxSAT)."""

    def solve(self, problem: EncodedProblem) -> SolverResult | ConflictSet:
        """Solve the encoded WCNF problem using RC2."""
        wcnf = WCNF()
        for clause in problem.hard_clauses:
            wcnf.append(clause)
        for weight, clause in problem.soft_clauses:
            wcnf.append(clause, weight=weight)

        with RC2(wcnf) as rc2:
            model = rc2.compute()
            if model is None:
                rc2.get_core()
                core: list[int] = getattr(rc2, "core", None) or []
                return ConflictSet(unsatisfied_clauses=[f"literal {v}" for v in core])

            selected_vars = [v for v in model if v > 0 and v in problem.var_map]
            selected = [problem.var_map[v] for v in sorted(selected_vars)]
            return SolverResult(selected=selected)

    def name(self) -> str:
        return "pysat-rc2"
