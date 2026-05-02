from __future__ import annotations

import abc
from dataclasses import dataclass


@dataclass(frozen=True)
class SolverResult:
    """Satisfying MaxSAT assignment returned by the solver."""

    selected: list[tuple[str, str]]  # (package_name, version)


@dataclass(frozen=True)
class ConflictSet:
    """Returned when hard clauses are unsatisfiable."""

    unsatisfied_clauses: list[str]


@dataclass
class EncodedProblem:
    """WCNF encoding ready for a solver driver."""

    hard_clauses: list[list[int]]
    soft_clauses: list[tuple[int, list[int]]]  # (weight, clause)
    var_map: dict[int, tuple[str, str]]  # var_id → (package_name, version)


class AbstractSolverDriver(abc.ABC):
    """Driver abstraction allowing the pysat prototype to be swapped for a native implementation."""

    @abc.abstractmethod
    def solve(self, problem: EncodedProblem) -> SolverResult | ConflictSet:
        """Solve an encoded WCNF problem and return either a solution or a conflict set."""
        ...

    @abc.abstractmethod
    def name(self) -> str:
        """Return a string identifying this driver."""
        ...
