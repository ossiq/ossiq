from __future__ import annotations

import logging

from ossiq.unit_of_work.solver.driver import AbstractSolverDriver, ConflictSet, EncodedProblem, SolverResult

logger = logging.getLogger(__name__)


class HPDRKernel:
    """Orchestrates MaxSAT solving via a pluggable driver."""

    def __init__(self, driver: AbstractSolverDriver) -> None:
        self._driver = driver

    def solve(self, problem: EncodedProblem) -> SolverResult | ConflictSet:
        """Delegate solving to the configured driver."""
        logger.debug(
            "HPDRKernel.solve: driver=%s hard_clauses=%d soft_clauses=%d vars=%d",
            self._driver.name(),
            len(problem.hard_clauses),
            len(problem.soft_clauses),
            len(problem.var_map),
        )
        result = self._driver.solve(problem)
        if isinstance(result, ConflictSet):
            logger.debug("HPDRKernel result: ConflictSet unsatisfied=%d", len(result.unsatisfied_clauses))
        else:
            logger.debug("HPDRKernel result: selected %d packages", len(result.selected))
        return result

    @property
    def driver_name(self) -> str:
        """Name of the configured driver."""
        return self._driver.name()
