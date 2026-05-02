from __future__ import annotations

from ossiq.unit_of_work.solver.driver import AbstractSolverDriver, ConflictSet, EncodedProblem, SolverResult


class HPDRKernel:
    """Orchestrates MaxSAT solving via a pluggable driver."""

    def __init__(self, driver: AbstractSolverDriver) -> None:
        self._driver = driver

    def solve(self, problem: EncodedProblem) -> SolverResult | ConflictSet:
        """Delegate solving to the configured driver."""
        return self._driver.solve(problem)

    @property
    def driver_name(self) -> str:
        """Name of the configured driver."""
        return self._driver.name()
