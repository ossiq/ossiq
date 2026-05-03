from unittest.mock import MagicMock

from ossiq.unit_of_work.solver.driver import AbstractSolverDriver, ConflictSet, EncodedProblem, SolverResult
from ossiq.unit_of_work.solver.driver_pysat import PySATDriver, VarAllocator
from ossiq.unit_of_work.solver.kernel import HPDRKernel


def _problem(
    hard: list[list[int]],
    soft: list[tuple[int, list[int]]],
    var_map: dict[int, tuple[str, str]],
) -> EncodedProblem:
    return EncodedProblem(hard_clauses=hard, soft_clauses=soft, var_map=var_map)


class TestVarAllocator:
    def test_ids_start_at_one(self) -> None:
        alloc = VarAllocator()
        assert alloc.allocate("requests", "1.0.0") == 1

    def test_allocates_unique_ids(self) -> None:
        alloc = VarAllocator()
        ids = {alloc.allocate("a", "1.0"), alloc.allocate("a", "2.0"), alloc.allocate("b", "1.0")}
        assert len(ids) == 3
        assert all(i > 0 for i in ids)

    def test_idempotent(self) -> None:
        alloc = VarAllocator()
        assert alloc.allocate("requests", "1.0.0") == alloc.allocate("requests", "1.0.0")

    def test_different_packages_same_version_distinct(self) -> None:
        alloc = VarAllocator()
        assert alloc.allocate("a", "1.0") != alloc.allocate("b", "1.0")

    def test_decode_round_trip(self) -> None:
        alloc = VarAllocator()
        pairs = [("requests", "1.0"), ("requests", "2.0"), ("flask", "1.0"), ("flask", "2.0"), ("numpy", "3.0")]
        for pkg, ver in pairs:
            var_id = alloc.allocate(pkg, ver)
            assert alloc.decode(var_id) == (pkg, ver)


class TestPySATDriverSolving:
    def test_selects_higher_weighted_version(self) -> None:
        # v2 (3.0.0) has weight 100; v1 (2.0.0) has weight 1.
        # Selecting v1: pay 100 (v2 not selected). Selecting v2: pay 1 (v1 not selected).
        var_map = {1: ("requests", "2.0.0"), 2: ("requests", "3.0.0")}
        problem = _problem(
            hard=[[-1, -2], [1, 2]],
            soft=[(1, [1]), (100, [2])],
            var_map=var_map,
        )
        result = PySATDriver().solve(problem)
        assert isinstance(result, SolverResult)
        assert result.selected == [("requests", "3.0.0")]

    def test_hard_clause_eliminates_candidate(self) -> None:
        # v1 (2.0.0) is forbidden by hard clause, even though its soft weight is higher.
        var_map = {1: ("requests", "2.0.0"), 2: ("requests", "3.0.0")}
        problem = _problem(
            hard=[[-1, -2], [1, 2], [-1]],
            soft=[(100, [1]), (1, [2])],
            var_map=var_map,
        )
        result = PySATDriver().solve(problem)
        assert isinstance(result, SolverResult)
        assert result.selected == [("requests", "3.0.0")]

    def test_unsat_returns_conflict_set(self) -> None:
        # Hard clauses [1] and [-1] are contradictory.
        var_map = {1: ("requests", "1.0.0")}
        problem = _problem(hard=[[1], [-1]], soft=[], var_map=var_map)
        result = PySATDriver().solve(problem)
        assert isinstance(result, ConflictSet)

    def test_deprecated_penalty_loses_to_non_deprecated(self) -> None:
        # v1 (1.0.0) is deprecated: selecting it costs +10_000 on top of equal age weights.
        # Cost(v1 selected) = 100_000 (v2 missed) + 10_000 (deprecated) = 110_000
        # Cost(v2 selected) = 100_000 (v1 missed) = 100_000
        var_map = {1: ("flask", "1.0.0"), 2: ("flask", "1.1.0")}
        problem = _problem(
            hard=[[-1, -2], [1, 2]],
            soft=[(100_000, [1]), (100_000, [2]), (10_000, [-1])],
            var_map=var_map,
        )
        result = PySATDriver().solve(problem)
        assert isinstance(result, SolverResult)
        assert result.selected == [("flask", "1.1.0")]

    def test_engine_weight_overrides_age_preference(self) -> None:
        # v1 (2.0.0) is newest (weight 100_000) but engine-incompatible (penalty 1_000_000).
        # Cost(v1 selected) = 1 (v2 missed) + 1_000_000 (engine) = 1_000_001
        # Cost(v2 selected) = 100_000 (v1 missed)
        var_map = {1: ("numpy", "2.0.0"), 2: ("numpy", "1.0.0")}
        problem = _problem(
            hard=[[-1, -2], [1, 2]],
            soft=[(100_000, [1]), (1, [2]), (1_000_000, [-1])],
            var_map=var_map,
        )
        result = PySATDriver().solve(problem)
        assert isinstance(result, SolverResult)
        assert result.selected == [("numpy", "1.0.0")]

    def test_two_independent_packages(self) -> None:
        # Each package independently selects its highest-weighted (latest) version.
        var_map = {1: ("requests", "2.0.0"), 2: ("requests", "3.0.0"), 3: ("flask", "1.0.0"), 4: ("flask", "2.0.0")}
        problem = _problem(
            hard=[[-1, -2], [1, 2], [-3, -4], [3, 4]],
            soft=[(1, [1]), (100, [2]), (1, [3]), (100, [4])],
            var_map=var_map,
        )
        result = PySATDriver().solve(problem)
        assert isinstance(result, SolverResult)
        assert set(result.selected) == {("requests", "3.0.0"), ("flask", "2.0.0")}


class TestHPDRKernel:
    def test_delegates_to_driver(self) -> None:
        driver = MagicMock(spec=AbstractSolverDriver)
        driver.solve.return_value = SolverResult(selected=[])
        problem = _problem(hard=[], soft=[], var_map={})
        HPDRKernel(driver).solve(problem)
        driver.solve.assert_called_once_with(problem)

    def test_returns_solver_result_unchanged(self) -> None:
        driver = MagicMock(spec=AbstractSolverDriver)
        expected = SolverResult(selected=[("a", "1.0")])
        driver.solve.return_value = expected
        result = HPDRKernel(driver).solve(_problem(hard=[], soft=[], var_map={}))
        assert result is expected

    def test_returns_conflict_set_unchanged(self) -> None:
        driver = MagicMock(spec=AbstractSolverDriver)
        expected = ConflictSet(unsatisfied_clauses=["conflict"])
        driver.solve.return_value = expected
        result = HPDRKernel(driver).solve(_problem(hard=[], soft=[], var_map={}))
        assert result is expected

    def test_driver_name_proxied(self) -> None:
        driver = MagicMock(spec=AbstractSolverDriver)
        driver.name.return_value = "test-driver"
        assert HPDRKernel(driver).driver_name == "test-driver"
