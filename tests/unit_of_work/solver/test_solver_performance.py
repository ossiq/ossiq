"""Solver performance smoke tests.

These tests guard against SAT encoder / driver regressions by asserting that
solve_direct and solve_transitive complete within a wall-time budget on synthetic
inputs representative of a medium-sized real project (20 direct + 20 transitive
deps, 30 candidate versions each, no network calls).
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

from packaging.version import Version as PV

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import ConstraintType
from ossiq.domain.cve import CVE
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion
from ossiq.unit_of_work.solver.uow_dependencies_solver import SolverOutput, solve_direct, solve_transitive

PACKAGES = 20
CANDIDATES = 30
BUDGET_SECONDS = 1.0


def _pv(version: str, published: str = "2024-01-01T00:00:00Z") -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url=f"https://example.com/{version}",
        declared_dependencies={},
        published_date_iso=published,
        is_yanked=False,
        is_unpublished=False,
        is_prerelease=False,
        is_deprecated=False,
        runtime_requirements=None,
    )


def _make_registry(versions_by_name: dict[str, list[PackageVersion]]) -> MagicMock:
    from ossiq.domain.common import ProjectPackagesRegistry

    registry = MagicMock(spec=AbstractPackageRegistryApi)
    registry.package_registry = ProjectPackagesRegistry.PYPI
    registry.package_versions.side_effect = lambda name: versions_by_name.get(name, [])

    def _cmp(v1: str, v2: str) -> int:
        p1, p2 = PV(v1), PV(v2)
        return -1 if p1 < p2 else (1 if p1 > p2 else 0)

    registry.compare_versions.side_effect = _cmp
    return registry


def _build_synthetic_registry(n_packages: int, n_candidates: int) -> tuple[dict, MagicMock]:
    """Build a synthetic registry with n_packages, each having n_candidates versions."""
    versions_by_name: dict[str, list[PackageVersion]] = {}
    for i in range(n_packages):
        name = f"package-{i:03d}"
        versions_by_name[name] = [
            _pv(f"1.{j}.0", published=f"2024-{(j % 12) + 1:02d}-01T00:00:00Z") for j in range(n_candidates)
        ]
    return versions_by_name, _make_registry(versions_by_name)


class _FakeDep:
    def __init__(self, canonical_name: str, version: str) -> None:
        self.canonical_name = canonical_name
        self.version = version
        self.version_constraint = None
        self.constraint_info = ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml")
        self.all_constraints: list[str] = []


class _FakeTransitiveRecord:
    """Satisfies the TransitiveRecord Protocol required by solve_transitive."""

    def __init__(self, package_name: str, installed_version: str) -> None:
        self.package_name = package_name
        self.installed_version = installed_version
        self.version_constraint: str | None = None
        self.constraint_info = ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml")
        self.cve: list[CVE] = []
        self.version_age_days: int | None = None
        self.all_constraints: list[str] = []


class TestSolveDirectPerformance:
    def test_completes_within_budget(self) -> None:
        """solve_direct on 20 packages × 30 candidates must finish under BUDGET_SECONDS."""
        versions_by_name, registry = _build_synthetic_registry(PACKAGES, CANDIDATES)
        deps = [_FakeDep(name, "1.0.0") for name in versions_by_name]

        start = time.perf_counter()
        result = solve_direct(deps, registry, {})
        elapsed = time.perf_counter() - start

        assert isinstance(result, SolverOutput)
        assert elapsed < BUDGET_SECONDS, f"solve_direct took {elapsed:.2f}s — regression? (budget {BUDGET_SECONDS}s)"


class TestSolveTransitivePerformance:
    def test_completes_within_budget(self) -> None:
        """solve_transitive on 20 packages × 30 candidates must finish under BUDGET_SECONDS."""
        versions_by_name, registry = _build_synthetic_registry(PACKAGES, CANDIDATES)
        records = [_FakeTransitiveRecord(name, "1.0.0") for name in versions_by_name]

        start = time.perf_counter()
        result = solve_transitive(records, registry, {})
        elapsed = time.perf_counter() - start

        assert isinstance(result, SolverOutput)
        assert elapsed < BUDGET_SECONDS, (
            f"solve_transitive took {elapsed:.2f}s — regression? (budget {BUDGET_SECONDS}s)"
        )
