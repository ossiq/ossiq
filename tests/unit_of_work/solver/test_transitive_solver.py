"""Unit tests for uow_dependencies_solver.solve_transitive."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

from packaging.version import Version as PV

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion
from ossiq.unit_of_work.solver.uow_dependencies_solver import solve_transitive

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CONSTRAINT_SOURCE = ConstraintSource(type=ConstraintType.DECLARED, source_file="lock")


@dataclass
class _FakeCVE:
    """Minimal CVE stand-in carrying only affected_versions."""

    affected_versions: tuple[str, ...]


@dataclass
class _FakeRecord:
    """Minimal object satisfying the _TransitiveDepLike Protocol."""

    package_name: str
    installed_version: str
    version_constraint: str | None
    constraint_info: ConstraintSource
    cve: list[Any]
    version_age_days: int | None


def _rec(
    name: str,
    installed: str = "1.0.0",
    *,
    constraint: str | None = None,
    cve_affected: list[str] | None = None,
    age_days: int | None = 30,
) -> _FakeRecord:
    """Build a _FakeRecord. cve_affected lists versions the CVE covers."""
    cve_list = [_FakeCVE(affected_versions=tuple(cve_affected))] if cve_affected else []
    return _FakeRecord(
        package_name=name,
        installed_version=installed,
        version_constraint=constraint,
        constraint_info=_CONSTRAINT_SOURCE,
        cve=cve_list,
        version_age_days=age_days,
    )


def _pv(
    version: str,
    *,
    published: str | None = "2024-01-01T00:00:00Z",
    yanked: bool = False,
    unpublished: bool = False,
    prerelease: bool = False,
    deprecated: bool = False,
) -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url=f"https://example.com/{version}",
        declared_dependencies={},
        published_date_iso=published,
        is_yanked=yanked,
        is_unpublished=unpublished,
        is_prerelease=prerelease,
        is_deprecated=deprecated,
        runtime_requirements=None,
    )


def _make_registry(versions_by_name: dict[str, list[PackageVersion]]) -> MagicMock:
    registry = MagicMock(spec=AbstractPackageRegistryApi)
    registry.package_versions.side_effect = lambda name: versions_by_name.get(name, [])

    def _cmp(v1: str, v2: str) -> int:
        p1, p2 = PV(v1), PV(v2)
        return -1 if p1 < p2 else (1 if p1 > p2 else 0)

    registry.compare_versions.side_effect = _cmp
    return registry


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSolveTransitiveEmpty:
    def test_empty_records_returns_empty_dict(self) -> None:
        registry = _make_registry({})
        result = solve_transitive([], registry, {})
        assert result == {}
        registry.package_versions.assert_not_called()


class TestSolveTransitiveUnflagged:
    def test_no_cve_and_age_over_threshold_not_solved(self) -> None:
        """A package with no CVEs and age well above threshold should be skipped."""
        records = [_rec("requests", "2.28.0", age_days=30)]
        registry = _make_registry({"requests": [_pv("2.32.0")]})
        result = solve_transitive(records, registry, {})
        assert result == {}
        registry.package_versions.assert_not_called()


class TestSolveTransitiveCVE:
    def test_cve_flags_package_and_solver_picks_safe_version(self) -> None:
        """Installed version has a CVE → solver must recommend a non-affected version."""
        records = [_rec("vuln-pkg", "1.0.0", cve_affected=["1.0.0"], age_days=100)]
        registry = _make_registry(
            {
                "vuln-pkg": [
                    _pv("1.0.0", published="2023-06-01T00:00:00Z"),
                    _pv("2.0.0", published="2024-01-01T00:00:00Z"),
                ]
            }
        )
        result = solve_transitive(records, registry, {})
        assert result.get("vuln-pkg") == "2.0.0"

    def test_all_candidates_cve_returns_empty(self) -> None:
        """When every candidate version is CVE-affected, solver returns ConflictSet → {}."""
        records = [_rec("bad-pkg", "1.0.0", cve_affected=["1.0.0", "2.0.0"], age_days=100)]
        registry = _make_registry(
            {
                "bad-pkg": [
                    _pv("1.0.0", published="2023-06-01T00:00:00Z"),
                    _pv("2.0.0", published="2024-01-01T00:00:00Z"),
                ]
            }
        )
        result = solve_transitive(records, registry, {})
        assert result == {}


class TestSolveTransitiveVeryFresh:
    def test_very_fresh_installed_flags_package(self) -> None:
        """A package installed very recently (age < 7 days) is flagged even without CVEs."""
        records = [_rec("new-pkg", "2.0.0", age_days=2)]
        registry = _make_registry(
            {
                "new-pkg": [
                    _pv("1.0.0", published="2023-01-01T00:00:00Z"),  # old, safe
                    _pv("2.0.0", published="2026-04-28T00:00:00Z"),  # very fresh
                ]
            }
        )
        # Solver should recommend 1.0.0 because 2.0.0 has L6 penalty and 1.0.0 has none
        result = solve_transitive(records, registry, {})
        # Package was flagged (age < 7) so solver runs — result should contain a recommendation
        assert "new-pkg" in result

    def test_very_fresh_solver_prefers_older_stable_version(self) -> None:
        """Solver avoids a very-fresh candidate in favour of a stable older one."""
        records = [_rec("new-pkg", "2.0.0", age_days=3)]
        registry = _make_registry(
            {
                "new-pkg": [
                    # age=200 → L3 weight=99_800; no L6 penalty
                    _pv("1.0.0", published="2025-10-13T00:00:00Z"),
                    # age=3 → L3 weight=99_997; L6 penalty=1_000_000
                    _pv("2.0.0", published="2026-04-30T00:00:00Z"),
                ]
            }
        )
        result = solve_transitive(records, registry, {})
        assert result.get("new-pkg") == "1.0.0"


class TestSolveTransitiveDeduplication:
    def test_duplicate_package_names_solved_once(self) -> None:
        """Two records for the same package (from different dep paths) are deduplicated."""
        rec1 = _rec("shared", "1.0.0", cve_affected=["1.0.0"], age_days=100)
        rec2 = _rec("shared", "1.0.0", cve_affected=["1.0.0"], age_days=100)
        registry = _make_registry(
            {
                "shared": [
                    _pv("1.0.0", published="2023-06-01T00:00:00Z"),
                    _pv("2.0.0", published="2024-01-01T00:00:00Z"),
                ]
            }
        )
        result = solve_transitive([rec1, rec2], registry, {})
        # Only one call per unique package name
        assert registry.package_versions.call_count == 1
        assert result.get("shared") == "2.0.0"
