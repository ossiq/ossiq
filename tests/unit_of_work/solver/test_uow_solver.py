"""Unit tests for uow_dependencies_solver.solve_direct."""

from __future__ import annotations

from unittest.mock import MagicMock

from packaging.version import Version as PV

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion
from ossiq.unit_of_work.solver.uow_dependencies_solver import solve_direct

# ---------------------------------------------------------------------------
# Helpers (mirror test_universe.py style)
# ---------------------------------------------------------------------------


def _pv(
    version: str,
    *,
    published: str | None = "2024-01-01T00:00:00Z",
    yanked: bool = False,
    unpublished: bool = False,
    prerelease: bool = False,
    deprecated: bool = False,
    runtime_requirements: dict[str, str] | None = None,
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
        runtime_requirements=runtime_requirements,
    )


class _FakeDep:
    """Minimal object satisfying the _DepLike Protocol."""

    def __init__(
        self,
        canonical_name: str,
        version: str,
        *,
        constraint: str | None = None,
        constraint_type: ConstraintType = ConstraintType.DECLARED,
    ) -> None:
        self.canonical_name = canonical_name
        self.version = version
        self.version_constraint = constraint
        self.constraint_info = ConstraintSource(type=constraint_type, source_file="pyproject.toml")


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


class TestSolveDirectEmptyDeps:
    def test_empty_deps_returns_empty_dict(self) -> None:
        registry = _make_registry({})
        result = solve_direct([], registry, {})
        assert result == {}
        registry.package_versions.assert_not_called()


class TestSolveDirectHappyPath:
    def test_returns_recommended_version_for_each_package(self) -> None:
        """Solver selects the freshest eligible version per package."""
        deps = [
            _FakeDep("requests", "2.28.0", constraint=">=2.0.0"),
            _FakeDep("flask", "2.0.0", constraint=">=2.0.0"),
        ]
        registry = _make_registry(
            {
                "requests": [
                    _pv("2.28.0", published="2023-01-01T00:00:00Z"),
                    _pv("2.32.0", published="2024-06-01T00:00:00Z"),
                ],
                "flask": [
                    _pv("2.0.0", published="2023-01-01T00:00:00Z"),
                    _pv("3.1.0", published="2024-06-01T00:00:00Z"),
                ],
            }
        )
        result = solve_direct(deps, registry, {})
        assert result.get("requests") == "2.32.0"
        assert result.get("flask") == "3.1.0"

    def test_result_is_dict_of_str_to_str(self) -> None:
        deps = [_FakeDep("requests", "2.28.0")]
        registry = _make_registry(
            {
                "requests": [
                    _pv("2.28.0", published="2023-01-01T00:00:00Z"),
                    _pv("2.32.0", published="2024-06-01T00:00:00Z"),
                ]
            }
        )
        result = solve_direct(deps, registry, {})
        assert isinstance(result, dict)
        assert all(isinstance(k, str) and isinstance(v, str) for k, v in result.items())


class TestSolveDirectNoEligibleCandidates:
    def test_all_candidates_excluded_returns_empty_dict(self) -> None:
        """When the constraint eliminates all candidates, return {} without raising."""
        deps = [_FakeDep("requests", "1.0.0", constraint=">=5.0.0")]
        registry = _make_registry({"requests": [_pv("1.0.0"), _pv("2.0.0")]})
        result = solve_direct(deps, registry, {})
        assert result == {}


class TestSolveDirectPrereleaseFiltering:
    def test_prerelease_excluded_when_flag_false(self) -> None:
        """Pre-release candidates must not be selected when allow_prerelease=False."""
        deps = [_FakeDep("requests", "2.28.0")]
        registry = _make_registry(
            {
                "requests": [
                    _pv("2.28.0", published="2023-01-01T00:00:00Z"),
                    _pv("3.0.0a1", published="2024-06-01T00:00:00Z", prerelease=True),
                ]
            }
        )
        result = solve_direct(deps, registry, {}, allow_prerelease=False)
        assert result.get("requests") == "2.28.0"

    def test_prerelease_included_when_flag_true(self) -> None:
        """Pre-release candidates are eligible when allow_prerelease=True."""
        deps = [_FakeDep("requests", "2.28.0")]
        registry = _make_registry(
            {
                "requests": [
                    _pv("2.28.0", published="2023-01-01T00:00:00Z"),
                    _pv("3.0.0a1", published="2024-06-01T00:00:00Z", prerelease=True),
                ]
            }
        )
        result = solve_direct(deps, registry, {}, allow_prerelease=True)
        assert "requests" in result
        assert result["requests"] == "3.0.0a1"
