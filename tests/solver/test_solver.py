"""Unit tests for dependencies_solver.solve_direct."""

from __future__ import annotations

from unittest.mock import MagicMock

from packaging.version import Version as PV

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion
from ossiq.solver.dependencies_solver import solve_direct

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
        all_constraints: list[str] | None = None,
    ) -> None:
        self.canonical_name = canonical_name
        self.version = version
        self.version_constraint = constraint
        self.constraint_info = ConstraintSource(type=constraint_type, source_file="pyproject.toml")
        self.all_constraints = all_constraints or []


def _make_registry(
    versions_by_name: dict[str, list[PackageVersion]],
    requires: dict[tuple[str, str], dict[str, str]] | None = None,
) -> MagicMock:
    from ossiq.domain.common import ProjectPackagesRegistry

    registry = MagicMock(spec=AbstractPackageRegistryApi)
    registry.package_registry = ProjectPackagesRegistry.PYPI
    registry.package_versions.side_effect = lambda name: versions_by_name.get(name, [])
    registry.package_version_requires.side_effect = lambda name, version: (requires or {}).get((name, version), {})

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
        assert result.recommendations == {}
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
        assert result.recommendations.get("requests") == "2.32.0"
        assert result.recommendations.get("flask") == "3.1.0"

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
        assert isinstance(result.recommendations, dict)
        assert all(isinstance(k, str) and isinstance(v, str) for k, v in result.recommendations.items())


class TestSolveDirectNoEligibleCandidates:
    def test_all_candidates_excluded_returns_empty_dict(self) -> None:
        """When the constraint eliminates all candidates, return {} without raising."""
        deps = [_FakeDep("requests", "1.0.0", constraint=">=5.0.0")]
        registry = _make_registry({"requests": [_pv("1.0.0"), _pv("2.0.0")]})
        result = solve_direct(deps, registry, {})
        assert result.recommendations == {}


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
        assert result.recommendations.get("requests") == "2.28.0"

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
        assert "requests" in result.recommendations
        assert result.recommendations["requests"] == "3.0.0a1"


class TestSolveDirectPostSolveValidator:
    """Phase 4c: post_solve_validator triggers fallback when the top pick fails."""

    def test_validator_accepted_leaves_output_unchanged(self) -> None:
        deps = [_FakeDep("requests", "2.28.0")]
        registry = _make_registry(
            {
                "requests": [
                    _pv("2.28.0", published="2023-01-01T00:00:00Z"),
                    _pv("2.32.0", published="2024-06-01T00:00:00Z"),
                ]
            }
        )
        result = solve_direct(deps, registry, {}, post_solve_validator=lambda _pkg, _ver: True)
        assert result.recommendations.get("requests") == "2.32.0"

    def test_validator_fallback_to_second_candidate(self) -> None:
        """When validator rejects the top pick, the next eligible candidate is used."""
        deps = [_FakeDep("requests", "2.28.0")]
        registry = _make_registry(
            {
                "requests": [
                    _pv("2.28.0", published="2022-01-01T00:00:00Z"),
                    _pv("2.31.0", published="2023-06-01T00:00:00Z"),
                    _pv("2.32.0", published="2024-06-01T00:00:00Z"),
                ]
            }
        )
        # Reject 2.32.0 (top pick), accept 2.31.0.
        result = solve_direct(
            deps,
            registry,
            {},
            post_solve_validator=lambda _pkg, ver: ver != "2.32.0",
        )
        assert result.recommendations.get("requests") == "2.31.0"
        assert result.reasons.get("requests") is not None

    def test_validator_drops_package_when_no_fallback(self) -> None:
        """When all candidates are rejected, the package is dropped from recommendations."""
        deps = [_FakeDep("requests", "2.28.0")]
        registry = _make_registry(
            {
                "requests": [
                    _pv("2.28.0", published="2022-01-01T00:00:00Z"),
                    _pv("2.32.0", published="2024-06-01T00:00:00Z"),
                ]
            }
        )
        result = solve_direct(deps, registry, {}, post_solve_validator=lambda _pkg, _ver: False)
        assert "requests" not in result.recommendations

    def test_validator_independent_per_package(self) -> None:
        """Validator rejection of one package does not affect another."""
        deps = [
            _FakeDep("requests", "2.28.0"),
            _FakeDep("flask", "2.0.0"),
        ]
        registry = _make_registry(
            {
                "requests": [
                    _pv("2.28.0", published="2022-01-01T00:00:00Z"),
                    _pv("2.32.0", published="2024-06-01T00:00:00Z"),
                ],
                "flask": [
                    _pv("2.0.0", published="2022-01-01T00:00:00Z"),
                    _pv("3.1.0", published="2024-06-01T00:00:00Z"),
                ],
            }
        )
        # Reject all requests versions; accept all flask versions.
        result = solve_direct(
            deps,
            registry,
            {},
            post_solve_validator=lambda pkg, _ver: pkg != "requests",
        )
        assert "requests" not in result.recommendations
        assert result.recommendations.get("flask") == "3.1.0"


class TestSolveDirectRequiresConsistency:
    """Joint requires-consistency: a pick conflicting with another pinned version is demoted."""

    def test_conflicting_requirement_demotes_to_compatible_candidate(self) -> None:
        """Regression: scikit-learn-style pick requiring numpy>=2.0.0 while numpy is held <2.0.0."""
        deps = [
            _FakeDep("scikit-learn", "1.8.0", constraint="<2.0.0"),
            _FakeDep("numpy", "1.26.4", constraint=">=1.20.0,!=1.24.2,<2.0.0"),
        ]
        registry = _make_registry(
            {
                "scikit-learn": [
                    _pv("1.8.0", published="2023-01-01T00:00:00Z"),
                    _pv("1.9.0", published="2024-06-01T00:00:00Z"),
                ],
                "numpy": [_pv("1.26.4", published="2023-01-01T00:00:00Z")],
            },
            requires={
                ("scikit-learn", "1.9.0"): {"numpy": ">=2.0.0"},
                ("scikit-learn", "1.8.0"): {"numpy": ">=1.19.0"},
            },
        )
        result = solve_direct(deps, registry, {})
        assert result.recommendations.get("scikit-learn") == "1.8.0"
        assert result.recommendations.get("numpy") == "1.26.4"

    def test_requirement_satisfied_by_co_recommendation_keeps_pick(self) -> None:
        deps = [_FakeDep("a", "1.0.0"), _FakeDep("b", "2.0.0")]
        registry = _make_registry(
            {
                "a": [_pv("1.0.0"), _pv("2.0.0")],
                "b": [_pv("2.0.0"), _pv("2.5.0")],
            },
            requires={("a", "2.0.0"): {"b": ">=2.0"}},
        )
        result = solve_direct(deps, registry, {})
        assert result.recommendations.get("a") == "2.0.0"
        assert result.recommendations.get("b") == "2.5.0"

    def test_requirement_on_package_outside_solution_is_ignored(self) -> None:
        deps = [_FakeDep("a", "1.0.0")]
        registry = _make_registry(
            {"a": [_pv("1.0.0"), _pv("2.0.0")]},
            requires={("a", "2.0.0"): {"unrelated": ">=99.0"}},
        )
        result = solve_direct(deps, registry, {})
        assert result.recommendations.get("a") == "2.0.0"

    def test_empty_requires_and_empty_spec_keep_pick(self) -> None:
        deps = [_FakeDep("a", "1.0.0"), _FakeDep("b", "1.0.0")]
        registry = _make_registry(
            {
                "a": [_pv("1.0.0"), _pv("2.0.0")],
                "b": [_pv("1.0.0")],
            },
            requires={("a", "2.0.0"): {"b": ""}},
        )
        result = solve_direct(deps, registry, {})
        assert result.recommendations.get("a") == "2.0.0"

    def test_demote_walk_picks_newest_requires_compatible_candidate(self) -> None:
        deps = [_FakeDep("a", "1.0.0"), _FakeDep("b", "1.0.0")]
        registry = _make_registry(
            {
                "a": [_pv("1.0.0"), _pv("2.5.0"), _pv("3.0.0")],
                "b": [_pv("1.0.0")],
            },
            requires={
                ("a", "3.0.0"): {"b": ">=9.0"},
                ("a", "2.5.0"): {"b": ">=1.0"},
            },
        )
        result = solve_direct(deps, registry, {})
        assert result.recommendations.get("a") == "2.5.0"

    def test_combined_with_post_solve_validator(self) -> None:
        """Both the requires check and the caller's validator must accept a candidate."""
        deps = [_FakeDep("a", "1.0.0"), _FakeDep("b", "1.0.0")]
        registry = _make_registry(
            {
                "a": [_pv("1.0.0"), _pv("2.0.0"), _pv("3.0.0")],
                "b": [_pv("1.0.0")],
            },
            requires={("a", "2.0.0"): {"b": ">=9.0"}},
        )
        # Validator rejects the top pick 3.0.0; requires check rejects 2.0.0 -> 1.0.0 remains.
        result = solve_direct(
            deps,
            registry,
            {},
            post_solve_validator=lambda _pkg, ver: ver != "3.0.0",
        )
        assert result.recommendations.get("a") == "1.0.0"

    def test_stale_recommendation_invalidated_by_fixpoint(self) -> None:
        """A pick validated against a co-recommendation that later gets demoted must be re-checked."""
        deps = [
            _FakeDep("a", "1.0.0"),
            _FakeDep("b", "1.0.0"),
            _FakeDep("c", "1.0.0", constraint="<2.0.0"),
        ]
        registry = _make_registry(
            {
                "a": [_pv("1.0.0"), _pv("2.0.0")],
                "b": [_pv("1.0.0"), _pv("2.0.0")],
                "c": [_pv("1.0.0")],
            },
            requires={
                # b@2.0.0 conflicts with c (held at 1.0.0) and gets demoted to 1.0.0;
                # a@2.0.0 was valid against b's original 2.0.0 pick and must follow it down.
                ("b", "2.0.0"): {"c": ">=2.0"},
                ("a", "2.0.0"): {"b": ">=2.0"},
            },
        )
        result = solve_direct(deps, registry, {})
        assert result.recommendations.get("b") == "1.0.0"
        assert result.recommendations.get("a") == "1.0.0"
        assert result.recommendations.get("c") == "1.0.0"
