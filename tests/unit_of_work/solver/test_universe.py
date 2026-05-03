from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

from packaging.version import Version as PV

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion
from ossiq.unit_of_work.solver.problem import CandidateVersion, PackageConstraint, SolverProblem
from ossiq.unit_of_work.solver.universe import SolvablePool

# ---------------------------------------------------------------------------
# Shared helpers
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


_FIXED_NOW = datetime(2024, 1, 31, 0, 0, 0, tzinfo=UTC)
_PUBLISH_30_DAYS_AGO = "2024-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# TestCandidateVersionFiltering
# ---------------------------------------------------------------------------


class TestCandidateVersionFiltering:
    def test_yanked_versions_excluded(self) -> None:
        registry = _make_registry({"pkg": [_pv("1.0.0", yanked=True), _pv("2.0.0")]})
        problem = SolvablePool.build([_FakeDep("pkg", "1.0.0")], registry, {})
        versions = [cv.version for cv in problem.candidates["pkg"]]
        assert versions == ["2.0.0"]

    def test_unpublished_versions_excluded(self) -> None:
        registry = _make_registry({"pkg": [_pv("1.0.0", unpublished=True), _pv("2.0.0")]})
        problem = SolvablePool.build([_FakeDep("pkg", "1.0.0")], registry, {})
        versions = [cv.version for cv in problem.candidates["pkg"]]
        assert versions == ["2.0.0"]

    def test_prerelease_excluded_by_default(self) -> None:
        registry = _make_registry({"pkg": [_pv("1.0.0"), _pv("2.0.0a1", prerelease=True)]})
        problem = SolvablePool.build([_FakeDep("pkg", "1.0.0")], registry, {}, allow_prerelease=False)
        assert all(not cv.is_prerelease for cv in problem.candidates["pkg"])
        assert len(problem.candidates["pkg"]) == 1

    def test_prerelease_included_when_flag_set(self) -> None:
        registry = _make_registry({"pkg": [_pv("1.0.0"), _pv("2.0.0a1", prerelease=True)]})
        problem = SolvablePool.build([_FakeDep("pkg", "1.0.0")], registry, {}, allow_prerelease=True)
        versions = [cv.version for cv in problem.candidates["pkg"]]
        assert "2.0.0a1" in versions

    def test_versions_sorted_descending(self) -> None:
        registry = _make_registry({"pkg": [_pv("1.0.0"), _pv("3.0.0"), _pv("2.0.0")]})
        problem = SolvablePool.build([_FakeDep("pkg", "1.0.0")], registry, {})
        versions = [cv.version for cv in problem.candidates["pkg"]]
        assert versions == ["3.0.0", "2.0.0", "1.0.0"]


# ---------------------------------------------------------------------------
# TestCandidateVersionAgeComputation
# ---------------------------------------------------------------------------


class TestCandidateVersionAgeComputation:
    def test_age_days_computed_from_published_date(self) -> None:
        registry = _make_registry({"pkg": [_pv("1.0.0", published=_PUBLISH_30_DAYS_AGO)]})
        problem = SolvablePool.build([_FakeDep("pkg", "1.0.0")], registry, {}, _now=_FIXED_NOW)
        assert problem.candidates["pkg"][0].age_days == 30

    def test_age_days_none_when_no_publish_date(self) -> None:
        registry = _make_registry({"pkg": [_pv("1.0.0", published=None)]})
        problem = SolvablePool.build([_FakeDep("pkg", "1.0.0")], registry, {}, _now=_FIXED_NOW)
        assert problem.candidates["pkg"][0].age_days is None


# ---------------------------------------------------------------------------
# TestSolvablePoolConstraintBuilding
# ---------------------------------------------------------------------------


class TestSolvablePoolConstraintBuilding:
    def test_single_descriptor_becomes_one_constraint(self) -> None:
        dep = _FakeDep("requests", "2.31.0", constraint=">=2.0.0", constraint_type=ConstraintType.DECLARED)
        registry = _make_registry({"requests": [_pv("2.31.0")]})
        problem = SolvablePool.build([dep], registry, {})
        assert len(problem.constraints) == 1
        c = problem.constraints[0]
        assert c.package_name == "requests"
        assert c.version_constraint == ">=2.0.0"
        assert c.constraint_type == ConstraintType.DECLARED
        assert c.installed_version == "2.31.0"

    def test_duplicate_canonical_names_deduplicated(self) -> None:
        deps = [
            _FakeDep("requests", "2.31.0", constraint_type=ConstraintType.DECLARED),
            _FakeDep("requests", "2.31.0", constraint_type=ConstraintType.PINNED),
        ]
        registry = _make_registry({"requests": [_pv("2.31.0")]})
        problem = SolvablePool.build(deps, registry, {})
        assert len(problem.constraints) == 1
        assert problem.constraints[0].constraint_type == ConstraintType.PINNED

    def test_constraint_fields_preserved(self) -> None:
        dep = _FakeDep("flask", "3.0.0", constraint=">=3.0.0,<4.0.0", constraint_type=ConstraintType.NARROWED)
        registry = _make_registry({"flask": [_pv("3.0.0")]})
        problem = SolvablePool.build([dep], registry, {})
        c = problem.constraints[0]
        assert c.version_constraint == ">=3.0.0,<4.0.0"
        assert c.installed_version == "3.0.0"
        assert c.constraint_type == ConstraintType.NARROWED


# ---------------------------------------------------------------------------
# TestSolverProblemFingerprint
# ---------------------------------------------------------------------------


def _make_problem(
    *,
    constraint_str: str = ">=1.0.0",
    candidate_version: str = "1.0.0",
    engine: dict[str, str] | None = None,
) -> SolverProblem:
    return SolverProblem(
        constraints=(
            PackageConstraint(
                package_name="pkg",
                version_constraint=constraint_str,
                constraint_type=ConstraintType.DECLARED,
                installed_version="1.0.0",
            ),
        ),
        candidates={
            "pkg": (
                CandidateVersion(
                    version=candidate_version,
                    age_days=30,
                    is_deprecated=False,
                    is_prerelease=False,
                    is_yanked=False,
                    runtime_requirements=None,
                ),
            )
        },
        engine_context=engine or {"python": "3.11"},
    )


class TestSolverProblemFingerprint:
    def test_fingerprint_is_deterministic(self) -> None:
        p1 = _make_problem()
        p2 = _make_problem()
        assert p1.fingerprint() == p2.fingerprint()

    def test_fingerprint_changes_on_different_constraint(self) -> None:
        p1 = _make_problem(constraint_str=">=1.0.0")
        p2 = _make_problem(constraint_str=">=2.0.0")
        assert p1.fingerprint() != p2.fingerprint()

    def test_fingerprint_changes_on_different_candidate(self) -> None:
        p1 = _make_problem(candidate_version="1.0.0")
        p2 = _make_problem(candidate_version="1.0.1")
        assert p1.fingerprint() != p2.fingerprint()

    def test_fingerprint_changes_on_different_engine_context(self) -> None:
        p1 = _make_problem(engine={"python": "3.11"})
        p2 = _make_problem(engine={"python": "3.12"})
        assert p1.fingerprint() != p2.fingerprint()
