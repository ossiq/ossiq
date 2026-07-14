"""
Tests for the pure pipeline helpers in service/project.py and service/common/package_versions.py.

All functions here are data-in / data-out — zero network mocks needed.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock

from packaging.version import Version

from ossiq.domain.common import ConstraintType, CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.package import Package
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion, VersionsDifference
from ossiq.service.common.package_versions import filter_versions_between
from ossiq.service.project import (
    DependencyDescriptor,
    PrefetchedData,
    ScanRecord,
    apply_conflicts,
    apply_recommendations,
    build_records,
    clamp_recommendations,
)
from ossiq.solver.dependencies_solver import (
    EMPTY_OUTPUT,
    ConstraintConflict,
    SolverOutput,
)

_CONSTRAINT = ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml")
_DIFF = VersionsDifference("1.0.0", "2.0.0", 2, diff_name="minor")


def make_dep(name: str, version: str = "1.0.0", alias: str | None = None) -> DependencyDescriptor:
    return DependencyDescriptor(
        name=alias or name,
        canonical_name=name,
        version=version,
        is_optional=False,
        dependency_path=None,
        version_constraint=None,
        constraint_info=_CONSTRAINT,
    )


def make_package(name: str, latest: str = "2.0.0") -> Package:
    return Package(
        registry=ProjectPackagesRegistry.PYPI,
        name=name,
        latest_version=latest,
        next_version=None,
        repo_url=None,
        author=None,
        homepage_url=None,
        description=None,
        package_url=f"https://pypi.org/project/{name}/",
    )


def make_pv(version: str) -> PackageVersion:
    return PackageVersion(
        version=version,
        license="MIT",
        package_url="https://pypi.org/...",
        declared_dependencies={},
        published_date_iso="2024-01-01T00:00:00",
    )


def make_version_rules() -> MagicMock:
    rules = MagicMock()
    rules.package_registry = ProjectPackagesRegistry.PYPI
    rules.difference_versions.return_value = _DIFF
    return rules


def make_prefetched(packages: dict[str, Package], pairs: list[tuple[str, str]]) -> PrefetchedData:
    return PrefetchedData(
        packages_info=packages,
        cve_map={},
        versions_since_map={(name, ver): [make_pv(ver)] for name, ver in pairs},
        repositories_info={},
    )


def make_record(name: str, installed: str = "1.0.0") -> ScanRecord:
    return ScanRecord(
        package_name=name,
        dependency_name=name,
        is_optional_dependency=False,
        installed_version=installed,
        latest_version="2.0.0",
        versions_diff_index=_DIFF,
        time_lag_days=None,
        releases_lag=0,
        cve=[],
        constraint_info=_CONSTRAINT,
    )


# ============================================================================
# build_records
# ============================================================================


class TestBuildRecords:
    def test_empty_descriptors_returns_empty_list(self):
        records = build_records([], make_version_rules(), make_prefetched({}, []))
        assert records == []

    def test_returns_one_record_per_descriptor(self):
        pkg = make_package("requests")
        records = build_records(
            [make_dep("requests")],
            make_version_rules(),
            make_prefetched({"requests": pkg}, [("requests", "1.0.0")]),
        )
        assert len(records) == 1

    def test_package_name_is_canonical_dependency_name_is_alias(self):
        pkg = make_package("requests")
        dep = make_dep("requests", alias="requests-alias")
        records = build_records(
            [dep],
            make_version_rules(),
            make_prefetched({"requests": pkg}, [("requests", "1.0.0")]),
        )
        assert records[0].package_name == "requests"
        assert records[0].dependency_name == "requests-alias"

    def test_installed_version_matches_descriptor(self):
        pkg = make_package("django")
        records = build_records(
            [make_dep("django", version="4.2.0")],
            make_version_rules(),
            make_prefetched({"django": pkg}, [("django", "4.2.0")]),
        )
        assert records[0].installed_version == "4.2.0"

    def test_cves_threaded_from_prefetched_map(self):
        pkg = make_package("vuln-pkg")
        cve = CVE(
            id="CVE-2024-9999",
            cve_ids=("CVE-2024-9999",),
            source=CveDatabase.OSV,
            package_name="vuln-pkg",
            package_registry=ProjectPackagesRegistry.PYPI,
            summary="Test",
            severity=Severity.HIGH,
            affected_versions=("1.0.0",),
            published="2024-01-01",
            link="https://osv.dev/CVE-2024-9999",
        )
        prefetched = PrefetchedData(
            packages_info={"vuln-pkg": pkg},
            cve_map={("vuln-pkg", "1.0.0"): {cve}},
            versions_since_map={("vuln-pkg", "1.0.0"): [make_pv("1.0.0")]},
            repositories_info={},
        )
        records = build_records([make_dep("vuln-pkg")], make_version_rules(), prefetched)
        assert len(records[0].cve) == 1
        assert records[0].cve[0].id == "CVE-2024-9999"

    def test_multiple_descriptors_produces_matching_records(self):
        packages = {"a": make_package("a"), "b": make_package("b")}
        pairs = [("a", "1.0.0"), ("b", "1.0.0")]
        records = build_records(
            [make_dep("a"), make_dep("b")],
            make_version_rules(),
            make_prefetched(packages, pairs),
        )
        assert [r.package_name for r in records] == ["a", "b"]


# ============================================================================
# apply_conflicts
# ============================================================================


class TestApplyConflicts:
    def test_no_conflicts_leaves_records_unchanged(self):
        record = make_record("requests")
        apply_conflicts(EMPTY_OUTPUT, [record])
        assert record.constraint_conflict == []

    def test_conflict_written_to_matching_record(self):
        record = make_record("django")
        conflict = ConstraintConflict(package_name="django", conflicting_constraints=[">=3.0", "<2.0"])
        output = SolverOutput(recommendations={}, reasons={}, conflicts=[conflict])

        apply_conflicts(output, [record])

        assert record.constraint_conflict == [">=3.0", "<2.0"]

    def test_unrelated_package_not_affected(self):
        django = make_record("django")
        requests = make_record("requests")
        conflict = ConstraintConflict(package_name="django", conflicting_constraints=[">=3.0", "<2.0"])
        output = SolverOutput(recommendations={}, reasons={}, conflicts=[conflict])

        apply_conflicts(output, [django, requests])

        assert requests.constraint_conflict == []

    def test_empty_records_list_is_safe(self):
        conflict = ConstraintConflict(package_name="x", conflicting_constraints=[">=1"])
        output = SolverOutput(recommendations={}, reasons={}, conflicts=[conflict])
        apply_conflicts(output, [])


# ============================================================================
# apply_recommendations
# ============================================================================


class TestApplyRecommendations:
    def test_recommendation_written_to_matching_record(self):
        record = make_record("requests", installed="1.0.0")
        output = SolverOutput(recommendations={"requests": "2.0.0"}, reasons={})

        apply_recommendations([record], output)

        assert record.recommended_version == "2.0.0"

    def test_no_recommendation_leaves_field_none(self):
        record = make_record("requests")
        apply_recommendations([record], EMPTY_OUTPUT)
        assert record.recommended_version is None

    def test_skip_current_suppresses_same_version(self):
        record = make_record("requests", installed="2.0.0")
        output = SolverOutput(recommendations={"requests": "2.0.0"}, reasons={})

        apply_recommendations([record], output, skip_current=True)

        assert record.recommended_version is None

    def test_skip_current_false_writes_same_version(self):
        record = make_record("requests", installed="2.0.0")
        output = SolverOutput(recommendations={"requests": "2.0.0"}, reasons={})

        apply_recommendations([record], output, skip_current=False)

        assert record.recommended_version == "2.0.0"

    def test_unrelated_package_not_written(self):
        django = make_record("django")
        output = SolverOutput(recommendations={"requests": "2.0.0"}, reasons={})

        apply_recommendations([django], output)

        assert django.recommended_version is None


# ============================================================================
# clamp_recommendations
# ============================================================================

FIXED_NOW = datetime(2024, 6, 1, tzinfo=UTC)
PUBLISHED_OLD = "2024-01-01T00:00:00Z"
PUBLISHED_FRESH = "2024-05-30T00:00:00Z"


def make_npm_registry(versions_by_name: dict[str, list[PackageVersion]]) -> MagicMock:
    registry = MagicMock()
    registry.package_registry = ProjectPackagesRegistry.NPM
    registry.package_versions.side_effect = lambda name: versions_by_name.get(name, [])

    def compare(v1: str, v2: str) -> int:
        p1, p2 = Version(v1), Version(v2)
        return -1 if p1 < p2 else (1 if p1 > p2 else 0)

    registry.compare_versions.side_effect = compare
    return registry


def make_dated_pv(version: str, published: str = PUBLISHED_OLD) -> PackageVersion:
    return PackageVersion(
        version=version,
        license="MIT",
        package_url="https://registry.npmjs.org/...",
        declared_dependencies={},
        published_date_iso=published,
    )


def make_clamp_record(
    name: str,
    installed: str,
    constraint: str | None,
    recommended: str | None,
    constraint_type: ConstraintType = ConstraintType.DECLARED,
) -> ScanRecord:
    record = make_record(name, installed=installed)
    record.version_constraint = constraint
    record.recommended_version = recommended
    record.recommended_version_reason = MagicMock()
    record.constraint_info = ConstraintSource(type=constraint_type, source_file="package.json")
    return record


class TestClampRecommendations:
    def clamp(self, records: list[ScanRecord], registry: MagicMock, **kwargs) -> None:
        clamp_recommendations(records, registry, allow_prerelease=False, now=FIXED_NOW, **kwargs)

    def test_alias_range_violation_clamped_to_newest_in_range(self):
        registry = make_npm_registry(
            {"uuid": [make_dated_pv("7.0.0"), make_dated_pv("7.0.3"), make_dated_pv("11.0.0"), make_dated_pv("14.0.1")]}
        )
        record = make_clamp_record("uuid", "7.0.0", "npm:uuid@^7.0.0", "14.0.1")

        self.clamp([record], registry)

        assert record.recommended_version == "7.0.3"
        assert record.recommended_version_reason is None

    def test_alias_pin_violation_clamped_to_pin(self):
        registry = make_npm_registry({"chalk": [make_dated_pv("4.1.2"), make_dated_pv("5.3.0")]})
        record = make_clamp_record("chalk", "4.1.2", "npm:chalk@4.1.2", "5.3.0", constraint_type=ConstraintType.PINNED)

        self.clamp([record], registry)

        assert record.recommended_version == "4.1.2"

    def test_in_range_recommendation_untouched_with_reason(self):
        registry = make_npm_registry({"ms": [make_dated_pv("0.7.3"), make_dated_pv("2.1.3")]})
        record = make_clamp_record("ms", "2.1.3", "npm:ms@*", "2.1.3")

        self.clamp([record], registry)

        assert record.recommended_version == "2.1.3"
        assert record.recommended_version_reason is not None

    def test_downgrade_within_wide_range_clamped_up(self):
        registry = make_npm_registry({"ms": [make_dated_pv("0.7.3"), make_dated_pv("2.1.3")]})
        record = make_clamp_record("ms", "2.1.3", "npm:ms@*", "0.7.3")

        self.clamp([record], registry)

        assert record.recommended_version == "2.1.3"

    def test_non_alias_reverse_contamination_clamped_up(self):
        registry = make_npm_registry(
            {"chalk": [make_dated_pv("4.1.2"), make_dated_pv("5.0.0"), make_dated_pv("5.3.0")]}
        )
        record = make_clamp_record("chalk", "5.0.0", ">4.1.2 <=5.3.0", "4.1.2")

        self.clamp([record], registry)

        assert record.recommended_version == "5.3.0"

    def test_rewrite_pinned_exempts_non_alias_pin(self):
        registry = make_npm_registry({"chalk": [make_dated_pv("4.1.2"), make_dated_pv("5.3.0")]})
        record = make_clamp_record("chalk", "4.1.2", "4.1.2", "5.3.0", constraint_type=ConstraintType.PINNED)

        self.clamp([record], registry, rewrite_pinned=True)

        assert record.recommended_version == "5.3.0"

    def test_rewrite_pinned_still_clamps_alias_pin(self):
        registry = make_npm_registry({"chalk": [make_dated_pv("4.1.2"), make_dated_pv("5.3.0")]})
        record = make_clamp_record("chalk", "4.1.2", "npm:chalk@4.1.2", "5.3.0", constraint_type=ConstraintType.PINNED)

        self.clamp([record], registry, rewrite_pinned=True)

        assert record.recommended_version == "4.1.2"

    def test_no_version_in_range_drops_recommendation(self):
        registry = make_npm_registry({"chalk": [make_dated_pv("4.1.2"), make_dated_pv("5.3.0")]})
        record = make_clamp_record("chalk", "4.1.2", "npm:chalk@99.0.0", "5.3.0")

        self.clamp([record], registry)

        assert record.recommended_version is None

    def test_no_recommendation_is_noop(self):
        registry = make_npm_registry({})
        record = make_clamp_record("chalk", "4.1.2", "npm:chalk@4.1.2", None)

        self.clamp([record], registry)

        assert record.recommended_version is None
        registry.package_versions.assert_not_called()

    def test_no_constraint_is_noop(self):
        registry = make_npm_registry({})
        record = make_clamp_record("chalk", "4.1.2", None, "5.3.0")

        self.clamp([record], registry)

        assert record.recommended_version == "5.3.0"
        registry.package_versions.assert_not_called()

    def test_cooldown_prefers_aged_in_range_version(self):
        registry = make_npm_registry(
            {"chalk": [make_dated_pv("5.0.0", PUBLISHED_OLD), make_dated_pv("5.3.0", PUBLISHED_FRESH)]}
        )
        record = make_clamp_record("chalk", "5.0.0", "npm:chalk@^5.0.0", "6.0.0")

        self.clamp([record], registry, cooldown_period=7)

        assert record.recommended_version == "5.0.0"

    def test_cooldown_falls_back_to_fresh_when_only_option(self):
        registry = make_npm_registry(
            {"chalk": [make_dated_pv("5.0.0", PUBLISHED_FRESH), make_dated_pv("5.3.0", PUBLISHED_FRESH)]}
        )
        record = make_clamp_record("chalk", "5.0.0", "npm:chalk@^5.0.0", "6.0.0")

        self.clamp([record], registry, cooldown_period=7)

        assert record.recommended_version == "5.3.0"


# ============================================================================
# filter_versions_between
# ============================================================================


def _cmp(a: str, b: str) -> int:
    """Simple lexicographic comparator for test version strings like '1.0', '2.0'."""
    if a == b:
        return 0
    return -1 if a < b else 1


class TestFilterVersionsBetween:
    def test_returns_versions_in_range_inclusive(self):
        versions = ["1.0", "1.5", "2.0", "2.5", "3.0"]
        result = list(filter_versions_between(versions, "1.5", "2.5", _cmp))
        assert result == ["1.5", "2.0", "2.5"]

    def test_same_installed_and_latest_yields_nothing(self):
        result = list(filter_versions_between(["1.0", "2.0"], "1.0", "1.0", _cmp))
        assert result == []

    def test_versions_outside_range_excluded(self):
        versions = ["0.5", "1.0", "1.5", "2.0", "3.0"]
        result = list(filter_versions_between(versions, "1.0", "2.0", _cmp))
        assert "0.5" not in result
        assert "3.0" not in result

    def test_empty_versions_list_yields_nothing(self):
        result = list(filter_versions_between([], "1.0", "2.0", _cmp))
        assert result == []
