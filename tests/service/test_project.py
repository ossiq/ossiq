"""
Tests for service/project.py — ScanRecord factory and version_constraint propagation.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from ossiq.domain.common import ConstraintType, CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.package import Package
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion, VersionsDifference
from ossiq.service.project import (
    DependencyDescriptor,
    ScanRecord,
    calculate_version_age_days,
    get_package_versions_since,
    scan_record,
    scan_sort_key,
)

# ============================================================================
# Module-level constants
# ============================================================================

_PRERELEASE_VERSION = "1.0.0b1"
_STABLE_VERSION = "1.0.0"

_prerelease_pv = PackageVersion(
    version=_PRERELEASE_VERSION,
    license="MIT",
    package_url="https://pypi.org/project/mylib/1.0.0b1/",
    declared_dependencies={},
    published_date_iso="2024-01-01T00:00:00",
    is_prerelease=True,
)
_stable_pv = PackageVersion(
    version=_STABLE_VERSION,
    license="MIT",
    package_url="https://pypi.org/project/mylib/1.0.0/",
    declared_dependencies={},
    published_date_iso="2024-06-01T00:00:00",
)

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_package_registry():
    """Mock registry for a stable requests package (2.31.0 installed, 2.32.0 latest)."""
    registry = MagicMock()
    registry.package_registry = ProjectPackagesRegistry.PYPI

    installed_pv = PackageVersion(
        version="2.31.0",
        license="Apache-2.0",
        package_url="https://pypi.org/project/requests/2.31.0/",
        declared_dependencies={},
        published_date_iso="2023-05-22T00:00:00",
    )
    latest_pv = PackageVersion(
        version="2.32.0",
        license="Apache-2.0",
        package_url="https://pypi.org/project/requests/2.32.0/",
        declared_dependencies={},
        published_date_iso="2024-05-29T00:00:00",
    )
    registry.package_versions.return_value = [installed_pv, latest_pv]
    registry.compare_versions.side_effect = lambda v1, v2: 0 if v1 == v2 else (-1 if v1 < v2 else 1)
    registry.difference_versions.return_value = VersionsDifference("2.31.0", "2.32.0", 3, diff_name="patch")
    return registry


@pytest.fixture
def mock_package():
    return Package(
        registry=ProjectPackagesRegistry.PYPI,
        name="requests",
        latest_version="2.32.0",
        next_version=None,
        repo_url=None,
        author=None,
        homepage_url=None,
        description=None,
        package_url="https://pypi.org/project/requests/",
    )


@pytest.fixture
def mock_versions(mock_package_registry):
    return mock_package_registry.package_versions.return_value


@pytest.fixture
def prerelease_registry():
    registry = MagicMock()
    registry.package_registry = ProjectPackagesRegistry.PYPI
    registry.package_versions.return_value = [_prerelease_pv, _stable_pv]
    registry.compare_versions.side_effect = lambda v1, v2: 0 if v1 == v2 else (-1 if v1 < v2 else 1)
    registry.difference_versions.return_value = VersionsDifference(
        _PRERELEASE_VERSION, _STABLE_VERSION, 3, diff_name="minor"
    )
    return registry


@pytest.fixture
def prerelease_package():
    return Package(
        registry=ProjectPackagesRegistry.PYPI,
        name="mylib",
        latest_version=_STABLE_VERSION,
        next_version=None,
        repo_url=None,
        author=None,
        homepage_url=None,
        description=None,
        package_url="https://pypi.org/project/mylib/",
    )


# ============================================================================
# Tests: get_package_versions_since
# ============================================================================


class TestGetPackageVersionsSince:
    """Test prerelease filtering in get_package_versions_since."""

    def test_retains_installed_prerelease_when_filtering(self, prerelease_registry):
        """Installed prerelease is kept even when allow_prerelease=False."""
        result = get_package_versions_since(prerelease_registry, "mylib", _PRERELEASE_VERSION, allow_prerelease=False)

        assert any(pv.version == _PRERELEASE_VERSION for pv in result)

    def test_non_installed_prereleases_are_filtered(self, prerelease_registry):
        """Prerelease versions other than the installed one are excluded when allow_prerelease=False."""
        result = get_package_versions_since(prerelease_registry, "mylib", _STABLE_VERSION, allow_prerelease=False)

        assert not any(pv.version == _PRERELEASE_VERSION for pv in result)


# ============================================================================
# Tests: scan_record — stable package
# ============================================================================


class TestScanRecord:
    """Test scan_record() field mapping for a stable installed version."""

    def _make_record(self, registry, package, versions, **kwargs):
        return scan_record(
            version_rules=registry,
            package_info=package,
            package_name=kwargs.pop("package_name", "requests"),
            canonical_name=kwargs.pop("canonical_name", "requests"),
            package_version=kwargs.pop("package_version", "2.31.0"),
            is_optional_dependency=kwargs.pop("is_optional_dependency", False),
            prefetched_cves=kwargs.pop("prefetched_cves", set()),
            prefetched_versions_since=versions,
            constraint_info=kwargs.pop(
                "constraint_info",
                ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
            ),
            **kwargs,
        )

    @pytest.mark.parametrize(
        "constraint",
        [
            None,
            ">=2.31.0",
            ">=2.31.0,<3.0.0",
            "~=2.31.0",
            "^2.31.0",
            "~2.31.0",
            "==2.31.0",
        ],
    )
    def test_version_constraint_stored_as_given(self, mock_package_registry, mock_package, mock_versions, constraint):
        """version_constraint is stored verbatim (or None when absent)."""
        record = self._make_record(mock_package_registry, mock_package, mock_versions, version_constraint=constraint)

        assert record.version_constraint == constraint

    def test_purl_uses_canonical_name_and_registry(self, mock_package_registry, mock_package, mock_versions):
        """PURL is built from the canonical name, not any alias, and reflects the correct registry."""
        record = self._make_record(
            mock_package_registry,
            mock_package,
            mock_versions,
            package_name="requests-alias",
            canonical_name="requests",
        )

        assert record.purl == "pkg:pypi/requests@2.31.0"
        assert "requests-alias" not in record.purl


# ============================================================================
# Tests: scan_record — prerelease installed version
# ============================================================================


class TestScanRecordPrerelease:
    """Test scan_record() correctness when the installed version is a prerelease."""

    def _make_record(self, registry, package, versions_since, cves=None):
        return scan_record(
            version_rules=registry,
            package_info=package,
            package_name="mylib",
            canonical_name="mylib",
            package_version=_PRERELEASE_VERSION,
            is_optional_dependency=False,
            prefetched_cves=cves or set(),
            prefetched_versions_since=versions_since,
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
        )

    def test_is_installed_prerelease_flag(self, prerelease_registry, prerelease_package):
        record = self._make_record(prerelease_registry, prerelease_package, [_prerelease_pv, _stable_pv])

        assert record.is_installed_prerelease is True

    def test_releases_lag_is_zero_when_only_installed_version_present(self, prerelease_registry, prerelease_package):
        """releases_lag must be 0 (not -1) when the only version in the list is the installed one."""
        record = self._make_record(prerelease_registry, prerelease_package, [_prerelease_pv])

        assert record.releases_lag == 0

    def test_cves_are_included_for_prerelease_installed_version(self, prerelease_registry, prerelease_package):
        """CVEs are not silenced when the installed version is a prerelease."""
        cve = CVE(
            id="CVE-2024-1234",
            cve_ids=("CVE-2024-1234",),
            source=CveDatabase.OSV,
            package_name="mylib",
            package_registry=ProjectPackagesRegistry.PYPI,
            summary="A vulnerability",
            severity=Severity.HIGH,
            affected_versions=(_PRERELEASE_VERSION,),
            published="2024-01-01",
            link="https://osv.dev/CVE-2024-1234",
        )
        record = self._make_record(prerelease_registry, prerelease_package, [_prerelease_pv], cves={cve})

        assert len(record.cve) == 1
        assert record.cve[0].id == "CVE-2024-1234"


# ============================================================================
# Tests: ignore_packages filtering (DependencyDescriptor lists)
# ============================================================================

_CONSTRAINT_SOURCE = ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml")


def _make_dep(canonical_name: str, is_optional: bool = False) -> DependencyDescriptor:
    return DependencyDescriptor(
        name=canonical_name,
        canonical_name=canonical_name,
        version="1.0.0",
        is_optional=is_optional,
        dependency_path=None,
        version_constraint=None,
        constraint_info=_CONSTRAINT_SOURCE,
    )


class TestIgnorePackagesFiltering:
    """Verify that ignore_set correctly filters DependencyDescriptor lists (mirrors scan() logic)."""

    def test_ignored_package_removed_from_prod_deps(self):
        deps = [_make_dep("sphinx"), _make_dep("requests")]
        ignore_set = frozenset(["sphinx"])
        result = [d for d in deps if d.canonical_name not in ignore_set]
        assert [d.canonical_name for d in result] == ["requests"]

    def test_ignored_package_removed_from_opt_deps(self):
        deps = [_make_dep("pytest", is_optional=True), _make_dep("mypy", is_optional=True)]
        ignore_set = frozenset(["mypy"])
        result = [d for d in deps if d.canonical_name not in ignore_set]
        assert [d.canonical_name for d in result] == ["pytest"]

    def test_empty_ignore_set_leaves_deps_unchanged(self):
        deps = [_make_dep("sphinx"), _make_dep("requests")]
        ignore_set: frozenset[str] = frozenset()
        result = [d for d in deps if d.canonical_name not in ignore_set]
        assert result == deps

    def test_all_packages_ignored_yields_empty_list(self):
        deps = [_make_dep("sphinx"), _make_dep("requests")]
        ignore_set = frozenset(["sphinx", "requests"])
        result = [d for d in deps if d.canonical_name not in ignore_set]
        assert result == []

    def test_unknown_ignore_name_has_no_effect(self):
        deps = [_make_dep("sphinx")]
        ignore_set = frozenset(["nonexistent"])
        result = [d for d in deps if d.canonical_name not in ignore_set]
        assert result == deps


# ============================================================================
# TestCalculateVersionAgeDays
# ============================================================================


class TestCalculateVersionAgeDays:
    def _pv(self, version: str, published: str | None) -> PackageVersion:
        return PackageVersion(
            version=version,
            license=None,
            package_url=f"https://example.com/{version}",
            declared_dependencies={},
            published_date_iso=published,
        )

    def test_returns_days_since_publish_with_explicit_now(self) -> None:
        versions = [self._pv("1.0.0", "2024-01-01T00:00:00Z")]
        now = datetime(2024, 1, 11, tzinfo=UTC)
        assert calculate_version_age_days(versions, "1.0.0", now=now) == 10

    def test_returns_none_when_version_not_found(self) -> None:
        versions = [self._pv("1.0.0", "2024-01-01T00:00:00Z")]
        now = datetime(2024, 1, 11, tzinfo=UTC)
        assert calculate_version_age_days(versions, "2.0.0", now=now) is None

    def test_returns_none_when_no_published_date(self) -> None:
        versions = [self._pv("1.0.0", None)]
        now = datetime(2024, 1, 11, tzinfo=UTC)
        assert calculate_version_age_days(versions, "1.0.0", now=now) is None

    def test_without_now_returns_non_none_int(self) -> None:
        versions = [self._pv("1.0.0", "2020-01-01T00:00:00Z")]
        result = calculate_version_age_days(versions, "1.0.0")
        assert isinstance(result, int)
        assert result > 0


class TestScanSortKey:
    """Regression: sorting must not crash when time_lag_days is None (cutoff-date scans)."""

    def make_record(self, name: str, time_lag_days: int | None) -> ScanRecord:
        return ScanRecord(
            package_name=name,
            dependency_name=name,
            is_optional_dependency=False,
            installed_version="1.0.0",
            latest_version=None,
            versions_diff_index=VersionsDifference("1.0.0", "1.0.0", 0, diff_name="LATEST"),
            time_lag_days=time_lag_days,
            releases_lag=None,
            cve=[],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
        )

    def test_mixed_none_and_int_lag_sortable(self) -> None:
        records = [self.make_record("a", None), self.make_record("b", 10), self.make_record("c", None)]
        ordered = sorted(records, key=scan_sort_key, reverse=True)
        assert [r.package_name for r in ordered] == ["b", "c", "a"]

    def test_unknown_lag_ranks_below_known_lag(self) -> None:
        unknown = self.make_record("pkg", None)
        known = self.make_record("pkg", 0)
        assert scan_sort_key(unknown) < scan_sort_key(known)
