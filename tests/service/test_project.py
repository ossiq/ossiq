"""
Tests for the service/project package — ScanRecord factory and version_constraint propagation.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from ossiq.domain.common import ConstraintType, CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.package import Package
from ossiq.domain.project import ConstraintSource, Dependency, PeerRequirement
from ossiq.domain.version import PackageVersion, VersionsDifference
from ossiq.messages import IGNORE_REASON_IGNORE_FLAG, IGNORE_REASON_NON_REGISTRY
from ossiq.service.project.models import DependencyDescriptor, ScanRecord
from ossiq.service.project.prefetch import build_ignored_packages, get_package_versions_since, partition_git_hosted
from ossiq.service.project.records import calculate_version_age_days, scan_record, scan_sort_key
from ossiq.service.project.scan import direct_descriptor

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


def _make_scan_record(name: str, cve: bool = False) -> ScanRecord:
    return ScanRecord(
        package_name=name,
        dependency_name=name,
        is_optional_dependency=False,
        installed_version="1.0.0",
        latest_version=None,
        versions_diff_index=VersionsDifference("1.0.0", "1.0.0", 0, diff_name="LATEST"),
        time_lag_days=None,
        releases_lag=None,
        cve=[MagicMock()] if cve else [],
        constraint_info=_CONSTRAINT_SOURCE,
    )


class TestIgnorePackagesFiltering:
    """Verify ignore_set excludes packages from solver input (mirrors scan() logic).

    Ignored packages stay in prod_deps/opt_deps/trans_deps so status/export/html still
    show their row; only the solver-input lists built from them exclude ignore_set members,
    so an ignored package never receives a recommended_version.
    """

    def test_ignored_package_excluded_from_solvable_direct_deps(self):
        deps = [_make_dep("sphinx"), _make_dep("requests")]
        ignore_set = frozenset(["sphinx"])
        solvable = [d for d in deps if d.canonical_name not in ignore_set]
        assert [d.canonical_name for d in solvable] == ["requests"]

    def test_empty_ignore_set_leaves_solvable_direct_deps_unchanged(self):
        deps = [_make_dep("sphinx"), _make_dep("requests")]
        ignore_set: frozenset[str] = frozenset()
        solvable = [d for d in deps if d.canonical_name not in ignore_set]
        assert solvable == deps

    def test_all_packages_ignored_yields_empty_solvable_direct_deps(self):
        deps = [_make_dep("sphinx"), _make_dep("requests")]
        ignore_set = frozenset(["sphinx", "requests"])
        solvable = [d for d in deps if d.canonical_name not in ignore_set]
        assert solvable == []

    def test_unknown_ignore_name_has_no_effect_on_solvable_direct_deps(self):
        deps = [_make_dep("sphinx")]
        ignore_set = frozenset(["nonexistent"])
        solvable = [d for d in deps if d.canonical_name not in ignore_set]
        assert solvable == deps

    def test_ignored_transitive_record_excluded_from_solve_regardless_of_security_only(self):
        records = [_make_scan_record("sphinx", cve=True), _make_scan_record("requests", cve=False)]
        ignore_set = frozenset(["sphinx"])
        for security_only in (False, True):
            records_to_solve = [r for r in records if r.package_name not in ignore_set and (not security_only or r.cve)]
            assert "sphinx" not in [r.package_name for r in records_to_solve]


def _make_npm_dep(name: str, version_defined: str, source: str | None = None) -> Dependency:
    return Dependency(
        name=name,
        version_installed="0.0.0",
        canonical_name=name,
        version_defined=version_defined,
        source=source,
    )


class TestGitHostedDependencyFiltering:
    """Git/URL-hosted npm deps are split out (they can't be fetched) and reported as ignored."""

    def test_partition_splits_git_hosted_from_registry(self):
        deps = [
            _make_npm_dep("lodash", "^4.17.21"),
            _make_npm_dep("uWebSockets.js", "github:uNetworking/uWebSockets.js#v20.10.0"),
        ]
        registry, git_hosted = partition_git_hosted(deps, enabled=True)
        assert [d.name for d in registry] == ["lodash"]
        assert [d.name for d in git_hosted] == ["uWebSockets.js"]

    def test_partition_disabled_keeps_everything_as_registry(self):
        deps = [_make_npm_dep("uWebSockets.js", "github:uNetworking/uWebSockets.js#v20.10.0")]
        registry, git_hosted = partition_git_hosted(deps, enabled=False)
        assert [d.name for d in registry] == ["uWebSockets.js"]
        assert git_hosted == []

    def test_build_ignored_packages_reports_git_hosted_with_spec(self):
        git_hosted = [_make_npm_dep("uWebSockets.js", "github:uNetworking/uWebSockets.js#v20.10.0")]
        ignored = build_ignored_packages(git_hosted, direct_descriptors=[], ignore_set=frozenset())
        assert len(ignored) == 1
        assert ignored[0].name == "uWebSockets.js"
        assert ignored[0].spec == "github:uNetworking/uWebSockets.js#v20.10.0"
        assert ignored[0].reason == IGNORE_REASON_NON_REGISTRY

    def test_build_ignored_packages_reports_ignore_flag_deps(self):
        descriptors = [_make_dep("sphinx"), _make_dep("requests")]
        ignored = build_ignored_packages([], direct_descriptors=descriptors, ignore_set=frozenset(["sphinx"]))
        assert [i.name for i in ignored] == ["sphinx"]
        assert ignored[0].reason == IGNORE_REASON_IGNORE_FLAG

    def test_build_ignored_packages_git_hosted_wins_on_overlap(self):
        git_hosted = [_make_npm_dep("sphinx", "github:owner/sphinx#main")]
        descriptors = [_make_dep("sphinx")]
        ignored = build_ignored_packages(git_hosted, descriptors, ignore_set=frozenset(["sphinx"]))
        assert len(ignored) == 1
        assert ignored[0].reason == IGNORE_REASON_NON_REGISTRY


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


# ============================================================================
# TestDirectDescriptorPeerConstraints
# ============================================================================


class TestDirectDescriptorPeerConstraints:
    """Direct deps must carry their peer requirements as hard constraints — and only those.

    Regression for the frontend/ ERESOLVE: peer specs were collected on the Dependency node but
    dropped when building the descriptor, so nothing forbade typescript 7.x.
    """

    @staticmethod
    def typescript_dep() -> Dependency:
        return Dependency(
            name="typescript",
            canonical_name="typescript",
            version_installed="6.0.3",
            version_defined=">=5.0.0",
            parent_constraints=["~6.0.3", ">=4.8.4 <6.1.0", ">=5.0.0"],
            peer_requirements=[
                PeerRequirement(requirer_name="typescript-eslint", spec=">=4.8.4 <6.1.0"),
                PeerRequirement(requirer_name="pinia", spec=">=4.5.0"),
            ],
        )

    def test_peer_specs_become_constraints(self):
        descriptor = direct_descriptor(self.typescript_dep(), is_optional=True)
        assert descriptor.all_constraints == [">=4.8.4 <6.1.0", ">=4.5.0"]
        assert descriptor.is_optional is True

    def test_root_manifest_specifier_is_not_a_constraint(self):
        """~6.0.3 sits in parent_constraints; promoting it would freeze every declared range."""
        descriptor = direct_descriptor(self.typescript_dep(), is_optional=False)
        assert "~6.0.3" not in descriptor.all_constraints

    def test_dep_without_peers_stays_unconstrained(self):
        """PyPI deps never carry peer requirements — behaviour must be unchanged for them."""
        dep = Dependency(name="requests", canonical_name="requests", version_installed="2.31.0")
        descriptor = direct_descriptor(dep, is_optional=False)
        assert descriptor.all_constraints == []
