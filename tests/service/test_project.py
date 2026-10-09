"""
Tests for the service/project package — ScanRecord factory and version_constraint propagation.
"""

import dataclasses
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ossiq.adapters.api_pypi import PackageRegistryApiPypi
from ossiq.adapters.package_managers.api_npm import PackageManagerJsNpm
from ossiq.adapters.package_managers.dependency_tree import GraphExporter
from ossiq.domain.common import ConstraintType, CveDatabase, ProjectPackagesRegistry, RegistryStatus
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.package import Package
from ossiq.domain.packages_manager import UV
from ossiq.domain.project import ConstraintSource, Dependency, IncomingEdge, InstalledCopy, PeerRequirement, Project
from ossiq.domain.version import PackageVersion, VersionsDifference
from ossiq.messages import IGNORE_REASON_IGNORE_FLAG, IGNORE_REASON_NON_REGISTRY
from ossiq.risk.maintenance import DeprecationSignal
from ossiq.service.project.models import DependencyDescriptor, ScanRecord
from ossiq.service.project.prefetch import build_ignored_packages, get_package_versions_since, partition_git_hosted
from ossiq.service.project.records import calculate_version_age_days, scan_record, scan_sort_key
from ossiq.service.project.scan import (
    ScanDescriptors,
    build_scan_descriptors,
    direct_descriptor,
    held_transitive_versions,
    installed_package_names,
    requirement_scope_for,
    scan,
    solve_transitive_phase,
)
from ossiq.service.update_impact import ImpactKind, TransitiveImpact
from ossiq.settings import Settings
from ossiq.solver.dependencies_solver import EMPTY_OUTPUT, SolverOutput

# ============================================================================
# Module-level constants
# ============================================================================

TESTDATA_NPM = Path(__file__).parents[2] / "testdata" / "npm"

_PRERELEASE_VERSION = "1.0.0b1"
_STABLE_VERSION = "1.0.0"

# Real PEP 440 semantics (the constructor does no I/O) for the ladder tests below, where a
# MagicMock registry would make latest_in_range a mock attribute rather than a version.
_REAL_PYPI = PackageRegistryApiPypi(Settings())
_LADDER_VERSIONS = [
    PackageVersion(
        version=version,
        license="Apache-2.0",
        package_url=f"https://pypi.org/project/requests/{version}/",
        declared_dependencies={},
        published_date_iso="2023-05-22T00:00:00",
    )
    for version in ("2.31.0", "2.32.0")
]

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

    def test_ladder_is_computed_against_the_declaration_not_the_lww_constraint(self, mock_package):
        """version_constraint is a last-writer-wins accumulator that a transitive consumer can
        overwrite; the declaration is what authorizes a manifest write. latest_in_range must be
        computed against the same string service.project.strategy.classify_rung uses, or the rung
        shown and the rung that gates `ossiq apply` disagree."""
        record = self._make_record(
            _REAL_PYPI,
            mock_package,
            _LADDER_VERSIONS,
            version_constraint=">=2.0.0",
            version_constraint_declared="==2.31.0",
        )

        assert record.compatibility.latest_in_range == "2.31.0"

    def test_ladder_falls_back_to_the_lww_constraint_without_a_declaration(self, mock_package):
        record = self._make_record(
            _REAL_PYPI,
            mock_package,
            _LADDER_VERSIONS,
            version_constraint=">=2.0.0",
            version_constraint_declared=None,
        )

        assert record.compatibility.latest_in_range == "2.32.0"

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

    def test_install_execution_fields_come_from_installed_release(self, mock_package_registry, mock_package):
        installed_pv = PackageVersion(
            version="2.31.0",
            license="Apache-2.0",
            package_url="https://pypi.org/project/requests/2.31.0/",
            declared_dependencies={},
            published_date_iso="2023-05-22T00:00:00",
            runs_code_at_install=True,
            install_execution_reason="PyPI source distribution build",
        )
        versions = [installed_pv, mock_package_registry.package_versions.return_value[1]]

        record = self._make_record(mock_package_registry, mock_package, versions)

        assert record.runs_code_at_install is True
        assert record.install_execution_reason == "PyPI source distribution build"

    def test_install_execution_fields_default_to_none_without_installed_release(
        self, mock_package_registry, mock_package
    ):
        """No PackageVersion matches the installed version, so both fields stay None."""
        record = self._make_record(mock_package_registry, mock_package, versions=[])

        assert record.runs_code_at_install is None
        assert record.install_execution_reason is None


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


class TestLatestReleaseAgeDays:
    """scan_record dates the registry's latest release, not just the installed one."""

    def test_records_the_age_of_the_latest_release(self, mock_package_registry, mock_package, mock_versions) -> None:
        record = scan_record(
            version_rules=mock_package_registry,
            package_info=mock_package,
            package_name="requests",
            canonical_name="requests",
            package_version="2.31.0",
            is_optional_dependency=False,
            prefetched_cves=set(),
            prefetched_versions_since=mock_versions,
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
            # Naive to match the fixture's published_date_iso values.
            now=datetime(2024, 6, 8),  # noqa: DTZ001
        )
        # The installed 2.31.0 went out in 2023, the latest 2.32.0 on 2024-05-29: the two clocks
        # the maintenance model needs to tell apart.
        assert record.version_age_days == 383
        assert record.latest_release_age_days == 10

    def test_none_when_the_registry_names_no_latest_version(
        self, mock_package_registry, mock_package, mock_versions
    ) -> None:
        mock_package.latest_version = None
        record = scan_record(
            version_rules=mock_package_registry,
            package_info=mock_package,
            package_name="requests",
            canonical_name="requests",
            package_version="2.31.0",
            is_optional_dependency=False,
            prefetched_cves=set(),
            prefetched_versions_since=mock_versions,
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
        )
        assert record.latest_release_age_days is None


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
    """Direct deps carry no hard constraints of their own: peers bind per candidate, not per snapshot.

    The installed lockfile's peer specs describe the installed release's neighbours. Held as L1
    clauses they froze a lockstep family (vue and @vue/server-renderer), because the only version
    that satisfied the old spec was the old one.
    """

    @staticmethod
    def typescript_dep() -> Dependency:
        return Dependency(
            name="typescript",
            canonical_name="typescript",
            version_installed="6.0.3",
            version_defined="~6.0.3",
            parent_constraints=["~6.0.3", ">=4.8.4 <6.1.0", ">=5.0.0"],
            peer_requirements=[
                PeerRequirement(requirer_name="typescript-eslint", spec=">=4.8.4 <6.1.0"),
                PeerRequirement(requirer_name="pinia", spec=">=4.5.0"),
            ],
        )

    def test_installed_peer_specs_are_not_hard_constraints(self):
        descriptor = direct_descriptor(self.typescript_dep(), is_optional=True)
        assert descriptor.all_constraints == []
        assert descriptor.is_optional is True

    def test_root_manifest_specifier_is_not_a_constraint(self):
        """~6.0.3 sits in parent_constraints; promoting it would freeze every declared range."""
        descriptor = direct_descriptor(self.typescript_dep(), is_optional=False)
        assert "~6.0.3" not in descriptor.all_constraints

    def test_peer_requirements_still_travel_with_the_descriptor(self):
        """The record shows them, and peer_violations is computed from them."""
        descriptor = direct_descriptor(self.typescript_dep(), is_optional=False)
        assert [(r.requirer_name, r.spec) for r in descriptor.peer_requirements] == [
            ("typescript-eslint", ">=4.8.4 <6.1.0"),
            ("pinia", ">=4.5.0"),
        ]

    def test_dep_without_peers_stays_unconstrained(self):
        """PyPI deps never carry peer requirements — behaviour must be unchanged for them."""
        dep = Dependency(name="requests", canonical_name="requests", version_installed="2.31.0")
        descriptor = direct_descriptor(dep, is_optional=False)
        assert descriptor.all_constraints == []


def pypi_project(root: Dependency, python_floor: str | None = "3.12") -> Project:
    return Project(
        package_manager_type=UV,
        name="app",
        project_path="/tmp/app",
        dependency_tree=root,
        engine_constraints={"python": python_floor} if python_floor else None,
    )


def pypi_node(name: str, version: str = "1.0.0", **fields) -> Dependency:
    return Dependency(name=name, canonical_name=name, version_installed=version, **fields)


class TestRequirementScopeFor:
    """The scope carries what the project installs with: enabled extras per package, and the floor."""

    def test_extras_are_collected_per_package_at_any_depth(self):
        allauth = pypi_node("django-allauth", extras=["socialaccount"])
        uvicorn = pypi_node("uvicorn", extras=["standard"], dependencies={"click": pypi_node("click")})
        nested = pypi_node("pyjwt", extras=["crypto"])
        wagtail = pypi_node("wagtail", dependencies={"pyjwt": nested})
        root = pypi_node("app", dependencies={"django-allauth": allauth, "uvicorn": uvicorn, "wagtail": wagtail})

        scope = requirement_scope_for(pypi_project(root))

        assert scope.extras_for("django-allauth") == frozenset({"socialaccount"})
        assert scope.extras_for("uvicorn") == frozenset({"standard"})
        assert scope.extras_for("pyjwt") == frozenset({"crypto"})
        assert scope.extras_for("click") == frozenset()

    def test_optional_dependencies_are_visited_too(self):
        dev_tool = pypi_node("pylint", extras=["spelling"])
        root = pypi_node("app", optional_dependencies={"pylint": dev_tool})

        assert requirement_scope_for(pypi_project(root)).extras_for("pylint") == frozenset({"spelling"})

    def test_a_dependency_cycle_terminates(self):
        a = pypi_node("pkg-a", extras=["x"])
        b = pypi_node("pkg-b", dependencies={"pkg-a": a})
        a.dependencies["pkg-b"] = b

        scope = requirement_scope_for(pypi_project(pypi_node("app", dependencies={"pkg-a": a})))

        assert scope.extras_for("pkg-a") == frozenset({"x"})

    def test_the_python_floor_comes_from_the_projects_engine_constraints(self):
        assert requirement_scope_for(pypi_project(pypi_node("app"), python_floor="3.12")).python_floor == "3.12"

    def test_a_project_without_a_python_floor_has_none(self):
        assert requirement_scope_for(pypi_project(pypi_node("app"), python_floor=None)).python_floor is None


class TestHeldTransitiveVersions:
    """The version of each transitive package that direct dependencies see once the plan applies."""

    @staticmethod
    def record(name: str, *copies: InstalledCopy, pick: str | None = None) -> ScanRecord:
        record = ScanRecord(
            package_name=name,
            dependency_name=name,
            is_optional_dependency=False,
            installed_version=copies[0].version,
            latest_version=None,
            versions_diff_index=VersionsDifference("1.0.0", "1.0.0", 0, diff_name="LATEST"),
            time_lag_days=None,
            releases_lag=None,
            cve=[],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
            recommended_version=pick,
        )
        record.installed_copies = list(copies)
        return record

    @staticmethod
    def copy(version: str, *requirers: str) -> InstalledCopy:
        edges = tuple(IncomingEdge(name, "1.0.0", "*") for name in requirers)
        return InstalledCopy(version, edges, ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"))

    def test_the_copy_a_direct_dependency_asks_for_stands_for_the_name(self):
        shared = self.record("@vue/shared", self.copy("3.5.43", "vue"), self.copy("3.5.42", "@vue-macros/common"))

        finals, installed = held_transitive_versions([shared], {"@vue-macros/common"})

        assert (finals, installed) == ({"@vue/shared": "3.5.42"}, {"@vue/shared": "3.5.42"})

    def test_a_pick_on_that_copy_is_its_final_version(self):
        host = self.record("host", self.copy("1.0.0", "app-plugin"), pick="1.2.0")

        assert held_transitive_versions([host], {"app-plugin"})[0] == {"host": "1.2.0"}

    def test_a_family_move_on_that_copy_is_its_final_version(self):
        shared = self.record("@vue/shared", self.copy("3.5.43", "vue"), self.copy("3.5.42", "@vue-macros/common"))
        pick = self.record("vue-family-owner", self.copy("1.0.0", "x"))
        pick.update_transitive_impacts = [
            TransitiveImpact(
                package_name="@vue/shared",
                current_version="3.5.42",
                projected_version="3.5.43",
                new_constraint="3.5.43",
                driven_by="vue-family-owner",
                has_conflict=False,
                kind=ImpactKind.OVERRIDE_BUMP,
            )
        ]

        finals, _ = held_transitive_versions([shared, pick], {"@vue-macros/common"})

        assert finals["@vue/shared"] == "3.5.43"


class TestInstalledPackageNames:
    @staticmethod
    def descriptors(root: Dependency) -> ScanDescriptors:
        return ScanDescriptors(
            prod_deps=[_make_dep(name) for name in root.dependencies],
            opt_deps=[_make_dep(name, is_optional=True) for name in root.optional_dependencies],
            trans_deps=[],
            ignored_packages=[],
            ignore_set=frozenset(),
            walker=GraphExporter(root),
        )

    def test_what_an_enabled_extra_installs_counts_as_installed(self):
        """Regression: uvicorn[standard]'s httptools was reported as a new dependency of uvicorn 0.54."""
        httptools = pypi_node("httptools", categories=["standard"])
        uvicorn = pypi_node("uvicorn", extras=["standard"], optional_dependencies={"httptools": httptools})
        root = pypi_node("app", dependencies={"uvicorn": uvicorn})

        assert "httptools" in installed_package_names(self.descriptors(root))

    def test_an_extra_nobody_enabled_is_not_installed(self):
        pytest_pkg = pypi_node("pytest", categories=["test"])
        uvicorn = pypi_node("uvicorn", extras=["standard"], optional_dependencies={"pytest": pytest_pkg})
        root = pypi_node("app", dependencies={"uvicorn": uvicorn})

        assert "pytest" not in installed_package_names(self.descriptors(root))

    def test_direct_optional_and_transitive_packages_are_all_installed(self):
        click = pypi_node("click")
        root = pypi_node(
            "app",
            dependencies={"uvicorn": pypi_node("uvicorn", dependencies={"click": click})},
            optional_dependencies={"ruff": pypi_node("ruff")},
        )

        assert installed_package_names(self.descriptors(root)) == {"uvicorn", "ruff", "click"}


class TestScanSetsTheRequirementScope:
    class StopScan(Exception):
        pass

    def test_the_registry_reads_requirements_under_the_projects_scope_before_anything_else(self):
        """Regression: allauth[socialaccount]'s `oauthlib<4` was invisible, so oauthlib 4.0.0 was recommended."""
        root = pypi_node("app", dependencies={"django-allauth": pypi_node("django-allauth", extras=["socialaccount"])})
        sources = MagicMock()
        sources.packages_manager.project_info.return_value = pypi_project(root, python_floor="3.12")

        with (
            patch("ossiq.service.project.scan.resolve_library_constraints", side_effect=lambda project, _: project),
            patch("ossiq.service.project.scan.build_scan_descriptors", side_effect=self.StopScan),
            pytest.raises(self.StopScan),
        ):
            scan(sources)

        scope = sources.packages_registry.use_requirement_scope.call_args.args[0]
        assert scope.extras_for("django-allauth") == frozenset({"socialaccount"})
        assert scope.python_floor == "3.12"


class TestTransitivePhaseWarmsTheDirectRequirements:
    def test_the_direct_deps_requirements_are_fetched_in_one_batch_before_the_solve(self):
        """The solver reads what each direct dep requires of a pick; a fetch per unchanged dep is serial."""
        calls: list[str] = []
        registry = MagicMock(spec=PackageRegistryApiPypi)
        registry.warmup_version_requires.side_effect = lambda pairs: calls.append(f"warm {pairs}")
        sources = MagicMock()
        sources.packages_registry = registry

        def solve(*args, **kwargs):
            calls.append("solve")
            return EMPTY_OUTPUT

        with patch("ossiq.service.project.scan.dependencies_solver.solve_transitive", side_effect=solve):
            solve_transitive_phase(
                [_make_scan_record("oauthlib")],
                frozenset(),
                sources,
                MagicMock(versions={}),
                {"django": "6.0.7", "wagtail": "7.4.2"},
                SolverOutput(recommendations={"wagtail": "8.0"}, reasons={}),
                None,
            )

        assert calls == ["warm [('django', '6.0.7'), ('wagtail', '8.0')]", "solve"]


class TestDirectPackagesAreListedOnce:
    @staticmethod
    def sources() -> MagicMock:
        sources = MagicMock()
        sources.ignore_packages = []
        sources.packages_registry = MagicMock(spec=PackageRegistryApiPypi)
        sources.production = False
        return sources

    def test_a_package_in_both_dependencies_and_an_extra_has_one_descriptor(self):
        """Regression: `ty` is in [project].dependencies and the dev extra, and got two rows."""
        root = pypi_node(
            "app",
            dependencies={"ty": pypi_node("ty", "0.0.63")},
            optional_dependencies={"ty": pypi_node("ty", "0.0.63"), "pylint": pypi_node("pylint")},
        )

        descriptors = build_scan_descriptors(pypi_project(root), self.sources())

        assert [d.canonical_name for d in descriptors.prod_deps] == ["ty"]
        assert [d.canonical_name for d in descriptors.opt_deps] == ["pylint"]

    def test_an_extra_only_package_stays_optional(self):
        root = pypi_node("app", optional_dependencies={"pylint": pypi_node("pylint")})

        descriptors = build_scan_descriptors(pypi_project(root), self.sources())

        assert [(d.canonical_name, d.is_optional) for d in descriptors.opt_deps] == [("pylint", True)]


class TestInstalledCopies:
    """A package npm nests is installed more than once; the scan keeps every copy, and one stands for the name."""

    @staticmethod
    def sources(*, one_copy_per_name: bool) -> MagicMock:
        sources = MagicMock()
        sources.ignore_packages = []
        sources.production = False
        sources.packages_registry = MagicMock(spec=PackageRegistryApiPypi)
        sources.packages_registry.one_copy_per_name = one_copy_per_name
        sources.packages_registry.compare_versions.side_effect = lambda a, b: (
            (tuple(map(int, a.split("."))) > tuple(map(int, b.split("."))))
            - (tuple(map(int, a.split("."))) < tuple(map(int, b.split("."))))
        )
        return sources

    @staticmethod
    def minimatch_copies() -> Dependency:
        """eslint resolves minimatch ^10 to 10.2.5, editorconfig resolves ^9 to its own nested 9.0.9."""
        hoisted = pypi_node(
            "minimatch",
            "10.2.5",
            parent_constraints=["^10.2.4"],
            parent_edges=[IncomingEdge("eslint", "10.2.0", "^10.2.4")],
        )
        nested = pypi_node(
            "minimatch",
            "9.0.9",
            parent_constraints=["^9.0.1"],
            parent_edges=[IncomingEdge("editorconfig", "1.0.7", "^9.0.1")],
        )
        return pypi_node(
            "app",
            dependencies={
                "eslint": pypi_node("eslint", "10.2.0", dependencies={"minimatch": hoisted}),
                "editorconfig": pypi_node("editorconfig", "1.0.7", dependencies={"minimatch": nested}),
            },
        )

    def test_the_newest_copy_stands_for_the_name_and_every_copy_is_kept(self):
        descriptors = build_scan_descriptors(
            pypi_project(self.minimatch_copies()), self.sources(one_copy_per_name=False)
        )

        (minimatch,) = [d for d in descriptors.trans_deps if d.canonical_name == "minimatch"]
        assert minimatch.version == "10.2.5"
        assert [(c.version, [e.requirer_name for e in c.edges]) for c in minimatch.installed_copies] == [
            ("10.2.5", ["eslint"]),
            ("9.0.9", ["editorconfig"]),
        ]

    def test_the_name_carries_every_copys_constraints(self):
        """What a version-keyed override on the newest copy would rewrite is found among them."""
        descriptors = build_scan_descriptors(
            pypi_project(self.minimatch_copies()), self.sources(one_copy_per_name=False)
        )

        (minimatch,) = [d for d in descriptors.trans_deps if d.canonical_name == "minimatch"]
        assert minimatch.all_constraints == ["^10.2.4", "^9.0.1"]

    def test_a_one_copy_manager_keeps_the_copy_the_walk_reached_last(self):
        """pip and uv behave as before: no copy is promoted, only that node's own constraints."""
        descriptors = build_scan_descriptors(
            pypi_project(self.minimatch_copies()), self.sources(one_copy_per_name=True)
        )

        (minimatch,) = [d for d in descriptors.trans_deps if d.canonical_name == "minimatch"]
        assert minimatch.version == "9.0.9"
        assert minimatch.all_constraints == ["^9.0.1"]

    def test_a_direct_dependency_also_nested_elsewhere_carries_both_copies(self):
        nested_ms = pypi_node("ms", "2.0.0", parent_edges=[IncomingEdge("debug", "4.0.0", "2.0.0")])
        root = pypi_node(
            "app",
            dependencies={
                "ms": pypi_node("ms", "2.1.3", parent_edges=[IncomingEdge("app", "1.0.0", "^2.1.0")]),
                "debug": pypi_node("debug", "4.0.0", dependencies={"ms": nested_ms}),
            },
        )

        descriptors = build_scan_descriptors(pypi_project(root), self.sources(one_copy_per_name=False))

        (ms,) = [d for d in descriptors.prod_deps if d.canonical_name == "ms"]
        assert [c.version for c in ms.installed_copies] == ["2.1.3", "2.0.0"]
        assert not [d for d in descriptors.trans_deps if d.canonical_name == "ms"]

    def test_aliases_of_one_package_at_one_version_are_one_copy(self):
        lodash_a = Dependency(name="lodash-a", canonical_name="lodash", version_installed="4.17.21")
        lodash_b = Dependency(name="lodash-b", canonical_name="lodash", version_installed="4.17.21")
        root = pypi_node(
            "app", dependencies={"host": pypi_node("host", dependencies={"lodash-a": lodash_a, "lodash-b": lodash_b})}
        )

        descriptors = build_scan_descriptors(pypi_project(root), self.sources(one_copy_per_name=False))

        (lodash,) = [d for d in descriptors.trans_deps if d.canonical_name == "lodash"]
        assert [c.version for c in lodash.installed_copies] == ["4.17.21"]

    def test_a_real_lockfile_keeps_the_nested_copy_a_vulnerable_dependent_needs(self):
        """cross-spawn 7.0.3 (advisory GHSA-3xgq-45jj-v275) needs which ^2 while the hoisted which is 5.

        npm installed a second which under cross-spawn, so the fix to 7.0.6 is not blocked by
        the hoisted copy: both copies, and who asked for each, have to reach the solver.
        """
        project = PackageManagerJsNpm(str(TESTDATA_NPM / "nested-copies"), Settings()).project_info()

        descriptors = build_scan_descriptors(project, self.sources(one_copy_per_name=False))

        (which,) = [d for d in descriptors.prod_deps if d.canonical_name == "which"]
        (cross_spawn,) = [d for d in descriptors.trans_deps if d.canonical_name == "cross-spawn"]
        assert [(c.version, [e.requirer_name for e in c.edges]) for c in which.installed_copies] == [
            ("5.0.0", ["nested-copies"]),
            ("2.0.2", ["cross-spawn"]),
        ]
        assert (cross_spawn.version, cross_spawn.all_constraints) == ("7.0.3", ["^7.0.0"])


class TestScanRecordRegistryVerdict:
    """scan_record is the one writer of the registry's verdict onto a ScanRecord."""

    @staticmethod
    def record(registry, package, versions):
        return scan_record(
            version_rules=registry,
            package_info=package,
            package_name="requests",
            canonical_name="requests",
            package_version="2.31.0",
            is_optional_dependency=False,
            prefetched_cves=set(),
            prefetched_versions_since=versions,
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
        )

    def test_carries_the_packages_status_and_message(self, mock_package_registry, mock_package, mock_versions):
        mock_package.registry_status = RegistryStatus.DEPRECATED
        mock_package.deprecation_message = "use httpx instead"

        record = self.record(mock_package_registry, mock_package, mock_versions)

        assert record.registry_status == RegistryStatus.DEPRECATED
        assert record.deprecation_message == "use httpx instead"
        assert record.is_installed_deprecated is True

    def test_a_package_the_registry_has_no_verdict_on_carries_none(
        self, mock_package_registry, mock_package, mock_versions
    ):
        record = self.record(mock_package_registry, mock_package, mock_versions)

        assert record.registry_status is None
        assert record.deprecation_message is None
        assert record.is_installed_deprecated is False

    def test_the_packages_own_message_outranks_the_releases(self, mock_package_registry, mock_package, mock_versions):
        mock_package.registry_status = RegistryStatus.DEPRECATED
        mock_package.deprecation_message = "package: use httpx"
        installed = dataclasses.replace(mock_versions[0], is_deprecated=True, deprecation_message="release: update")

        record = self.record(mock_package_registry, mock_package, [installed, mock_versions[1]])

        assert record.deprecation_message == "package: use httpx"

    def test_a_deprecated_release_of_a_live_package_is_not_a_retired_package(
        self, mock_package_registry, mock_package, mock_versions
    ):
        mock_package.registry_status = RegistryStatus.ACTIVE
        installed = dataclasses.replace(mock_versions[0], is_deprecated=True, deprecation_message="update to latest")

        record = self.record(mock_package_registry, mock_package, [installed, mock_versions[1]])

        assert record.is_installed_deprecated is True
        assert record.registry_status == RegistryStatus.ACTIVE
        # The release's note still explains the flag.
        assert record.deprecation_message == "update to latest"
        assert DeprecationSignal.REGISTRY_DEPRECATED not in record.deprecation.signals

    def test_an_undeprecated_release_does_not_lend_its_message(
        self, mock_package_registry, mock_package, mock_versions
    ):
        installed = dataclasses.replace(mock_versions[0], is_deprecated=False, deprecation_message="stale")

        record = self.record(mock_package_registry, mock_package, [installed, mock_versions[1]])

        assert record.deprecation_message is None

    @pytest.mark.parametrize("status", [RegistryStatus.DEPRECATED, RegistryStatus.ARCHIVED])
    def test_a_retired_package_is_strong_deprecation_evidence(
        self, mock_package_registry, mock_package, mock_versions, status
    ):
        mock_package.registry_status = status

        record = self.record(mock_package_registry, mock_package, mock_versions)

        assert DeprecationSignal.REGISTRY_DEPRECATED in record.deprecation.signals

    def test_quarantine_is_not_deprecation_evidence(self, mock_package_registry, mock_package, mock_versions):
        mock_package.registry_status = RegistryStatus.QUARANTINED

        record = self.record(mock_package_registry, mock_package, mock_versions)

        assert record.registry_status == RegistryStatus.QUARANTINED
        assert record.is_installed_deprecated is False
        assert DeprecationSignal.REGISTRY_DEPRECATED not in record.deprecation.signals
