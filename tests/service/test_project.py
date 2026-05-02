"""
Tests for service/project.py — ScanRecord factory and version_constraint propagation.
"""

from unittest.mock import MagicMock

import pytest

from ossiq.domain.common import ConstraintType, CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.package import Package
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion, VersionsDifference
from ossiq.service.project import get_package_versions_since, scan_record

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
            packages_registry=registry,
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
            packages_registry=registry,
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
