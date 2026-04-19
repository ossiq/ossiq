"""
Tests for service/project.py — ScanRecord factory and version_constraint propagation.
"""

from unittest.mock import MagicMock

import pytest

from ossiq.domain.common import ConstraintType, ProjectPackagesRegistry
from ossiq.domain.package import Package
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion, VersionsDifference
from ossiq.service.project import scan_record

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_package_registry():
    """Mock package registry API returning a stable package and version list."""
    registry = MagicMock()
    registry.package_registry = ProjectPackagesRegistry.PYPI

    # package_info returns a minimal Package
    package = Package(
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
    registry.package_info.return_value = package

    # package_versions returns two versions (installed + latest)
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
def mock_package(mock_package_registry):
    """The Package object returned by mock_package_registry.package_info."""
    return mock_package_registry.package_info.return_value


# ============================================================================
# Tests
# ============================================================================


class TestScanRecordVersionConstraint:
    """Test that scan_record() correctly propagates version_constraint."""

    def test_version_constraint_is_stored_in_scan_record(self, mock_package_registry, mock_package):
        """Test scan_record stores version_constraint when provided.

        AAA Pattern:
        - Arrange: mock registry, provide a version constraint string
        - Act: call scan_record() with version_constraint kwarg
        - Assert: resulting ScanRecord.version_constraint matches the input
        """
        # Arrange
        constraint = ">=2.31.0,<3.0.0"

        # Act
        record = scan_record(
            packages_registry=mock_package_registry,
            package_info=mock_package,
            package_name="requests",
            canonical_name="requests",
            package_version="2.31.0",
            is_optional_dependency=False,
            prefetched_cves=set(),
            prefetched_versions_since=mock_package_registry.package_versions.return_value,
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
            version_constraint=constraint,
        )

        # Assert
        assert record.version_constraint == constraint

    def test_version_constraint_defaults_to_none(self, mock_package_registry, mock_package):
        """Test scan_record sets version_constraint to None when not provided.

        AAA Pattern:
        - Arrange: mock registry, omit version_constraint
        - Act: call scan_record() without version_constraint
        - Assert: resulting ScanRecord.version_constraint is None
        """
        # Act
        record = scan_record(
            packages_registry=mock_package_registry,
            package_info=mock_package,
            package_name="requests",
            canonical_name="requests",
            package_version="2.31.0",
            is_optional_dependency=False,
            prefetched_cves=set(),
            prefetched_versions_since=mock_package_registry.package_versions.return_value,
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
        )

        # Assert
        assert record.version_constraint is None

    @pytest.mark.parametrize(
        "constraint",
        [
            ">=2.31.0",
            ">=2.31.0,<3.0.0",
            "~=2.31.0",
            "^2.31.0",
            "~2.31.0",
            "==2.31.0",
        ],
    )
    def test_various_constraint_formats_are_preserved(self, mock_package_registry, mock_package, constraint):
        """Test that raw constraint strings from different ecosystems are stored as-is.

        AAA Pattern:
        - Arrange: provide a constraint string in various formats
        - Act: call scan_record() with each constraint
        - Assert: the raw string is stored without modification
        """
        # Act
        record = scan_record(
            packages_registry=mock_package_registry,
            package_info=mock_package,
            package_name="requests",
            canonical_name="requests",
            package_version="2.31.0",
            is_optional_dependency=False,
            prefetched_cves=set(),
            prefetched_versions_since=mock_package_registry.package_versions.return_value,
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
            version_constraint=constraint,
        )

        # Assert
        assert record.version_constraint == constraint


class TestScanRecordPurl:
    """Test that scan_record() correctly generates and stores the PURL field."""

    def test_purl_is_populated_for_pypi_package(self, mock_package_registry, mock_package):
        """Test scan_record generates a valid PURL for a PyPI package.

        AAA Pattern:
        - Arrange: mock registry with PYPI registry type
        - Act: call scan_record() for a known package and version
        - Assert: resulting ScanRecord.purl matches expected PURL format
        """
        # Act
        record = scan_record(
            packages_registry=mock_package_registry,
            package_info=mock_package,
            package_name="requests",
            canonical_name="requests",
            package_version="2.31.0",
            is_optional_dependency=False,
            prefetched_cves=set(),
            prefetched_versions_since=mock_package_registry.package_versions.return_value,
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
        )

        # Assert
        assert record.purl == "pkg:pypi/requests@2.31.0"

    def test_purl_uses_canonical_name(self, mock_package_registry, mock_package):
        """Test scan_record uses canonical_name (not alias) when building PURL.

        AAA Pattern:
        - Arrange: mock registry, package_name differs from canonical_name
        - Act: call scan_record() with an alias name and a canonical name
        - Assert: purl uses canonical_name, not the alias
        """
        # Act
        record = scan_record(
            packages_registry=mock_package_registry,
            package_info=mock_package,
            package_name="requests-alias",
            canonical_name="requests",
            package_version="2.31.0",
            is_optional_dependency=False,
            prefetched_cves=set(),
            prefetched_versions_since=mock_package_registry.package_versions.return_value,
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
        )

        # Assert — PURL must reference canonical registry name
        assert record.purl == "pkg:pypi/requests@2.31.0"
        assert "requests-alias" not in record.purl
