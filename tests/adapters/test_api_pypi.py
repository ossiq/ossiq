# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for PackageRegistryApiPypi adapter.

Tests focus on:
1. API sanity checks (methods work after refactoring)
2. Edge cases (legacy versions, invalid PEP 440)
3. Yanked packages handling
"""

import pytest
from packaging.version import InvalidVersion

from ossiq.adapters.api_pypi import PackageRegistryApiPypi, is_valid_pep440_version
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.version import (
    VERSION_DIFF_BUILD,
    VERSION_DIFF_MAJOR,
    VERSION_DIFF_MINOR,
    VERSION_DIFF_PATCH,
    VERSION_DIFF_PRERELEASE,
    VERSION_LATEST,
    VERSION_NO_DIFF,
)
from ossiq.settings import Settings

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def pypi_api():
    """Create a PyPI API instance for testing."""
    settings = Settings()
    return PackageRegistryApiPypi(settings)


# ============================================================================
# Test is_valid_pep440_version helper
# ============================================================================


class TestIsValidPEP440Version:
    """Test the PEP 440 version validation helper."""

    def test_valid_simple_version(self):
        """Valid simple version should return True."""
        assert is_valid_pep440_version("1.2.3") is True

    def test_valid_two_part_version(self):
        """Valid two-part version should return True."""
        assert is_valid_pep440_version("3.11") is True

    def test_valid_prerelease_alpha(self):
        """Valid alpha prerelease should return True."""
        assert is_valid_pep440_version("1.0.0a1") is True

    def test_valid_prerelease_beta(self):
        """Valid beta prerelease should return True."""
        assert is_valid_pep440_version("1.0.0b2") is True

    def test_valid_prerelease_rc(self):
        """Valid release candidate should return True."""
        assert is_valid_pep440_version("1.0.0rc1") is True

    def test_valid_dev_version(self):
        """Valid dev version should return True."""
        assert is_valid_pep440_version("1.0.0.dev0") is True

    def test_valid_post_version(self):
        """Valid post version should return True."""
        assert is_valid_pep440_version("1.0.0.post1") is True

    def test_invalid_legacy_dev_r(self):
        """Legacy 'dev-r' format should return False."""
        assert is_valid_pep440_version("0.1dev-r1716") is False

    def test_invalid_with_spaces(self):
        """Version with spaces should return False."""
        assert is_valid_pep440_version("1.0 alpha") is False

    def test_invalid_random_string(self):
        """Random string should return False."""
        assert is_valid_pep440_version("not-a-version") is False

    def test_invalid_empty_string(self):
        """Empty string should return False."""
        assert is_valid_pep440_version("") is False


# ============================================================================
# Test compare_versions (API sanity)
# ============================================================================


class TestCompareVersions:
    """Test version comparison using PEP 440 semantics."""

    def test_compare_less_than(self, pypi_api):
        """Lower version should return -1."""
        result = pypi_api.compare_versions("1.0.0", "2.0.0")
        assert result == -1

    def test_compare_greater_than(self, pypi_api):
        """Higher version should return 1."""
        result = pypi_api.compare_versions("2.0.0", "1.0.0")
        assert result == 1

    def test_compare_equal(self, pypi_api):
        """Equal versions should return 0."""
        result = pypi_api.compare_versions("1.0.0", "1.0.0")
        assert result == 0

    def test_compare_prerelease_vs_release(self, pypi_api):
        """Prerelease should be less than release."""
        result = pypi_api.compare_versions("1.0.0a1", "1.0.0")
        assert result == -1

    def test_compare_two_part_versions(self, pypi_api):
        """Should handle two-part versions like Python versions."""
        result = pypi_api.compare_versions("3.10", "3.11")
        assert result == -1

    def test_compare_raises_on_invalid_version(self, pypi_api):
        """Should raise InvalidVersion for legacy versions."""
        with pytest.raises(InvalidVersion):
            pypi_api.compare_versions("0.1dev-r1716", "1.0.0")


# ============================================================================
# Test difference_versions (API sanity + edge cases)
# ============================================================================


class TestDifferenceVersions:
    """Test version difference calculation."""

    def test_difference_major(self, pypi_api):
        """Major version difference should be detected."""
        diff = pypi_api.difference_versions("1.0.0", "2.0.0")
        assert diff.diff_index == VERSION_DIFF_MAJOR
        assert diff.version1 == "1.0.0"
        assert diff.version2 == "2.0.0"

    def test_difference_minor(self, pypi_api):
        """Minor version difference should be detected."""
        diff = pypi_api.difference_versions("1.0.0", "1.1.0")
        assert diff.diff_index == VERSION_DIFF_MINOR

    def test_difference_patch(self, pypi_api):
        """Patch version difference should be detected."""
        diff = pypi_api.difference_versions("1.0.0", "1.0.1")
        assert diff.diff_index == VERSION_DIFF_PATCH

    def test_difference_prerelease(self, pypi_api):
        """Prerelease difference should be detected."""
        diff = pypi_api.difference_versions("1.0.0a1", "1.0.0a2")
        assert diff.diff_index == VERSION_DIFF_PRERELEASE

    def test_difference_dev(self, pypi_api):
        """Dev version difference should be detected as build."""
        diff = pypi_api.difference_versions("1.0.0.dev0", "1.0.0.dev1")
        assert diff.diff_index == VERSION_DIFF_BUILD

    def test_difference_post(self, pypi_api):
        """Post version difference should be detected as build."""
        diff = pypi_api.difference_versions("1.0.0.post1", "1.0.0.post2")
        assert diff.diff_index == VERSION_DIFF_BUILD

    def test_difference_identical(self, pypi_api):
        """Identical versions should return LATEST."""
        diff = pypi_api.difference_versions("1.0.0", "1.0.0")
        assert diff.diff_index == VERSION_LATEST

    def test_difference_none_first(self, pypi_api):
        """None as first version should return NO_DIFF."""
        diff = pypi_api.difference_versions(None, "1.0.0")
        assert diff.diff_index == VERSION_NO_DIFF
        assert diff.version1 == "N/A"

    def test_difference_none_second(self, pypi_api):
        """None as second version should return NO_DIFF."""
        diff = pypi_api.difference_versions("1.0.0", None)
        assert diff.diff_index == VERSION_NO_DIFF
        assert diff.version2 == "N/A"

    def test_difference_empty_string(self, pypi_api):
        """Empty string should return NO_DIFF."""
        diff = pypi_api.difference_versions("", "1.0.0")
        assert diff.diff_index == VERSION_NO_DIFF

    def test_difference_two_part_python_versions(self, pypi_api):
        """Should handle Python-style two-part versions."""
        diff = pypi_api.difference_versions("3.10", "3.11")
        assert diff.diff_index == VERSION_DIFF_MINOR

    def test_difference_string_equality_optimization(self, pypi_api):
        """String equality should be checked before parsing (optimization)."""
        # This should not call Version() constructor
        diff = pypi_api.difference_versions("1.0.0", "1.0.0")
        assert diff.diff_index == VERSION_LATEST

    def test_difference_raises_on_invalid_version(self, pypi_api):
        """Should raise InvalidVersion for legacy versions (not filtered)."""
        with pytest.raises(InvalidVersion):
            pypi_api.difference_versions("0.1dev-r1716", "1.0.0")


# ============================================================================
# Test package_versions (integration + yanked + legacy filtering)
# ============================================================================


class TestPackageVersions:
    """Test package versions retrieval with filtering."""

    def test_filters_legacy_versions(self, pypi_api, monkeypatch):
        """Legacy versions should be filtered out silently."""
        mock_response = {
            "info": {"name": "test-package", "version": "1.0.0", "requires_dist": []},
            "releases": {
                "1.0.0": [{"upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": False}],
                "0.1dev-r1716": [{"upload_time_iso_8601": "2011-01-01T00:00:00Z", "yanked": False}],
            },
        }

        monkeypatch.setattr(pypi_api, "_make_request", lambda path: mock_response)

        versions = list(pypi_api.package_versions("test-package"))

        # Should only include valid version, not legacy
        assert len(versions) == 1
        assert versions[0].version == "1.0.0"

    def test_handles_yanked_versions(self, pypi_api, monkeypatch):
        """Yanked versions should be marked as not published."""
        mock_response = {
            "info": {"name": "test-package", "version": "2.0.0", "requires_dist": []},
            "releases": {
                "2.0.0": [{"upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": False}],
                "1.0.0": [{"upload_time_iso_8601": "2022-01-01T00:00:00Z", "yanked": True}],
            },
        }

        monkeypatch.setattr(pypi_api, "_make_request", lambda path: mock_response)

        versions = list(pypi_api.package_versions("test-package"))

        # Both versions should be included
        assert len(versions) == 2

        # Find the yanked version
        yanked_version = next(v for v in versions if v.version == "1.0.0")
        assert yanked_version.is_published is False

        # Find the non-yanked version
        published_version = next(v for v in versions if v.version == "2.0.0")
        assert published_version.is_published is True

    def test_skips_empty_release_files(self, pypi_api, monkeypatch):
        """Versions with no files should be skipped."""
        mock_response = {
            "info": {"name": "test-package", "version": "1.0.0", "requires_dist": []},
            "releases": {
                "1.0.0": [{"upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": False}],
                "0.9.0": [],  # No files
            },
        }

        monkeypatch.setattr(pypi_api, "_make_request", lambda path: mock_response)

        versions = list(pypi_api.package_versions("test-package"))

        # Should only include version with files
        assert len(versions) == 1
        assert versions[0].version == "1.0.0"

    def test_includes_dependencies_for_latest_version(self, pypi_api, monkeypatch):
        """Latest version should have dependencies populated."""
        mock_response = {
            "info": {"name": "test-package", "version": "2.0.0", "requires_dist": ["requests>=2.0.0", "urllib3"]},
            "releases": {
                "2.0.0": [{"upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": False}],
                "1.0.0": [{"upload_time_iso_8601": "2022-01-01T00:00:00Z", "yanked": False}],
            },
        }

        monkeypatch.setattr(pypi_api, "_make_request", lambda path: mock_response)

        versions = list(pypi_api.package_versions("test-package"))

        latest = next(v for v in versions if v.version == "2.0.0")
        assert "requests>=2.0.0" in latest.declared_dependencies
        assert "urllib3" in latest.declared_dependencies

        # Older versions don't have dependencies (PyPI API limitation)
        older = next(v for v in versions if v.version == "1.0.0")
        assert len(older.declared_dependencies) == 0

    def test_all_files_yanked_marks_version_unpublished(self, pypi_api, monkeypatch):
        """If all files are yanked, version should be unpublished."""
        mock_response = {
            "info": {"name": "test-package", "version": "1.0.0", "requires_dist": []},
            "releases": {
                "1.0.0": [
                    {"upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": True},
                    {"upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": True},
                ]
            },
        }

        monkeypatch.setattr(pypi_api, "_make_request", lambda path: mock_response)

        versions = list(pypi_api.package_versions("test-package"))

        assert len(versions) == 1
        assert versions[0].is_published is False

    def test_partial_yanked_files_keeps_version_published(self, pypi_api, monkeypatch):
        """If some files are not yanked, version should remain published."""
        mock_response = {
            "info": {"name": "test-package", "version": "1.0.0", "requires_dist": []},
            "releases": {
                "1.0.0": [
                    {"upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": True},
                    {"upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": False},
                ]
            },
        }

        monkeypatch.setattr(pypi_api, "_make_request", lambda path: mock_response)

        versions = list(pypi_api.package_versions("test-package"))

        assert len(versions) == 1
        assert versions[0].is_published is True


# ============================================================================
# Test edge cases for _calculate_pep440_diff_index (internal method)
# ============================================================================


class TestCalculatePEP440DiffIndex:
    """Test the internal diff calculation logic."""

    def test_handles_four_part_versions(self, pypi_api):
        """Should handle versions with 4+ segments."""
        diff = pypi_api.difference_versions("1.2.3.4", "1.2.3.5")
        assert diff.diff_index == VERSION_DIFF_PATCH

    def test_handles_mismatched_segment_lengths(self, pypi_api):
        """Should handle different length release tuples."""
        # 3.11 vs 3.11.1
        diff = pypi_api.difference_versions("3.11", "3.11.1")
        assert diff.diff_index == VERSION_DIFF_PATCH

    def test_prerelease_vs_no_prerelease(self, pypi_api):
        """Prerelease should differ from no prerelease."""
        diff = pypi_api.difference_versions("1.0.0", "1.0.0a1")
        assert diff.diff_index == VERSION_DIFF_PRERELEASE


# ============================================================================
# Test API attributes and initialization
# ============================================================================


class TestPackageRegistryApiPypiInit:
    """Test API initialization and attributes."""

    def test_has_correct_registry_type(self, pypi_api):
        """Should have PYPI as package registry."""
        assert pypi_api.package_registry == ProjectPackagesRegistry.PYPI

    def test_repr(self, pypi_api):
        """Should have a readable repr."""
        assert repr(pypi_api) == "<PackageRegistryApiPypi instance>"

    def test_stores_settings(self):
        """Should store settings instance."""
        settings = Settings()
        api = PackageRegistryApiPypi(settings)
        assert api.settings is settings
