# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for PackageRegistryApiPypi adapter.

Tests focus on:
1. API sanity checks (methods work after refactoring)
2. Edge cases (legacy versions, invalid PEP 440)
3. Yanked packages handling
"""

from unittest.mock import patch

import pytest
from packaging.version import InvalidVersion

from ossiq.adapters.api_pypi import PackageRegistryApiPypi, extract_license_from_classifiers, is_valid_pep440_version
from ossiq.clients.batch import BatchClient
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.exceptions import UnableLoadPackage
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


@pytest.fixture
def mock_pypi_response(pypi_api):
    """
    Fixture to mock PyPI registry API responses via _raw_cache.

    Populates _raw_cache directly, bypassing HTTP, so packages_info_batch
    and package_versions use cached data without network calls.
    """

    class MockHelper:
        def set_response(self, name: str, data: dict):
            pypi_api._raw_cache[name] = data

        def clear(self):
            pypi_api._raw_cache.clear()

    return MockHelper()


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
# Test packages_info_batch
# ============================================================================


class TestPackageInfosBatch:
    """Test packages_info_batch() method."""

    def test_returns_mapping_of_name_to_package(self, pypi_api):
        """Batch result maps each name to a Package instance."""
        raw = {
            "requests": {
                "info": {
                    "name": "requests",
                    "version": "2.31.0",
                    "project_urls": {},
                    "author": "Kenneth Reitz",
                    "home_page": "https://requests.readthedocs.io",
                    "summary": "HTTP for Humans",
                    "package_url": "https://pypi.org/project/requests/",
                    "license": "Apache 2.0",
                },
                "releases": {},
            }
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([raw])):
            result = pypi_api.packages_info_batch(["requests"])

        assert "requests" in result
        assert result["requests"].name == "requests"
        assert result["requests"].latest_version == "2.31.0"

    def test_raises_for_missing_package(self, pypi_api):
        """UnableLoadPackage is raised when a requested name is absent from the response."""
        with patch.object(BatchClient, "run_batch", return_value=iter([])):
            with pytest.raises(UnableLoadPackage):
                pypi_api.packages_info_batch(["missing-pkg"])

    def test_uses_raw_cache_to_avoid_refetch(self, pypi_api):
        """Names already in _raw_cache are not passed to run_batch."""
        pypi_api._raw_cache["cached-pkg"] = {
            "info": {
                "name": "cached-pkg",
                "version": "1.0.0",
                "project_urls": {},
                "author": None,
                "home_page": None,
                "summary": None,
                "package_url": None,
                "license": None,
            },
            "releases": {},
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([])) as mock_run:
            result = pypi_api.packages_info_batch(["cached-pkg"])

        mock_run.assert_called_once_with([])
        assert result["cached-pkg"].latest_version == "1.0.0"


# ============================================================================
# Test package_versions (integration + yanked + legacy filtering)
# ============================================================================


class TestPackageVersions:
    """Test package versions retrieval with filtering."""

    def test_filters_legacy_versions(self, pypi_api, mock_pypi_response):
        """Legacy versions should be filtered out silently."""
        mock_pypi_response.set_response(
            "test-package",
            {
                "info": {
                    "name": "test-package",
                    "version": "1.0.0",
                    "requires_dist": [],
                    "license": None,
                    "summary": None,
                },
                "releases": {
                    "1.0.0": [{"upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": False}],
                    "0.1dev-r1716": [{"upload_time_iso_8601": "2011-01-01T00:00:00Z", "yanked": False}],
                },
            },
        )

        versions = list(pypi_api.package_versions("test-package"))

        # Should only include valid version, not legacy
        assert len(versions) == 1
        assert versions[0].version == "1.0.0"

    def test_handles_yanked_versions(self, pypi_api, mock_pypi_response):
        """Yanked versions should be marked as not published."""
        mock_pypi_response.set_response(
            "test-package",
            {
                "info": {
                    "name": "test-package",
                    "version": "2.0.0",
                    "requires_dist": [],
                    "license": None,
                    "summary": None,
                },
                "releases": {
                    "2.0.0": [{"upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": False}],
                    "1.0.0": [{"upload_time_iso_8601": "2022-01-01T00:00:00Z", "yanked": True}],
                },
            },
        )

        versions = list(pypi_api.package_versions("test-package"))

        # Both versions should be included
        assert len(versions) == 2

        # Find the yanked version
        yanked_version = next(v for v in versions if v.version == "1.0.0")
        assert yanked_version.is_yanked is True

        # Find the non-yanked version
        published_version = next(v for v in versions if v.version == "2.0.0")
        assert published_version.is_yanked is False

    def test_skips_empty_release_files(self, pypi_api, mock_pypi_response):
        """Versions with no files should be skipped."""
        mock_pypi_response.set_response(
            "test-package",
            {
                "info": {
                    "name": "test-package",
                    "version": "1.0.0",
                    "requires_dist": [],
                    "license": None,
                    "summary": None,
                },
                "releases": {
                    "1.0.0": [{"upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": False}],
                    "0.9.0": [],  # No files
                },
            },
        )

        versions = list(pypi_api.package_versions("test-package"))

        # Should only include version with files
        assert len(versions) == 1
        assert versions[0].version == "1.0.0"

    def test_includes_dependencies_for_latest_version(self, pypi_api, mock_pypi_response):
        """Latest version should have dependencies populated."""
        mock_pypi_response.set_response(
            "test-package",
            {
                "info": {
                    "name": "test-package",
                    "version": "2.0.0",
                    "requires_dist": ["requests>=2.0.0", "urllib3"],
                    "license": None,
                    "summary": None,
                },
                "releases": {
                    "2.0.0": [{"upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": False}],
                    "1.0.0": [{"upload_time_iso_8601": "2022-01-01T00:00:00Z", "yanked": False}],
                },
            },
        )

        versions = list(pypi_api.package_versions("test-package"))

        latest = next(v for v in versions if v.version == "2.0.0")
        assert "requests>=2.0.0" in latest.declared_dependencies
        assert "urllib3" in latest.declared_dependencies

        # Older versions don't have dependencies (PyPI API limitation)
        older = next(v for v in versions if v.version == "1.0.0")
        assert len(older.declared_dependencies) == 0

    def test_all_files_yanked_marks_version_unpublished(self, pypi_api, mock_pypi_response):
        """If all files are yanked, version should be unpublished."""
        mock_pypi_response.set_response(
            "test-package",
            {
                "info": {
                    "name": "test-package",
                    "version": "1.0.0",
                    "requires_dist": [],
                    "license": None,
                    "summary": None,
                },
                "releases": {
                    "1.0.0": [
                        {"upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": True},
                        {"upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": True},
                    ]
                },
            },
        )

        versions = list(pypi_api.package_versions("test-package"))

        assert len(versions) == 1
        assert versions[0].is_yanked is True

    @pytest.mark.parametrize(
        "version_str, expected",
        [
            ("1.2.3", False),
            ("1.2.3rc1", True),
            ("1.2.3a1", True),
            ("1.2.3b2", True),
            ("1.2.3.dev1", True),
            ("1.2.3.post1", False),
        ],
    )
    def test_prerelease_flag(self, pypi_api, mock_pypi_response, version_str, expected):
        """is_prerelease is set correctly for PEP 440 prerelease and stable versions."""
        mock_pypi_response.set_response(
            "test-pkg",
            {
                "info": {
                    "name": "test-pkg",
                    "version": version_str,
                    "requires_dist": [],
                    "license": None,
                    "summary": None,
                },
                "releases": {
                    version_str: [{"upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": False}],
                },
            },
        )

        versions = list(pypi_api.package_versions("test-pkg"))
        assert len(versions) == 1
        assert versions[0].is_prerelease is expected

    def test_partial_yanked_files_keeps_version_published(self, pypi_api, mock_pypi_response):
        """If some files are not yanked, version should remain published."""
        mock_pypi_response.set_response(
            "test-package",
            {
                "info": {
                    "name": "test-package",
                    "version": "1.0.0",
                    "requires_dist": [],
                    "license": None,
                    "summary": None,
                },
                "releases": {
                    "1.0.0": [
                        {"upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": True},
                        {"upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": False},
                    ]
                },
            },
        )

        versions = list(pypi_api.package_versions("test-package"))

        assert len(versions) == 1
        assert versions[0].is_yanked is False


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


class TestExtractLicenseFromClassifiers:
    """Test extract_license_from_classifiers() helper."""

    def test_returns_none_for_empty_list(self):
        assert extract_license_from_classifiers([]) is None

    def test_returns_none_for_unrecognized_classifier(self):
        assert extract_license_from_classifiers(["License :: OSI Approved :: Unknown Exotic License"]) is None

    def test_returns_none_when_no_license_classifier(self):
        assert extract_license_from_classifiers(["Programming Language :: Python :: 3"]) is None

    def test_maps_mit(self):
        assert extract_license_from_classifiers(["License :: OSI Approved :: MIT License"]) == "MIT"

    def test_maps_apache(self):
        result = extract_license_from_classifiers(["License :: OSI Approved :: Apache Software License"])
        assert result == "Apache-2.0"

    def test_maps_gpl_v2(self):
        result = extract_license_from_classifiers(["License :: OSI Approved :: GNU General Public License v2 (GPLv2)"])
        assert result == "GPL-2.0-only"

    def test_maps_gpl_v3(self):
        result = extract_license_from_classifiers(["License :: OSI Approved :: GNU General Public License v3 (GPLv3)"])
        assert result == "GPL-3.0-only"

    def test_maps_isc(self):
        assert extract_license_from_classifiers(["License :: OSI Approved :: ISC License (ISCL)"]) == "ISC"

    def test_returns_first_match_when_multiple_classifiers(self):
        classifiers = [
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "License :: OSI Approved :: Apache Software License",
        ]
        assert extract_license_from_classifiers(classifiers) == "MIT"

    def test_ignores_non_osi_approved_classifiers(self):
        classifiers = ["License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication"]
        assert extract_license_from_classifiers(classifiers) is None


class TestPackageLicenseFromRegistry:
    """Test that Package.license is populated from PyPI classifiers."""

    def test_license_extracted_from_classifiers(self, pypi_api):
        raw = {
            "requests": {
                "info": {
                    "name": "requests",
                    "version": "2.31.0",
                    "project_urls": {},
                    "author": None,
                    "home_page": None,
                    "summary": None,
                    "package_url": None,
                    "classifiers": ["License :: OSI Approved :: Apache Software License"],
                },
                "releases": {},
            }
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([raw])):
            result = pypi_api.packages_info_batch(["requests"])

        assert result["requests"].license == "Apache-2.0"

    def test_license_is_none_when_no_classifier_match(self, pypi_api):
        raw = {
            "mypkg": {
                "info": {
                    "name": "mypkg",
                    "version": "1.0.0",
                    "project_urls": {},
                    "author": None,
                    "home_page": None,
                    "summary": None,
                    "package_url": None,
                    "classifiers": ["Programming Language :: Python :: 3"],
                },
                "releases": {},
            }
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([raw])):
            result = pypi_api.packages_info_batch(["mypkg"])

        assert result["mypkg"].license is None

    def test_license_is_none_when_classifiers_absent(self, pypi_api):
        raw = {
            "mypkg": {
                "info": {
                    "name": "mypkg",
                    "version": "1.0.0",
                    "project_urls": {},
                    "author": None,
                    "home_page": None,
                    "summary": None,
                    "package_url": None,
                },
                "releases": {},
            }
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([raw])):
            result = pypi_api.packages_info_batch(["mypkg"])

        assert result["mypkg"].license is None


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
