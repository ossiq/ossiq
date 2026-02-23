# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for PackageRegistryApiNpm in ossiq.adapters.api_npm module.

This module tests the NPM registry adapter implementation, including:
- Semantic versioning validation and comparison
- Version difference calculation (major, minor, patch, prerelease, build)
- Package info and version retrieval
- Unpublished packages handling
- Prerelease versions handling
"""

import pytest
import semver

from ossiq.adapters.api_npm import PackageRegistryApiNpm
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


@pytest.fixture
def npm_api():
    """Fixture providing a PackageRegistryApiNpm instance."""
    settings = Settings()
    return PackageRegistryApiNpm(settings)


@pytest.fixture
def mock_npm_response(monkeypatch):
    """
    Fixture to mock NPM registry API responses.

    Provides a helper class to set up mock responses for package info
    and versions endpoints.
    """
    responses = {}

    def mock_make_request(self, path: str, headers=None, timeout=15):
        if path in responses:
            return responses[path]
        raise ValueError(f"No mock response for path: {path}")

    monkeypatch.setattr(PackageRegistryApiNpm, "_make_request", mock_make_request)

    class MockHelper:
        def set_response(self, path, data):
            responses[path] = data

        def clear(self):
            responses.clear()

    return MockHelper()


class TestCompareVersions:
    """
    Test suite for compare_versions() static method.

    Tests semantic version comparison following NPM's semver rules.
    """

    def test_compare_equal_versions(self):
        """
        Test comparison of identical versions.

        Verifies that comparing equal versions returns 0.
        """
        assert PackageRegistryApiNpm.compare_versions("1.2.3", "1.2.3") == 0

    def test_compare_v1_less_than_v2(self):
        """
        Test comparison when first version is older.

        Verifies that comparing older version to newer returns -1.
        """
        assert PackageRegistryApiNpm.compare_versions("1.2.3", "1.2.4") == -1

    def test_compare_v1_greater_than_v2(self):
        """
        Test comparison when first version is newer.

        Verifies that comparing newer version to older returns 1.
        """
        assert PackageRegistryApiNpm.compare_versions("2.0.0", "1.9.9") == 1

    def test_compare_prerelease_versions(self):
        """
        Test comparison of prerelease versions.

        Verifies that prerelease versions are correctly ordered before
        their release counterparts.
        """
        assert PackageRegistryApiNpm.compare_versions("1.0.0-alpha", "1.0.0") == -1
        assert PackageRegistryApiNpm.compare_versions("1.0.0", "1.0.0-alpha") == 1

    def test_compare_build_metadata(self):
        """
        Test comparison with build metadata.

        Verifies that build metadata is handled correctly in comparisons.
        """
        # Build metadata should not affect comparison
        assert PackageRegistryApiNpm.compare_versions("1.0.0+build1", "1.0.0+build2") == 0


class TestCalculateSemverDiffIndex:
    """
    Test suite for _calculate_semver_diff_index() private method.

    Tests the internal logic for determining the most significant
    difference between two semver versions.
    """

    def test_major_version_difference(self):
        """Test detection of major version difference."""
        v1 = semver.Version.parse("1.0.0")
        v2 = semver.Version.parse("2.0.0")
        diff = PackageRegistryApiNpm._calculate_semver_diff_index(v1, v2)
        assert diff == VERSION_DIFF_MAJOR

    def test_minor_version_difference(self):
        """Test detection of minor version difference."""
        v1 = semver.Version.parse("1.1.0")
        v2 = semver.Version.parse("1.2.0")
        diff = PackageRegistryApiNpm._calculate_semver_diff_index(v1, v2)
        assert diff == VERSION_DIFF_MINOR

    def test_patch_version_difference(self):
        """Test detection of patch version difference."""
        v1 = semver.Version.parse("1.0.1")
        v2 = semver.Version.parse("1.0.2")
        diff = PackageRegistryApiNpm._calculate_semver_diff_index(v1, v2)
        assert diff == VERSION_DIFF_PATCH

    def test_prerelease_difference(self):
        """Test detection of prerelease difference."""
        v1 = semver.Version.parse("1.0.0-alpha")
        v2 = semver.Version.parse("1.0.0-beta")
        diff = PackageRegistryApiNpm._calculate_semver_diff_index(v1, v2)
        assert diff == VERSION_DIFF_PRERELEASE

    def test_build_metadata_difference(self):
        """Test detection of build metadata difference."""
        v1 = semver.Version.parse("1.0.0+build1")
        v2 = semver.Version.parse("1.0.0+build2")
        diff = PackageRegistryApiNpm._calculate_semver_diff_index(v1, v2)
        assert diff == VERSION_DIFF_BUILD

    def test_no_difference(self):
        """Test when versions are identical."""
        v1 = semver.Version.parse("1.0.0")
        v2 = semver.Version.parse("1.0.0")
        diff = PackageRegistryApiNpm._calculate_semver_diff_index(v1, v2)
        assert diff == VERSION_NO_DIFF


class TestDifferenceVersions:
    """
    Test suite for difference_versions() static method.

    Tests version difference calculation using semver semantics,
    covering all diff types and edge cases.
    """

    def test_none_versions(self):
        """Test handling of None versions."""
        result = PackageRegistryApiNpm.difference_versions(None, None)
        assert result.version1 == "N/A"
        assert result.version2 == "N/A"
        assert result.diff_index == VERSION_NO_DIFF
        assert result.diff_name == "NO_DIFF"

    def test_empty_string_versions(self):
        """Test handling of empty string versions."""
        result = PackageRegistryApiNpm.difference_versions("", "")
        assert result.version1 == "N/A"
        assert result.version2 == "N/A"
        assert result.diff_index == VERSION_NO_DIFF

    def test_one_none_version(self):
        """Test handling when only one version is None."""
        result = PackageRegistryApiNpm.difference_versions("1.0.0", None)
        assert result.diff_index == VERSION_NO_DIFF

    def test_identical_versions(self):
        """Test that identical versions are detected before parsing."""
        result = PackageRegistryApiNpm.difference_versions("1.2.3", "1.2.3")
        assert result.version1 == "1.2.3"
        assert result.version2 == "1.2.3"
        assert result.diff_index == VERSION_LATEST
        assert result.diff_name == "LATEST"

    def test_major_version_diff(self):
        """Test major version difference detection."""
        result = PackageRegistryApiNpm.difference_versions("1.0.0", "2.0.0")
        assert result.diff_index == VERSION_DIFF_MAJOR
        assert result.diff_name == "DIFF_MAJOR"

    def test_minor_version_diff(self):
        """Test minor version difference detection."""
        result = PackageRegistryApiNpm.difference_versions("1.1.0", "1.2.0")
        assert result.diff_index == VERSION_DIFF_MINOR
        assert result.diff_name == "DIFF_MINOR"

    def test_patch_version_diff(self):
        """Test patch version difference detection."""
        result = PackageRegistryApiNpm.difference_versions("1.0.1", "1.0.2")
        assert result.diff_index == VERSION_DIFF_PATCH
        assert result.diff_name == "DIFF_PATCH"

    def test_prerelease_diff(self):
        """
        Test prerelease version difference detection.

        Critical test to ensure prerelease versions are not confused
        with latest stable versions.
        """
        result = PackageRegistryApiNpm.difference_versions("1.0.0-alpha", "1.0.0-beta")
        assert result.diff_index == VERSION_DIFF_PRERELEASE
        assert result.diff_name == "DIFF_PRERELEASE"

    def test_prerelease_vs_release(self):
        """
        Test difference between prerelease and stable release.

        Verifies that prerelease versions are correctly distinguished
        from stable releases.
        """
        result = PackageRegistryApiNpm.difference_versions("1.0.0-rc.1", "1.0.0")
        assert result.diff_index == VERSION_DIFF_PRERELEASE
        assert result.diff_name == "DIFF_PRERELEASE"

    def test_build_metadata_diff(self):
        """Test build metadata difference detection."""
        result = PackageRegistryApiNpm.difference_versions("1.0.0+build1", "1.0.0+build2")
        assert result.diff_index == VERSION_DIFF_BUILD
        assert result.diff_name == "DIFF_BUILD"

    def test_complex_prerelease_versions(self):
        """
        Test complex prerelease version strings.

        Ensures that various prerelease formats (alpha.1, beta.2, rc.3)
        are correctly parsed and compared.
        """
        result = PackageRegistryApiNpm.difference_versions("2.0.0-alpha.1", "2.0.0-alpha.2")
        assert result.diff_index == VERSION_DIFF_PRERELEASE

    def test_version_normalization(self):
        """
        Test that parsed versions are normalized in output.

        Verifies that the output uses normalized version strings.
        """
        result = PackageRegistryApiNpm.difference_versions("1.0.0", "2.0.0")
        assert result.version1 == "1.0.0"
        assert result.version2 == "2.0.0"


class TestPackageInfo:
    """
    Test suite for package_info() method.

    Tests fetching package information from NPM registry,
    including dist-tags (latest, next) and metadata.
    """

    def test_package_info_basic(self, npm_api, mock_npm_response):
        """
        Test basic package info retrieval.

        Verifies that package metadata is correctly extracted from
        NPM registry response.
        """
        mock_npm_response.set_response(
            "/test-package",
            {
                "name": "test-package",
                "description": "A test package",
                "dist-tags": {"latest": "1.0.0", "next": "2.0.0-beta.1"},
                "repository": {"url": "https://github.com/owner/repo"},
                "author": "Test Author",
                "homepage": "https://example.com",
            },
        )

        package = npm_api.package_info("test-package")

        assert package.name == "test-package"
        assert package.description == "A test package"
        assert package.latest_version == "1.0.0"
        assert package.next_version == "2.0.0-beta.1"
        assert package.repo_url == "https://github.com/owner/repo"
        assert package.author == "Test Author"
        assert package.homepage_url == "https://example.com"
        assert package.registry == ProjectPackagesRegistry.NPM
        assert "test-package" in package.package_url

    def test_package_info_with_prerelease_next(self, npm_api, mock_npm_response):
        """
        Test package info with prerelease 'next' tag.

        Verifies that packages with prerelease versions in the 'next'
        dist-tag are correctly handled and distinguished from 'latest'.
        """
        mock_npm_response.set_response(
            "/prerelease-pkg",
            {
                "name": "prerelease-pkg",
                "description": "Package with prerelease",
                "dist-tags": {
                    "latest": "1.5.0",
                    "next": "2.0.0-rc.1",  # Prerelease version
                },
            },
        )

        package = npm_api.package_info("prerelease-pkg")

        assert package.name == "prerelease-pkg"
        assert package.latest_version == "1.5.0"
        assert package.next_version == "2.0.0-rc.1"
        # Verify next is a prerelease
        assert "-" in package.next_version

    def test_package_info_no_next_tag(self, npm_api, mock_npm_response):
        """
        Test package info when 'next' dist-tag is missing.

        Verifies that packages without a 'next' tag still work correctly.
        """
        mock_npm_response.set_response(
            "/stable-pkg",
            {
                "name": "stable-pkg",
                "description": "Stable package only",
                "dist-tags": {"latest": "3.0.0"},
            },
        )

        package = npm_api.package_info("stable-pkg")

        assert package.name == "stable-pkg"
        assert package.latest_version == "3.0.0"
        assert package.next_version is None

    def test_package_info_missing_optional_fields(self, npm_api, mock_npm_response):
        """
        Test package info with missing optional fields.

        Verifies graceful handling when author, homepage, or repository
        are missing from the NPM response.
        """
        mock_npm_response.set_response(
            "/minimal-pkg",
            {
                "name": "minimal-pkg",
                "dist-tags": {"latest": "1.0.0"},
            },
        )

        package = npm_api.package_info("minimal-pkg")

        assert package.name == "minimal-pkg"
        assert package.latest_version == "1.0.0"
        assert package.author is None
        assert package.homepage_url is None
        assert package.repo_url is None


class TestPackageVersions:
    """
    Test suite for package_versions() method.

    Tests fetching version history from NPM registry, including
    published versions, unpublished versions, and dependencies.
    """

    def test_package_versions_basic(self, npm_api, mock_npm_response):
        """
        Test basic version listing.

        Verifies that published versions are correctly extracted with
        their metadata and dependencies.
        """
        mock_npm_response.set_response(
            "/simple-pkg",
            {
                "name": "simple-pkg",
                "versions": {
                    "1.0.0": {
                        "version": "1.0.0",
                        "description": "First release",
                        "license": "MIT",
                        "dependencies": {"lodash": "^4.17.0"},
                        "engines": {"node": ">=14"},
                    },
                    "1.1.0": {
                        "version": "1.1.0",
                        "description": "Second release",
                        "license": "MIT",
                        "dependencies": {"lodash": "^4.17.0", "axios": "^0.21.0"},
                    },
                },
                "time": {
                    "1.0.0": "2020-01-01T00:00:00.000Z",
                    "1.1.0": "2020-02-01T00:00:00.000Z",
                },
            },
        )

        versions = list(npm_api.package_versions("simple-pkg"))

        assert len(versions) == 2
        assert versions[0].version == "1.0.0"
        assert versions[0].is_published is True
        assert versions[0].unpublished_date_iso is None
        assert versions[0].license == "MIT"
        assert versions[0].declared_dependencies == {"lodash": "^4.17.0"}
        assert versions[0].runtime_requirements == {"node": ">=14"}

        assert versions[1].version == "1.1.0"
        assert versions[1].declared_dependencies == {
            "lodash": "^4.17.0",
            "axios": "^0.21.0",
        }

    def test_package_versions_with_unpublished(self, npm_api, mock_npm_response):
        """
        Test handling of unpublished package versions.

        Verifies that unpublished versions are correctly marked with
        is_published=False and include unpublished timestamp.
        """
        mock_npm_response.set_response(
            "/unpublished-pkg",
            {
                "name": "unpublished-pkg",
                "versions": {},
                "time": {
                    "unpublished": {
                        "time": "2021-03-15T10:30:00.000Z",
                        "versions": ["1.0.0", "1.0.1", "1.0.2"],
                    }
                },
            },
        )

        versions = list(npm_api.package_versions("unpublished-pkg"))

        assert len(versions) == 3
        for version in versions:
            assert version.is_published is False
            assert version.unpublished_date_iso == "2021-03-15T10:30:00.000Z"
            assert version.license is None
            assert version.declared_dependencies == {}

        assert versions[0].version == "1.0.0"
        assert versions[1].version == "1.0.1"
        assert versions[2].version == "1.0.2"

    def test_package_versions_with_prerelease(self, npm_api, mock_npm_response):
        """
        Test handling of prerelease versions.

        Verifies that prerelease versions (alpha, beta, rc) are correctly
        processed and not confused with stable releases.
        """
        mock_npm_response.set_response(
            "/prerelease-pkg",
            {
                "name": "prerelease-pkg",
                "versions": {
                    "1.0.0": {
                        "version": "1.0.0",
                        "license": "MIT",
                        "dependencies": {},
                    },
                    "2.0.0-alpha.1": {
                        "version": "2.0.0-alpha.1",
                        "license": "MIT",
                        "dependencies": {"new-dep": "^1.0.0"},
                    },
                    "2.0.0-beta.1": {
                        "version": "2.0.0-beta.1",
                        "license": "MIT",
                        "dependencies": {"new-dep": "^1.0.0"},
                    },
                    "2.0.0-rc.1": {
                        "version": "2.0.0-rc.1",
                        "license": "MIT",
                        "dependencies": {"new-dep": "^1.0.0"},
                    },
                },
                "time": {
                    "1.0.0": "2020-01-01T00:00:00.000Z",
                    "2.0.0-alpha.1": "2020-02-01T00:00:00.000Z",
                    "2.0.0-beta.1": "2020-03-01T00:00:00.000Z",
                    "2.0.0-rc.1": "2020-04-01T00:00:00.000Z",
                },
            },
        )

        versions = list(npm_api.package_versions("prerelease-pkg"))

        assert len(versions) == 4

        # Verify stable version
        stable = next(v for v in versions if v.version == "1.0.0")
        assert "-" not in stable.version
        assert stable.is_published is True

        # Verify prerelease versions
        alpha = next(v for v in versions if "alpha" in v.version)
        beta = next(v for v in versions if "beta" in v.version)
        rc = next(v for v in versions if "rc" in v.version)

        for prerelease in [alpha, beta, rc]:
            assert "-" in prerelease.version  # Prerelease indicator
            assert prerelease.is_published is True
            assert prerelease.declared_dependencies == {"new-dep": "^1.0.0"}

    def test_package_versions_dev_dependencies(self, npm_api, mock_npm_response):
        """
        Test extraction of dev dependencies.

        Verifies that devDependencies are correctly extracted separately
        from regular dependencies.
        """
        mock_npm_response.set_response(
            "/dev-deps-pkg",
            {
                "name": "dev-deps-pkg",
                "versions": {
                    "1.0.0": {
                        "version": "1.0.0",
                        "dependencies": {"lodash": "^4.17.0"},
                        "devDependencies": {
                            "jest": "^27.0.0",
                            "eslint": "^8.0.0",
                        },
                    },
                },
                "time": {"1.0.0": "2020-01-01T00:00:00.000Z"},
            },
        )

        versions = list(npm_api.package_versions("dev-deps-pkg"))

        assert len(versions) == 1
        assert versions[0].declared_dependencies == {"lodash": "^4.17.0"}
        assert versions[0].declared_dev_dependencies == {
            "jest": "^27.0.0",
            "eslint": "^8.0.0",
        }

    def test_package_versions_empty_versions(self, npm_api, mock_npm_response):
        """
        Test handling of package with no versions.

        Verifies graceful handling when a package has no published versions.
        """
        mock_npm_response.set_response("/empty-pkg", {"name": "empty-pkg", "versions": {}, "time": {}})

        versions = list(npm_api.package_versions("empty-pkg"))

        assert len(versions) == 0


class TestPackageRegistryApiNpmInit:
    """
    Test suite for PackageRegistryApiNpm initialization and basic properties.

    Tests constructor, string representation, and class attributes.
    """

    def test_initialization(self):
        """Test that the API client initializes correctly."""
        settings = Settings()
        api = PackageRegistryApiNpm(settings)

        assert api.settings == settings
        assert api.package_registry == ProjectPackagesRegistry.NPM

    def test_repr(self, npm_api):
        """Test string representation of the API client."""
        assert repr(npm_api) == "<PackageRegistryApiNpm instance>"

    def test_package_registry_constant(self, npm_api):
        """Test that package_registry attribute is set correctly."""
        assert npm_api.package_registry == ProjectPackagesRegistry.NPM
