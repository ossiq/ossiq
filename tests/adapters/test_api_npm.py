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

from unittest.mock import patch

import pytest
import semver

from ossiq.adapters.api_npm import PackageRegistryApiNpm, is_npm_prerelease
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


@pytest.fixture
def npm_api():
    """Fixture providing a PackageRegistryApiNpm instance."""
    settings = Settings()
    return PackageRegistryApiNpm(settings)


@pytest.fixture
def mock_npm_response(npm_api):
    """
    Fixture to mock NPM registry API responses via _raw_cache.

    Populates _raw_cache directly, bypassing HTTP, so packages_info_batch
    and package_versions use cached data without network calls.
    """

    class MockHelper:
        def set_response(self, name: str, data: dict):
            npm_api._raw_cache[name] = data

        def clear(self):
            npm_api._raw_cache.clear()

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


class TestPackageInfosBatch:
    """
    Test suite for packages_info_batch() method.

    Tests fetching a batch of packages from NPM registry.
    """

    def test_returns_mapping_of_name_to_package(self, npm_api):
        """Batch result maps each name to a Package instance."""
        raw = {
            "test-package": {
                "name": "test-package",
                "dist-tags": {"latest": "1.0.0"},
                "description": "A test package",
            }
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([raw])):
            result = npm_api.packages_info_batch(["test-package"])

        assert "test-package" in result
        assert result["test-package"].name == "test-package"
        assert result["test-package"].latest_version == "1.0.0"

    def test_raises_for_missing_package(self, npm_api):
        """UnableLoadPackage is raised when a requested name is absent from the response."""
        with patch.object(BatchClient, "run_batch", return_value=iter([])):
            with pytest.raises(UnableLoadPackage):
                npm_api.packages_info_batch(["missing-pkg"])

    def test_uses_raw_cache_to_avoid_refetch(self, npm_api):
        """Names already in _raw_cache are not passed to run_batch."""
        npm_api._raw_cache["cached-pkg"] = {
            "name": "cached-pkg",
            "dist-tags": {"latest": "2.0.0"},
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([])) as mock_run:
            result = npm_api.packages_info_batch(["cached-pkg"])

        mock_run.assert_called_once_with([])
        assert result["cached-pkg"].latest_version == "2.0.0"

    def test_multiple_packages(self, npm_api):
        """Multiple packages are all returned in one call."""
        raw = {
            "pkg-a": {"name": "pkg-a", "dist-tags": {"latest": "1.0.0"}},
            "pkg-b": {"name": "pkg-b", "dist-tags": {"latest": "2.0.0"}},
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([raw])):
            result = npm_api.packages_info_batch(["pkg-a", "pkg-b"])

        assert set(result.keys()) == {"pkg-a", "pkg-b"}


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
            "test-package",
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
            "prerelease-pkg",
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
            "stable-pkg",
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
            "minimal-pkg",
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
            "simple-pkg",
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
        assert versions[0].is_unpublished is False
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
        is_unpublished=True and include unpublished timestamp.
        """
        mock_npm_response.set_response(
            "unpublished-pkg",
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
            assert version.is_unpublished is True
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
            "prerelease-pkg",
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
        assert stable.is_unpublished is False
        assert stable.is_prerelease is False

        # Verify prerelease versions
        alpha = next(v for v in versions if "alpha" in v.version)
        beta = next(v for v in versions if "beta" in v.version)
        rc = next(v for v in versions if "rc" in v.version)

        for prerelease in [alpha, beta, rc]:
            assert "-" in prerelease.version  # Prerelease indicator
            assert prerelease.is_unpublished is False
            assert prerelease.is_prerelease is True
            assert prerelease.declared_dependencies == {"new-dep": "^1.0.0"}

    def test_package_versions_dev_dependencies(self, npm_api, mock_npm_response):
        """
        Test extraction of dev dependencies.

        Verifies that devDependencies are correctly extracted separately
        from regular dependencies.
        """
        mock_npm_response.set_response(
            "dev-deps-pkg",
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
        mock_npm_response.set_response("empty-pkg", {"name": "empty-pkg", "versions": {}, "time": {}})

        versions = list(npm_api.package_versions("empty-pkg"))

        assert len(versions) == 0


class TestPackageLicenseFromRegistry:
    """Test that Package.license is populated from the latest version's license field."""

    def test_license_extracted_from_latest_version(self, npm_api):
        raw = {
            "chalk": {
                "name": "chalk",
                "dist-tags": {"latest": "5.3.0"},
                "versions": {
                    "5.3.0": {"license": "MIT"},
                    "5.2.0": {"license": "MIT"},
                },
            }
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([raw])):
            result = npm_api.packages_info_batch(["chalk"])

        assert result["chalk"].license == "MIT"

    def test_license_is_none_when_version_missing_license(self, npm_api):
        raw = {
            "mypkg": {
                "name": "mypkg",
                "dist-tags": {"latest": "1.0.0"},
                "versions": {
                    "1.0.0": {"dependencies": {}},
                },
            }
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([raw])):
            result = npm_api.packages_info_batch(["mypkg"])

        assert result["mypkg"].license is None

    def test_license_is_none_when_no_versions(self, npm_api):
        raw = {
            "mypkg": {
                "name": "mypkg",
                "dist-tags": {"latest": "1.0.0"},
                "versions": {},
            }
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([raw])):
            result = npm_api.packages_info_batch(["mypkg"])

        assert result["mypkg"].license is None


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


# ============================================================================
# Test deprecation flags
# ============================================================================


class TestPackageDeprecation:
    """Tests for is_deprecated on PackageVersion and Package."""

    def test_version_with_deprecated_message_is_deprecated(self, npm_api, mock_npm_response):
        mock_npm_response.set_response(
            "dep-pkg",
            {
                "name": "dep-pkg",
                "dist-tags": {"latest": "1.0.0"},
                "versions": {
                    "1.0.0": {
                        "version": "1.0.0",
                        "license": "MIT",
                        "dependencies": {},
                        "deprecated": "Use new-pkg instead",
                    },
                    "0.9.0": {
                        "version": "0.9.0",
                        "license": "MIT",
                        "dependencies": {},
                    },
                },
                "time": {
                    "0.9.0": "2019-01-01T00:00:00.000Z",
                    "1.0.0": "2020-01-01T00:00:00.000Z",
                },
            },
        )

        versions = list(npm_api.package_versions("dep-pkg"))
        v100 = next(v for v in versions if v.version == "1.0.0")
        v090 = next(v for v in versions if v.version == "0.9.0")

        assert v100.is_deprecated is True
        assert v090.is_deprecated is False

    def test_version_with_empty_deprecated_field_is_not_deprecated(self, npm_api, mock_npm_response):
        mock_npm_response.set_response(
            "empty-dep-pkg",
            {
                "name": "empty-dep-pkg",
                "dist-tags": {"latest": "1.0.0"},
                "versions": {
                    "1.0.0": {
                        "version": "1.0.0",
                        "license": "MIT",
                        "dependencies": {},
                        "deprecated": "",
                    },
                },
                "time": {"1.0.0": "2020-01-01T00:00:00.000Z"},
            },
        )

        versions = list(npm_api.package_versions("empty-dep-pkg"))
        assert versions[0].is_deprecated is False

    def test_package_is_deprecated_when_latest_version_deprecated(self, npm_api):
        raw = {
            "dep-whole-pkg": {
                "name": "dep-whole-pkg",
                "dist-tags": {"latest": "2.0.0"},
                "versions": {
                    "1.0.0": {"license": "MIT", "dependencies": {}},
                    "2.0.0": {"license": "MIT", "dependencies": {}, "deprecated": "Use other-pkg instead"},
                },
            }
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([raw])):
            result = npm_api.packages_info_batch(["dep-whole-pkg"])

        assert result["dep-whole-pkg"].is_deprecated is True

    def test_package_is_not_deprecated_when_latest_version_not_deprecated(self, npm_api):
        raw = {
            "normal-pkg": {
                "name": "normal-pkg",
                "dist-tags": {"latest": "1.0.0"},
                "versions": {
                    "1.0.0": {"license": "MIT", "dependencies": {}},
                },
            }
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([raw])):
            result = npm_api.packages_info_batch(["normal-pkg"])

        assert result["normal-pkg"].is_deprecated is False


class TestPackageUnpublished:
    """Tests for Package.is_unpublished (entire-package unpublish)."""

    def test_package_is_unpublished_when_time_unpublished_present(self, npm_api):
        raw = {
            "gone-pkg": {
                "name": "gone-pkg",
                "dist-tags": {},
                "versions": {},
                "time": {
                    "unpublished": {
                        "time": "2021-06-01T00:00:00.000Z",
                        "versions": ["1.0.0"],
                    }
                },
            }
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([raw])):
            result = npm_api.packages_info_batch(["gone-pkg"])

        assert result["gone-pkg"].is_unpublished is True

    def test_package_is_not_unpublished_for_normal_package(self, npm_api):
        raw = {
            "live-pkg": {
                "name": "live-pkg",
                "dist-tags": {"latest": "1.0.0"},
                "versions": {"1.0.0": {"license": "MIT", "dependencies": {}}},
                "time": {"1.0.0": "2020-01-01T00:00:00.000Z"},
            }
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([raw])):
            result = npm_api.packages_info_batch(["live-pkg"])

        assert result["live-pkg"].is_unpublished is False


class TestIndividuallyDeletedVersions:
    """Tests for versions present in time but absent from versions dict (individual unpublish)."""

    def test_individually_deleted_version_is_marked_unpublished(self, npm_api, mock_npm_response):
        mock_npm_response.set_response(
            "partial-pkg",
            {
                "name": "partial-pkg",
                "dist-tags": {"latest": "1.1.0"},
                "versions": {
                    "1.1.0": {"version": "1.1.0", "license": "MIT", "dependencies": {}},
                },
                "time": {
                    "1.0.0": "2019-06-01T00:00:00.000Z",
                    "1.1.0": "2020-01-01T00:00:00.000Z",
                },
            },
        )

        versions = list(npm_api.package_versions("partial-pkg"))
        deleted = next(v for v in versions if v.version == "1.0.0")
        live = next(v for v in versions if v.version == "1.1.0")

        assert deleted.is_unpublished is True
        assert deleted.published_date_iso == "2019-06-01T00:00:00.000Z"
        assert live.is_unpublished is False

    def test_created_and_modified_keys_are_not_treated_as_versions(self, npm_api, mock_npm_response):
        mock_npm_response.set_response(
            "meta-keys-pkg",
            {
                "name": "meta-keys-pkg",
                "dist-tags": {"latest": "1.0.0"},
                "versions": {
                    "1.0.0": {"version": "1.0.0", "license": "MIT", "dependencies": {}},
                },
                "time": {
                    "created": "2019-01-01T00:00:00.000Z",
                    "modified": "2020-01-01T00:00:00.000Z",
                    "1.0.0": "2020-01-01T00:00:00.000Z",
                },
            },
        )

        versions = list(npm_api.package_versions("meta-keys-pkg"))

        assert len(versions) == 1
        assert versions[0].version == "1.0.0"

    def test_non_semver_time_key_is_skipped(self, npm_api, mock_npm_response):
        mock_npm_response.set_response(
            "noise-pkg",
            {
                "name": "noise-pkg",
                "dist-tags": {"latest": "1.0.0"},
                "versions": {
                    "1.0.0": {"version": "1.0.0", "license": "MIT", "dependencies": {}},
                },
                "time": {
                    "1.0": "2019-06-01T00:00:00.000Z",
                    "1.0.0": "2020-01-01T00:00:00.000Z",
                },
            },
        )

        versions = list(npm_api.package_versions("noise-pkg"))
        version_strings = [v.version for v in versions]

        assert "1.0" not in version_strings
        assert "1.0.0" in version_strings


# ============================================================================
# Test is_npm_prerelease helper
# ============================================================================


class TestIsNpmPrerelease:
    """Test the is_npm_prerelease() module-level helper."""

    @pytest.mark.parametrize(
        "version_str, expected",
        [
            ("1.2.3", False),
            ("1.2.3-beta.1", True),
            ("1.2.3-rc.1", True),
            ("1.2.3-0", True),
            ("2.0.0-alpha.1", True),
            ("1.0", False),  # non-strict semver: fallback to stable
        ],
    )
    def test_prerelease_detection(self, version_str, expected):
        assert is_npm_prerelease(version_str) is expected
