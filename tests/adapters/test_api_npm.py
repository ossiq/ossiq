# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for PackageRegistryApiNpm in ossiq.adapters.api_npm module.
"""

from unittest.mock import patch

import pytest

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
    return PackageRegistryApiNpm(Settings())


@pytest.fixture
def mock_npm_response(npm_api):
    class MockHelper:
        def set_response(self, name: str, data: dict):
            npm_api._raw_cache[name] = data

    return MockHelper()


# ============================================================================
# difference_versions
# ============================================================================


class TestDifferenceVersions:
    @pytest.mark.parametrize(
        "v1, v2, expected_diff",
        [
            (None, None, VERSION_NO_DIFF),
            ("1.2.3", None, VERSION_NO_DIFF),
            ("1.2.3", "1.2.3", VERSION_LATEST),
            ("1.0.0", "2.0.0", VERSION_DIFF_MAJOR),
            ("1.1.0", "1.2.0", VERSION_DIFF_MINOR),
            ("1.0.1", "1.0.2", VERSION_DIFF_PATCH),
            ("1.0.0-alpha", "1.0.0-beta", VERSION_DIFF_PRERELEASE),
            ("1.0.0+build1", "1.0.0+build2", VERSION_DIFF_BUILD),
        ],
    )
    def test_diff_index(self, v1, v2, expected_diff):
        result = PackageRegistryApiNpm.difference_versions(v1, v2)
        assert result.diff_index == expected_diff


# ============================================================================
# packages_info_batch / package_info
# ============================================================================


class TestPackageInfosBatch:
    def test_returns_mapping_of_name_to_package(self, npm_api):
        raw = {"pkg": {"name": "pkg", "dist-tags": {"latest": "1.0.0"}}}
        with patch.object(BatchClient, "run_batch", return_value=iter([raw])):
            result = npm_api.packages_info_batch(["pkg"])
        assert result["pkg"].latest_version == "1.0.0"
        assert result["pkg"].registry == ProjectPackagesRegistry.NPM

    def test_raises_for_missing_package(self, npm_api):
        with patch.object(BatchClient, "run_batch", return_value=iter([])):
            with pytest.raises(UnableLoadPackage):
                npm_api.packages_info_batch(["missing"])

    def test_uses_raw_cache_to_avoid_refetch(self, npm_api):
        npm_api._raw_cache["cached"] = {"name": "cached", "dist-tags": {"latest": "2.0.0"}}
        with patch.object(BatchClient, "run_batch", return_value=iter([])) as mock_run:
            result = npm_api.packages_info_batch(["cached"])
        mock_run.assert_called_once_with([])
        assert result["cached"].latest_version == "2.0.0"


class TestPackageInfo:
    def test_basic_metadata(self, npm_api, mock_npm_response):
        mock_npm_response.set_response(
            "pkg",
            {
                "name": "pkg",
                "description": "A test package",
                "dist-tags": {"latest": "1.0.0", "next": "2.0.0-beta.1"},
                "repository": {"url": "https://github.com/owner/repo"},
                "author": "Author",
                "homepage": "https://example.com",
            },
        )
        package = npm_api.package_info("pkg")
        assert package.latest_version == "1.0.0"
        assert package.next_version == "2.0.0-beta.1"
        assert package.repo_url == "https://github.com/owner/repo"
        assert package.description == "A test package"

    def test_missing_optional_fields_return_none(self, npm_api, mock_npm_response):
        mock_npm_response.set_response("pkg", {"name": "pkg", "dist-tags": {"latest": "1.0.0"}})
        package = npm_api.package_info("pkg")
        assert package.author is None
        assert package.homepage_url is None
        assert package.repo_url is None


# ============================================================================
# package_versions
# ============================================================================


class TestPackageVersions:
    def test_published_version_with_metadata(self, npm_api, mock_npm_response):
        mock_npm_response.set_response(
            "pkg",
            {
                "name": "pkg",
                "versions": {
                    "1.0.0": {
                        "license": "MIT",
                        "dependencies": {"lodash": "^4.17.0"},
                        "engines": {"node": ">=14"},
                    },
                },
                "time": {"1.0.0": "2020-01-01T00:00:00.000Z"},
            },
        )
        versions = list(npm_api.package_versions("pkg"))
        assert len(versions) == 1
        assert versions[0].license == "MIT"
        assert versions[0].declared_dependencies == {"lodash": "^4.17.0"}
        assert versions[0].runtime_requirements == {"node": ">=14"}
        assert versions[0].is_unpublished is False

    def test_fully_unpublished_package(self, npm_api, mock_npm_response):
        mock_npm_response.set_response(
            "pkg",
            {
                "name": "pkg",
                "versions": {},
                "time": {
                    "unpublished": {
                        "time": "2021-03-15T10:30:00.000Z",
                        "versions": ["1.0.0", "1.0.1"],
                    }
                },
            },
        )
        versions = list(npm_api.package_versions("pkg"))
        assert len(versions) == 2
        assert all(v.is_unpublished for v in versions)
        assert all(v.unpublished_date_iso == "2021-03-15T10:30:00.000Z" for v in versions)

    def test_prerelease_version_flagged(self, npm_api, mock_npm_response):
        mock_npm_response.set_response(
            "pkg",
            {
                "name": "pkg",
                "versions": {
                    "1.0.0": {"license": "MIT", "dependencies": {}},
                    "2.0.0-alpha.1": {"license": "MIT", "dependencies": {}},
                },
                "time": {
                    "1.0.0": "2020-01-01T00:00:00.000Z",
                    "2.0.0-alpha.1": "2020-02-01T00:00:00.000Z",
                },
            },
        )
        versions = list(npm_api.package_versions("pkg"))
        stable = next(v for v in versions if v.version == "1.0.0")
        pre = next(v for v in versions if v.version == "2.0.0-alpha.1")
        assert stable.is_prerelease is False
        assert pre.is_prerelease is True


# ============================================================================
# license, deprecation, and unpublished flags
# ============================================================================


class TestPackageLicenseAndFlags:
    def test_license_comes_from_latest_version(self, npm_api):
        raw = {
            "pkg": {
                "name": "pkg",
                "dist-tags": {"latest": "2.0.0"},
                "versions": {
                    "1.0.0": {"license": "ISC"},
                    "2.0.0": {"license": "MIT"},
                },
            }
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([raw])):
            result = npm_api.packages_info_batch(["pkg"])
        assert result["pkg"].license == "MIT"

    def test_license_none_when_absent(self, npm_api):
        raw = {
            "pkg": {
                "name": "pkg",
                "dist-tags": {"latest": "1.0.0"},
                "versions": {"1.0.0": {"dependencies": {}}},
            }
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([raw])):
            result = npm_api.packages_info_batch(["pkg"])
        assert result["pkg"].license is None

    def test_deprecated_version_flagged(self, npm_api, mock_npm_response):
        mock_npm_response.set_response(
            "pkg",
            {
                "name": "pkg",
                "dist-tags": {"latest": "1.0.0"},
                "versions": {
                    "1.0.0": {"license": "MIT", "dependencies": {}, "deprecated": "Use new-pkg"},
                    "0.9.0": {"license": "MIT", "dependencies": {}},
                },
                "time": {
                    "0.9.0": "2019-01-01T00:00:00.000Z",
                    "1.0.0": "2020-01-01T00:00:00.000Z",
                },
            },
        )
        versions = list(npm_api.package_versions("pkg"))
        v100 = next(v for v in versions if v.version == "1.0.0")
        v090 = next(v for v in versions if v.version == "0.9.0")
        assert v100.is_deprecated is True
        assert v090.is_deprecated is False

    def test_package_is_unpublished_when_time_key_present(self, npm_api):
        raw = {
            "pkg": {
                "name": "pkg",
                "dist-tags": {},
                "versions": {},
                "time": {"unpublished": {"time": "2021-06-01T00:00:00.000Z", "versions": ["1.0.0"]}},
            }
        }
        with patch.object(BatchClient, "run_batch", return_value=iter([raw])):
            result = npm_api.packages_info_batch(["pkg"])
        assert result["pkg"].is_unpublished is True


# ============================================================================
# individually deleted versions
# ============================================================================


class TestIndividuallyDeletedVersions:
    def test_deleted_version_marked_unpublished(self, npm_api, mock_npm_response):
        mock_npm_response.set_response(
            "pkg",
            {
                "name": "pkg",
                "dist-tags": {"latest": "1.1.0"},
                "versions": {"1.1.0": {"version": "1.1.0", "license": "MIT", "dependencies": {}}},
                "time": {
                    "1.0.0": "2019-06-01T00:00:00.000Z",
                    "1.1.0": "2020-01-01T00:00:00.000Z",
                },
            },
        )
        versions = list(npm_api.package_versions("pkg"))
        deleted = next(v for v in versions if v.version == "1.0.0")
        live = next(v for v in versions if v.version == "1.1.0")
        assert deleted.is_unpublished is True
        assert live.is_unpublished is False

    def test_created_modified_meta_keys_not_treated_as_versions(self, npm_api, mock_npm_response):
        mock_npm_response.set_response(
            "pkg",
            {
                "name": "pkg",
                "dist-tags": {"latest": "1.0.0"},
                "versions": {"1.0.0": {"version": "1.0.0", "license": "MIT", "dependencies": {}}},
                "time": {
                    "created": "2019-01-01T00:00:00.000Z",
                    "modified": "2020-01-01T00:00:00.000Z",
                    "1.0.0": "2020-01-01T00:00:00.000Z",
                },
            },
        )
        versions = list(npm_api.package_versions("pkg"))
        assert len(versions) == 1
        assert versions[0].version == "1.0.0"


# ============================================================================
# helpers
# ============================================================================


class TestIsNpmPrerelease:
    @pytest.mark.parametrize(
        "version_str, expected",
        [
            ("1.2.3", False),
            ("1.2.3-beta.1", True),
            ("1.2.3-rc.1", True),
            ("2.0.0-alpha.1", True),
            ("1.0", False),  # non-strict semver: fallback to stable
        ],
    )
    def test_prerelease_detection(self, version_str, expected):
        assert is_npm_prerelease(version_str) is expected


class TestPackageVersionRequires:
    def test_returns_dependencies_for_known_version(self, npm_api, mock_npm_response):
        mock_npm_response.set_response(
            "lodash",
            {"versions": {"4.17.21": {"dependencies": {"some-dep": "^1.0.0"}}}},
        )
        assert npm_api.package_version_requires("lodash", "4.17.21") == {"some-dep": "^1.0.0"}

    def test_returns_empty_for_unknown_version(self, npm_api, mock_npm_response):
        mock_npm_response.set_response("lodash", {"versions": {}})
        assert npm_api.package_version_requires("lodash", "9.9.9") == {}


class TestRewriteSpecifier:
    @pytest.mark.parametrize(
        "specifier, new_version, expected",
        [
            ("^4.17.0", "4.18.2", "^4.17.0"),  # same-major caret: unchanged (range satisfied)
            ("^4.17.0", "5.0.1", "^5.0.0"),  # new-major caret: bump to ^M.0.0
            ("^0.17.0", "0.18.2", "^0.17.0"),  # zero-major same: unchanged
            ("~4.17.0", "4.17.5", "~4.17.0"),  # tilde: same minor — unchanged (caller bumps lower bound)
            ("~4.17.0", "4.18.2", "~4.18.0"),  # tilde: track new minor
            ("~4.17.0", "5.0.1", "~5.0.0"),  # tilde: new major
            ("4.17.0", "4.18.2", "4.18.2"),  # bare exact: new version
            (None, "4.18.2", "4.18.2"),  # None: exact fallback
            (">=4.0.0 <5.0.0", "5.0.1", "5.0.1"),  # complex range: exact fallback
            ("file:../local", "4.18.2", "4.18.2"),  # file ref: exact fallback
        ],
    )
    def test_rewrite(self, specifier, new_version, expected):
        assert PackageRegistryApiNpm.rewrite_specifier(specifier, new_version) == expected


class TestExtractRepoUrl:
    def test_dict_with_url_key(self):
        data = {"repository": {"type": "git", "url": "https://github.com/owner/repo"}}
        assert PackageRegistryApiNpm.extract_repo_url(data) == "https://github.com/owner/repo"

    def test_plain_string_repository(self):
        data = {"repository": "https://github.com/owner/repo"}
        assert PackageRegistryApiNpm.extract_repo_url(data) == "https://github.com/owner/repo"

    def test_missing_repository_returns_none(self):
        assert PackageRegistryApiNpm.extract_repo_url({}) is None

    def test_dict_without_url_key_returns_none(self):
        data = {"repository": {"type": "git"}}
        assert PackageRegistryApiNpm.extract_repo_url(data) is None
