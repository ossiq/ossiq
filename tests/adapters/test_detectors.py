# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for detector functions in ossiq.adapters.detectors module.

This module tests the detection logic for identifying repository providers
based on URL patterns.
"""

import pytest

from ossiq.adapters.detectors import (
    detect_source_code_provider,
    is_git_hosted_source,
    is_github_url,
    is_repository_root_url,
)
from ossiq.domain.common import RepositoryProvider, UnsupportedRepositoryProvider


class TestDetectSourceCodeProvider:
    """
    Test suite for detect_source_code_provider() function.

    Tests URL pattern matching for various repository providers,
    including different URL formats (HTTPS, SSH) and error handling
    for unsupported providers.
    """

    def test_github_https_url(self):
        """
        Test GitHub detection with HTTPS URL format.

        Verifies that standard GitHub HTTPS URLs (https://github.com/...)
        are correctly identified as GitHub provider.
        """
        provider = detect_source_code_provider("https://github.com/owner/repo")
        assert provider == RepositoryProvider.PROVIDER_GITHUB

    def test_github_ssh_url(self):
        """
        Test GitHub detection with SSH URL format.

        Verifies that GitHub SSH URLs (git@github.com:...)
        are correctly identified as GitHub provider.
        """
        provider = detect_source_code_provider("git@github.com:owner/repo.git")
        assert provider == RepositoryProvider.PROVIDER_GITHUB

    def test_github_https_with_trailing_slash(self):
        """
        Test GitHub detection with trailing slash in URL.

        Verifies that URLs with trailing slashes are handled correctly.
        """
        provider = detect_source_code_provider("https://github.com/owner/repo/")
        assert provider == RepositoryProvider.PROVIDER_GITHUB

    def test_github_https_with_git_extension(self):
        """
        Test GitHub detection with .git extension in HTTPS URL.

        Verifies that HTTPS URLs with .git extension are correctly identified.
        """
        provider = detect_source_code_provider("https://github.com/owner/repo.git")
        assert provider == RepositoryProvider.PROVIDER_GITHUB

    def test_unsupported_gitlab_url(self):
        """
        Test error handling for unsupported GitLab provider.

        Verifies that GitLab URLs raise UnsupportedRepositoryProvider exception
        with appropriate error message.
        """
        with pytest.raises(UnsupportedRepositoryProvider) as excinfo:
            detect_source_code_provider("https://gitlab.com/owner/repo")
        assert "Unknown repository provider for the URL: https://gitlab.com/owner/repo" in str(excinfo.value)

    def test_unsupported_bitbucket_url(self):
        """
        Test error handling for unsupported Bitbucket provider.

        Verifies that Bitbucket URLs raise UnsupportedRepositoryProvider exception.
        """
        with pytest.raises(UnsupportedRepositoryProvider) as excinfo:
            detect_source_code_provider("https://bitbucket.org/owner/repo")
        assert "Unknown repository provider for the URL: https://bitbucket.org/owner/repo" in str(excinfo.value)

    def test_unsupported_custom_git_server(self):
        """
        Test error handling for custom/unknown Git servers.

        Verifies that URLs from unknown Git providers raise appropriate exception.
        """
        with pytest.raises(UnsupportedRepositoryProvider) as excinfo:
            detect_source_code_provider("https://git.example.com/owner/repo")
        assert "Unknown repository provider for the URL" in str(excinfo.value)

    def test_unsupported_ssh_gitlab(self):
        """
        Test error handling for GitLab SSH URLs.

        Verifies that GitLab SSH URLs are correctly identified as unsupported.
        """
        with pytest.raises(UnsupportedRepositoryProvider) as excinfo:
            detect_source_code_provider("git@gitlab.com:owner/repo.git")
        assert "Unknown repository provider for the URL" in str(excinfo.value)

    def test_undefined_repository(self):
        """
        This is exceptional case when there's no repository
        specified (possible) for a package.
        """

        provider = detect_source_code_provider(None)
        assert provider == RepositoryProvider.PROVIDER_UNKNOWN


class TestIsGitHostedSource:
    """Test suite for is_git_hosted_source() — detecting non-registry npm deps."""

    @pytest.mark.parametrize(
        "spec",
        [
            "github:owner/repo#v1.0.0",
            "owner/repo#semver:^20",
            "owner/repo",
            "git+https://github.com/owner/repo.git",
            "git+ssh://git@github.com/owner/repo.git",
            "git://github.com/owner/repo.git",
            "https://example.com/foo.tgz",
            "file:../local-pkg",
            "gitlab:owner/repo",
        ],
    )
    def test_git_hosted_spec_detected(self, spec: str) -> None:
        assert is_git_hosted_source(spec, None) is True

    @pytest.mark.parametrize(
        "spec",
        ["^1.2.3", "~4.0.0", "1.2.3", "*", "latest", ">=1.0.0 <2.0.0", "npm:chalk@^4.1.0"],
    )
    def test_registry_spec_not_detected(self, spec: str) -> None:
        assert is_git_hosted_source(spec, None) is False

    def test_lockfile_git_source_detected(self) -> None:
        assert is_git_hosted_source("*", "git+ssh://git@github.com/owner/repo.git#abc123") is True

    def test_registry_source_not_detected(self) -> None:
        assert is_git_hosted_source("^4.17.21", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz") is False

    def test_none_spec_and_source_not_detected(self) -> None:
        assert is_git_hosted_source(None, None) is False


class TestIsGithubUrl:
    """URL host test shared by the fetch filter, the coverage panel, and PyPI repo discovery."""

    def test_https_github_url(self) -> None:
        assert is_github_url("https://github.com/owner/repo") is True

    def test_git_prefixed_url(self) -> None:
        # npm's `repository.url` shape; urlparse still reports github.com as the host.
        assert is_github_url("git+https://github.com/janl/mustache.js.git") is True

    def test_subdomain_is_not_github(self) -> None:
        # gist. and raw.githubusercontent. serve neither the commits nor the activity API, so
        # treating them as GitHub would promise data no fetch can deliver.
        assert is_github_url("https://gist.github.com/owner/abc123") is False

    def test_other_hosts(self) -> None:
        assert is_github_url("https://gitlab.com/owner/repo") is False
        assert is_github_url("https://codeberg.org/owner/repo") is False

    def test_missing_url(self) -> None:
        assert is_github_url(None) is False
        assert is_github_url("") is False


class TestIsRepositoryRootUrl:
    def test_repository_root(self) -> None:
        assert is_repository_root_url("https://github.com/Textualize/rich") is True

    def test_trailing_slash_is_still_the_root(self) -> None:
        assert is_repository_root_url("https://github.com/Textualize/rich/") is True

    def test_sub_pages_are_not_the_repository(self) -> None:
        # The depth check is what makes scanning every project_urls entry safe: a project's
        # Issues/Releases/Changelog links share the host but are not something /repos can answer.
        for path in ("issues", "releases", "blob/main/README.md"):
            assert is_repository_root_url(f"https://github.com/owner/repo/{path}") is False

    def test_owner_page_is_not_a_repository(self) -> None:
        assert is_repository_root_url("https://github.com/owner") is False

    def test_non_github_host(self) -> None:
        assert is_repository_root_url("https://gitlab.com/owner/repo") is False
