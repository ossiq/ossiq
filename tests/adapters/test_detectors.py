"""
Tests for detector functions in ossiq.adapters.detectors module.

This module tests the detection logic for identifying repository providers
based on URL patterns.
"""

import pytest

from ossiq.adapters.detectors import detect_source_code_provider
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
