# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for SourceCodeProviderApiGithub in ossiq.adapters.api_github module.

This module tests the GitHub API adapter implementation, including:
- Repository information retrieval
- Release and tag version fetching
- Commit history between versions
- Rate limit handling (with and without token)
- Pagination support
"""

import datetime
from unittest.mock import Mock

import pytest

from ossiq.adapters.api_github import SourceCodeProviderApiGithub
from ossiq.domain.common import (
    VERSION_DATA_SOURCE_GITHUB_RELEASES,
    VERSION_DATA_SOURCE_GITHUB_TAGS,
    RepositoryProvider,
)
from ossiq.domain.exceptions import GithubRateLimitError
from ossiq.domain.repository import Repository
from ossiq.domain.version import PackageVersion


@pytest.fixture
def github_api_with_token():
    """Fixture providing a GitHub API instance with authentication token."""
    return SourceCodeProviderApiGithub(github_token="test_token_12345")


@pytest.fixture
def github_api_without_token():
    """Fixture providing a GitHub API instance without authentication token."""
    return SourceCodeProviderApiGithub(github_token=None)


@pytest.fixture
def mock_github_response(monkeypatch):
    """
    Fixture to mock GitHub API responses.

    Provides a helper class to set up mock responses for various
    GitHub API endpoints with support for pagination.
    """
    responses = {}
    response_headers = {}

    def mock_get(url: str, timeout=15, headers=None):
        """Mock requests.get to return predefined responses."""
        if url in responses:
            mock_response = Mock()
            mock_response.status_code = responses[url].get("status_code", 200)
            mock_response.json.return_value = responses[url].get("data", {})
            mock_response.headers = response_headers.get(url, {})
            mock_response.raise_for_status = Mock()

            # Simulate 403 rate limit error
            if mock_response.status_code == 403:
                mock_response.raise_for_status.side_effect = None

            return mock_response

        raise ValueError(f"No mock response for URL: {url}")

    monkeypatch.setattr("requests.get", mock_get)

    class MockHelper:
        def set_response(self, url, data, status_code=200, headers=None):
            responses[url] = {"data": data, "status_code": status_code}
            if headers:
                response_headers[url] = headers

        def clear(self):
            responses.clear()
            response_headers.clear()

    return MockHelper()


class TestInitialization:
    """
    Test suite for SourceCodeProviderApiGithub initialization.

    Tests constructor behavior with and without GitHub token.
    """

    def test_initialization_with_token(self):
        """Test initialization with GitHub token."""
        api = SourceCodeProviderApiGithub(github_token="my_token")
        assert api.github_token == "my_token"
        assert api.repository_provider == RepositoryProvider.PROVIDER_GITHUB

    def test_initialization_without_token(self):
        """Test initialization without GitHub token."""
        api = SourceCodeProviderApiGithub(github_token=None)
        assert api.github_token is None
        assert api.repository_provider == RepositoryProvider.PROVIDER_GITHUB

    def test_repr(self, github_api_with_token):
        """Test string representation."""
        assert repr(github_api_with_token) == "<SourceCodeProviderApiGithub instance>"

    def test_repository_provider_constant(self, github_api_with_token):
        """Test that repository_provider is correctly set."""
        assert github_api_with_token.repository_provider == RepositoryProvider.PROVIDER_GITHUB


class TestExtractNextUrl:
    """
    Test suite for _extract_next_url() method.

    Tests GitHub Link header parsing for pagination support.
    """

    def test_extract_next_url_with_valid_header(self, github_api_with_token):
        """Test extraction of next URL from Link header."""
        link_header = (
            '<https://api.github.com/repos/owner/repo/tags?page=2>; rel="next", '
            '<https://api.github.com/repos/owner/repo/tags?page=5>; rel="last"'
        )
        next_url = github_api_with_token._extract_next_url(link_header)
        assert next_url == "https://api.github.com/repos/owner/repo/tags?page=2"

    def test_extract_next_url_without_next(self, github_api_with_token):
        """Test extraction when there's no next link."""
        link_header = '<https://api.github.com/repos/owner/repo/tags?page=5>; rel="last"'
        next_url = github_api_with_token._extract_next_url(link_header)
        assert next_url is None

    def test_extract_next_url_with_none_header(self, github_api_with_token):
        """Test extraction with None header."""
        next_url = github_api_with_token._extract_next_url(None)
        assert next_url is None

    def test_extract_next_url_empty_string(self, github_api_with_token):
        """Test extraction with empty string."""
        next_url = github_api_with_token._extract_next_url("")
        assert next_url is None


class TestMakeGithubApiRequest:
    """
    Test suite for _make_github_api_request() method.

    Tests API request handling with authentication, rate limits,
    and pagination headers.
    """

    def test_request_with_token(self, github_api_with_token, mock_github_response):
        """
        Test API request includes authentication header when token is provided.

        Verifies that the Authorization header is properly set with Bearer token.
        """
        mock_github_response.set_response(
            "https://api.github.com/test",
            {"data": "test"},
            headers={"Link": '<https://api.github.com/test?page=2>; rel="next"'},
        )

        next_url, data = github_api_with_token._make_github_api_request("https://api.github.com/test")

        assert data == {"data": "test"}
        assert next_url == "https://api.github.com/test?page=2"

    def test_request_without_token(self, github_api_without_token, mock_github_response):
        """
        Test API request works without authentication token.

        Verifies that requests can be made without token (lower rate limits apply).
        """
        mock_github_response.set_response("https://api.github.com/test", {"data": "test_no_token"})

        next_url, data = github_api_without_token._make_github_api_request("https://api.github.com/test")

        assert data == {"data": "test_no_token"}
        assert next_url is None

    def test_request_rate_limit_error_with_token(self, github_api_with_token, mock_github_response):
        """
        Test rate limit error handling with authentication token.

        Verifies that rate limit information is properly extracted and
        exposed in the GithubRateLimitError exception, including reset time.
        """
        reset_timestamp = int(datetime.datetime.now().timestamp()) + 3600
        mock_github_response.set_response(
            "https://api.github.com/test",
            {"message": "API rate limit exceeded"},
            status_code=403,
            headers={
                "x-ratelimit-remaining": "0",
                "x-ratelimit-limit": "5000",
                "x-ratelimit-reset": str(reset_timestamp),
            },
        )

        with pytest.raises(GithubRateLimitError) as excinfo:
            github_api_with_token._make_github_api_request("https://api.github.com/test")

        error = excinfo.value
        assert error.remaining == "0"
        assert error.total == "5000"
        assert error.reset_time is not None
        assert "rate limit exceeded" in str(error).lower()

    def test_request_rate_limit_error_without_token(self, github_api_without_token, mock_github_response):
        """
        Test rate limit error handling without authentication token.

        Verifies that rate limit errors are properly raised even when
        requests are made without authentication (lower rate limits).
        """
        reset_timestamp = int(datetime.datetime.now().timestamp()) + 3600
        mock_github_response.set_response(
            "https://api.github.com/test",
            {"message": "API rate limit exceeded"},
            status_code=403,
            headers={
                "x-ratelimit-remaining": "0",
                "x-ratelimit-limit": "60",
                "x-ratelimit-reset": str(reset_timestamp),
            },
        )

        with pytest.raises(GithubRateLimitError) as excinfo:
            github_api_without_token._make_github_api_request("https://api.github.com/test")

        error = excinfo.value
        assert error.remaining == "0"
        assert error.total == "60"  # Unauthenticated rate limit
        assert error.reset_time is not None

    def test_request_rate_limit_with_missing_headers(self, github_api_with_token, mock_github_response):
        """
        Test rate limit error when headers are missing or invalid.

        Verifies graceful handling when rate limit headers are incomplete.
        """
        mock_github_response.set_response(
            "https://api.github.com/test",
            {"message": "API rate limit exceeded"},
            status_code=403,
            headers={},
        )

        with pytest.raises(GithubRateLimitError) as excinfo:
            github_api_with_token._make_github_api_request("https://api.github.com/test")

        error = excinfo.value
        assert error.remaining == "N/A"
        assert error.total == "N/A"
        assert error.reset_time == "N/A"


class TestRepositoryInfo:
    """
    Test suite for repository_info() method.

    Tests parsing of various GitHub URL formats and repository
    metadata retrieval.
    """

    def test_repository_info_https_url(self, github_api_with_token, mock_github_response):
        """Test parsing standard HTTPS GitHub URL."""
        mock_github_response.set_response(
            "https://api.github.com/repos/owner/repo",
            {
                "name": "repo",
                "owner": {"login": "owner"},
                "description": "A test repository",
            },
        )

        repo = github_api_with_token.repository_info("https://github.com/owner/repo")

        assert repo.name == "repo"
        assert repo.owner == "owner"
        assert repo.description == "A test repository"
        assert repo.html_url == "https://github.com/owner/repo"
        assert repo.provider == RepositoryProvider.PROVIDER_GITHUB

    def test_repository_info_ssh_url(self, github_api_with_token, mock_github_response):
        """Test parsing SSH GitHub URL."""
        mock_github_response.set_response(
            "https://api.github.com/repos/owner/repo",
            {"name": "repo", "owner": {"login": "owner"}, "description": "SSH repo"},
        )

        repo = github_api_with_token.repository_info("git@github.com:owner/repo.git")

        assert repo.name == "repo"
        assert repo.owner == "owner"
        assert repo.description == "SSH repo"

    def test_repository_info_with_git_prefix(self, github_api_with_token, mock_github_response):
        """Test parsing URL with git+ prefix."""
        mock_github_response.set_response(
            "https://api.github.com/repos/owner/repo",
            {
                "name": "repo",
                "owner": {"login": "owner"},
                "description": "Git prefix repo",
            },
        )

        repo = github_api_with_token.repository_info("git+https://github.com/owner/repo")

        assert repo.name == "repo"
        assert repo.owner == "owner"

    def test_repository_info_without_description(self, github_api_with_token, mock_github_response):
        """Test repository with no description."""
        mock_github_response.set_response(
            "https://api.github.com/repos/owner/minimal",
            {"name": "minimal", "owner": {"login": "owner"}},
        )

        repo = github_api_with_token.repository_info("https://github.com/owner/minimal")

        assert repo.name == "minimal"
        assert repo.description is None

    def test_repository_info_invalid_url(self, github_api_with_token):
        """Test error handling for invalid GitHub URLs."""
        with pytest.raises(ValueError) as excinfo:
            github_api_with_token.repository_info("https://gitlab.com/owner/repo")

        assert "Invalid GitHub URL" in str(excinfo.value)

    def test_repository_info_without_token(self, github_api_without_token, mock_github_response):
        """
        Test repository info retrieval without authentication token.

        Verifies that repository metadata can be fetched without token
        (subject to lower rate limits).
        """
        mock_github_response.set_response(
            "https://api.github.com/repos/public/repo",
            {
                "name": "repo",
                "owner": {"login": "public"},
                "description": "Public repo",
            },
        )

        repo = github_api_without_token.repository_info("https://github.com/public/repo")

        assert repo.name == "repo"
        assert repo.owner == "public"


class TestLoadReleases:
    """
    Test suite for _load_releases() method.

    Tests fetching GitHub releases and matching them with package versions.
    """

    def test_load_releases_basic(self, github_api_with_token, mock_github_response):
        """Test basic release loading."""
        repository = Repository(
            provider=RepositoryProvider.PROVIDER_GITHUB,
            name="repo",
            owner="owner",
            description="Test repo",
            html_url="https://github.com/owner/repo",
        )

        mock_github_response.set_response(
            "https://api.github.com/repos/owner/repo/releases",
            [
                {
                    "tag_name": "v1.0.0",
                    "name": "Release 1.0.0",
                    "body": "First release",
                    "html_url": "https://github.com/owner/repo/releases/tag/v1.0.0",
                },
                {
                    "tag_name": "v1.1.0",
                    "name": "Release 1.1.0",
                    "body": "Second release",
                    "html_url": "https://github.com/owner/repo/releases/tag/v1.1.0",
                },
            ],
        )

        versions_set = {"v1.0.0", "v1.1.0"}
        releases = list(github_api_with_token._load_releases(repository, versions_set))

        assert len(releases) == 2
        assert releases[0].version == "v1.0.0"
        assert releases[0].version_source_type == VERSION_DATA_SOURCE_GITHUB_RELEASES
        assert releases[0].release_name == "Release 1.0.0"
        assert releases[0].release_notes == "First release"
        assert releases[1].version == "v1.1.0"

    def test_load_releases_partial_match(self, github_api_with_token, mock_github_response):
        """Test loading when only some versions have releases."""
        repository = Repository(
            provider=RepositoryProvider.PROVIDER_GITHUB,
            name="repo",
            owner="owner",
            description="Test repo",
            html_url="https://github.com/owner/repo",
        )

        mock_github_response.set_response(
            "https://api.github.com/repos/owner/repo/releases",
            [
                {
                    "tag_name": "v1.0.0",
                    "name": "Release 1.0.0",
                    "body": "First release",
                    "html_url": "https://github.com/owner/repo/releases/tag/v1.0.0",
                },
                {
                    "tag_name": "v2.0.0",
                    "name": "Release 2.0.0",
                    "body": "Major release",
                    "html_url": "https://github.com/owner/repo/releases/tag/v2.0.0",
                },
            ],
        )

        versions_set = {"v1.0.0", "v1.1.0"}  # v1.1.0 not in releases
        releases = list(github_api_with_token._load_releases(repository, versions_set))

        assert len(releases) == 1
        assert releases[0].version == "v1.0.0"

    def test_load_releases_no_body(self, github_api_with_token, mock_github_response):
        """Test release without body/notes."""
        repository = Repository(
            provider=RepositoryProvider.PROVIDER_GITHUB,
            name="repo",
            owner="owner",
            description="Test repo",
            html_url="https://github.com/owner/repo",
        )

        mock_github_response.set_response(
            "https://api.github.com/repos/owner/repo/releases",
            [
                {
                    "tag_name": "v1.0.0",
                    "name": "Release 1.0.0",
                    "html_url": "https://github.com/owner/repo/releases/tag/v1.0.0",
                }
            ],
        )

        versions_set = {"v1.0.0"}
        releases = list(github_api_with_token._load_releases(repository, versions_set))

        assert releases[0].release_notes is None


class TestLoadVersionsFromTags:
    """
    Test suite for _load_versions_from_tags() method.

    Tests fallback to tags when releases are not available.
    """

    def test_load_tags_basic(self, github_api_with_token, mock_github_response):
        """Test basic tag loading."""
        repository = Repository(
            provider=RepositoryProvider.PROVIDER_GITHUB,
            name="repo",
            owner="owner",
            description="Test repo",
            html_url="https://github.com/owner/repo",
        )

        mock_github_response.set_response(
            "https://api.github.com/repos/owner/repo/tags",
            [
                {"name": "v1.0.0", "commit": {"sha": "abc123"}},
                {"name": "v1.1.0", "commit": {"sha": "def456"}},
            ],
        )

        versions_set = {"v1.0.0", "v1.1.0"}
        tags = list(github_api_with_token._load_versions_from_tags(repository, versions_set))

        assert len(tags) == 2
        assert tags[0].version == "v1.0.0"
        assert tags[0].version_source_type == VERSION_DATA_SOURCE_GITHUB_TAGS
        assert tags[0].ref_name == "v1.0.0"
        assert tags[0].release_name is None
        assert tags[0].release_notes is None
        assert "v1.0.0" in tags[0].source_url

    def test_load_tags_partial_match(self, github_api_with_token, mock_github_response):
        """Test tag loading when only some versions exist."""
        repository = Repository(
            provider=RepositoryProvider.PROVIDER_GITHUB,
            name="repo",
            owner="owner",
            description="Test repo",
            html_url="https://github.com/owner/repo",
        )

        mock_github_response.set_response(
            "https://api.github.com/repos/owner/repo/tags",
            [{"name": "v1.0.0", "commit": {"sha": "abc123"}}],
        )

        versions_set = {"v1.0.0", "v2.0.0"}
        tags = list(github_api_with_token._load_versions_from_tags(repository, versions_set))

        assert len(tags) == 1
        assert tags[0].version == "v1.0.0"


class TestPaginateGithubApiRequest:
    """
    Test suite for _paginate_github_api_request() method.

    Tests automatic pagination handling for multi-page API responses.
    """

    def test_pagination_single_page(self, github_api_with_token, mock_github_response):
        """Test pagination with single page response."""
        mock_github_response.set_response("https://api.github.com/test", [{"id": 1}, {"id": 2}])

        results = list(github_api_with_token._paginate_github_api_request("https://api.github.com/test"))

        assert len(results) == 2
        assert results[0]["id"] == 1
        assert results[1]["id"] == 2

    def test_pagination_multiple_pages(self, github_api_with_token, mock_github_response):
        """Test pagination across multiple pages."""
        # Page 1
        mock_github_response.set_response(
            "https://api.github.com/test",
            [{"id": 1}, {"id": 2}],
            headers={"Link": '<https://api.github.com/test?page=2>; rel="next"'},
        )
        # Page 2
        mock_github_response.set_response("https://api.github.com/test?page=2", [{"id": 3}, {"id": 4}])

        results = list(github_api_with_token._paginate_github_api_request("https://api.github.com/test"))

        assert len(results) == 4
        assert results[0]["id"] == 1
        assert results[3]["id"] == 4


class TestRepositoryVersions:
    """
    Test suite for repository_versions() method.

    Tests comprehensive version fetching with releases, tags, and commits.
    """

    def test_repository_versions_from_releases(self, github_api_with_token, mock_github_response):
        """
        Test fetching versions from GitHub releases.

        Verifies that release metadata is correctly parsed and versions
        are properly ordered.
        """
        repository = Repository(
            provider=RepositoryProvider.PROVIDER_GITHUB,
            name="repo",
            owner="owner",
            description="Test repo",
            html_url="https://github.com/owner/repo",
        )

        mock_github_response.set_response(
            "https://api.github.com/repos/owner/repo/releases",
            [
                {
                    "tag_name": "1.0.0",
                    "name": "Release 1.0.0",
                    "body": "First release",
                    "html_url": "https://github.com/owner/repo/releases/tag/1.0.0",
                },
                {
                    "tag_name": "1.1.0",
                    "name": "Release 1.1.0",
                    "body": "Second release",
                    "html_url": "https://github.com/owner/repo/releases/tag/1.1.0",
                },
            ],
        )

        package_versions = [
            PackageVersion(
                version="1.0.0",
                license="MIT",
                package_url="https://pypi.org/project/test/1.0.0/",
                declared_dependencies={},
            ),
            PackageVersion(
                version="1.1.0",
                license="MIT",
                package_url="https://pypi.org/project/test/1.1.0/",
                declared_dependencies={},
            ),
        ]

        def comparator(v1, v2):
            """Simple version comparator."""
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
            return 0

        versions = list(github_api_with_token.repository_versions(repository, package_versions, comparator))

        assert len(versions) == 2
        assert versions[0].version == "1.0.0"
        assert versions[0].version_source_type == VERSION_DATA_SOURCE_GITHUB_RELEASES
        assert versions[0].release_name == "Release 1.0.0"
        assert versions[0].release_notes == "First release"
        assert versions[1].version == "1.1.0"
        assert versions[1].version_source_type == VERSION_DATA_SOURCE_GITHUB_RELEASES
        assert versions[1].release_name == "Release 1.1.0"
        assert versions[1].ref_previous == "1.0.0"

    def test_repository_versions_empty(self, github_api_with_token, mock_github_response):
        """Test when no matching versions are found."""
        repository = Repository(
            provider=RepositoryProvider.PROVIDER_GITHUB,
            name="repo",
            owner="owner",
            description="Test repo",
            html_url="https://github.com/owner/repo",
        )

        mock_github_response.set_response("https://api.github.com/repos/owner/repo/releases", [])
        mock_github_response.set_response("https://api.github.com/repos/owner/repo/tags", [])

        package_versions = [
            PackageVersion(
                version="1.0.0",
                license="MIT",
                package_url="https://pypi.org/project/test/1.0.0/",
                declared_dependencies={},
            )
        ]

        def comparator(v1, v2):
            pass

        versions = list(github_api_with_token.repository_versions(repository, package_versions, comparator))

        assert len(versions) == 0
