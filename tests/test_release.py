"""Tests for release.py script."""

from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from release import (
    BumpType,
    ChangelogService,
    CommitInfo,
    CommitType,
    GitHubService,
    GitService,
    VersionService,
)

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_project():
    """Create a temporary project directory with pyproject.toml."""
    with tempfile.TemporaryDirectory() as tmpdir:
        project_dir = Path(tmpdir)

        pyproject = project_dir / "pyproject.toml"
        pyproject.write_text(
            """[project]
name = "test-project"
version = "1.2.3"
"""
        )

        changelog = project_dir / "CHANGELOG.md"
        changelog.write_text("# CHANGELOG\n\n## v1.2.3 (2026-01-01)\n\n* Initial release\n")

        yield project_dir


@pytest.fixture
def sample_commits() -> list[CommitInfo]:
    """Create sample commit data for testing."""
    return [
        CommitInfo(
            sha="abc1234567890",
            sha_short="abc1234",
            commit_type=CommitType.FEAT,
            scope="api",
            is_breaking=False,
            description="add new endpoint",
            body="",
            author_name="Test User",
            author_email="test@example.com",
            date=datetime.now(),
            github_issues=[],
        ),
        CommitInfo(
            sha="def1234567890",
            sha_short="def1234",
            commit_type=CommitType.FIX,
            scope=None,
            is_breaking=False,
            description="fix bug",
            body="Detailed description",
            author_name="Test User",
            author_email="test@example.com",
            date=datetime.now(),
            github_issues=["GH-42"],
        ),
    ]


# ============================================================================
# VersionService Tests
# ============================================================================


class TestVersionService:
    """Tests for VersionService."""

    def test_read_current_version_success(self, temp_project):
        """Test reading version from pyproject.toml."""
        # Act
        version = VersionService.read_current_version(temp_project)

        # Assert
        assert version == "1.2.3"

    def test_read_current_version_file_not_found(self):
        """Test error when pyproject.toml doesn't exist."""
        # Arrange
        non_existent = Path("/non/existent/path")

        # Act & Assert
        with pytest.raises(FileNotFoundError):
            VersionService.read_current_version(non_existent)

    def test_read_current_version_no_version_field(self, temp_project):
        """Test error when version field is missing."""
        # Arrange
        pyproject = temp_project / "pyproject.toml"
        pyproject.write_text("[project]\nname = 'test'\n")

        # Act & Assert
        with pytest.raises(ValueError, match="Could not find version"):
            VersionService.read_current_version(temp_project)

    @pytest.mark.parametrize(
        "current,bump_type,expected",
        [
            ("1.0.0", BumpType.PATCH, "1.0.1"),
            ("1.0.0", BumpType.MINOR, "1.1.0"),
            ("1.0.0", BumpType.MAJOR, "2.0.0"),
            ("1.2.3", BumpType.PATCH, "1.2.4"),
            ("0.1.0", BumpType.MINOR, "0.2.0"),
            ("0.0.1", BumpType.MAJOR, "1.0.0"),
        ],
    )
    def test_calculate_new_version_bump(self, current, bump_type, expected):
        """Test version bumping with different bump types."""
        # Act
        result = VersionService.calculate_new_version(current, bump_type, None)

        # Assert
        assert result == expected

    def test_calculate_new_version_override(self):
        """Test version override."""
        # Act
        result = VersionService.calculate_new_version("1.0.0", None, "5.0.0")

        # Assert
        assert result == "5.0.0"

    def test_calculate_new_version_invalid_override(self):
        """Test error on invalid override version."""
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid version format"):
            VersionService.calculate_new_version("1.0.0", None, "invalid")

    def test_calculate_new_version_no_bump_type_no_override(self):
        """Test error when neither bump type nor override is provided."""
        # Act & Assert
        with pytest.raises(ValueError, match="Must specify"):
            VersionService.calculate_new_version("1.0.0", None, None)

    def test_update_pyproject_version(self, temp_project):
        """Test updating version in pyproject.toml."""
        # Act
        VersionService.update_pyproject_version(temp_project, "2.0.0", dry_run=False)

        # Assert
        content = (temp_project / "pyproject.toml").read_text()
        assert 'version = "2.0.0"' in content

    def test_update_pyproject_version_dry_run(self, temp_project):
        """Test that dry run doesn't modify file."""
        # Arrange
        original = (temp_project / "pyproject.toml").read_text()

        # Act
        VersionService.update_pyproject_version(temp_project, "2.0.0", dry_run=True)

        # Assert
        assert (temp_project / "pyproject.toml").read_text() == original

    def test_read_repository_url_success(self):
        """Test reading repository URL from pyproject.toml."""
        # Arrange
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            pyproject = project_dir / "pyproject.toml"
            pyproject.write_text(
                """[project]
name = "test"
version = "1.0.0"

[project.urls]
repository = "https://github.com/user/repo.git"
"""
            )

            # Act
            result = VersionService.read_repository_url(project_dir)

            # Assert
            assert result == "https://github.com/user/repo"

    def test_read_repository_url_without_git_suffix(self):
        """Test reading repository URL without .git suffix."""
        # Arrange
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            pyproject = project_dir / "pyproject.toml"
            pyproject.write_text(
                """[project.urls]
repository = "https://github.com/user/repo"
"""
            )

            # Act
            result = VersionService.read_repository_url(project_dir)

            # Assert
            assert result == "https://github.com/user/repo"

    def test_read_repository_url_missing(self):
        """Test error when repository URL is missing."""
        # Arrange
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            pyproject = project_dir / "pyproject.toml"
            pyproject.write_text('[project]\nname = "test"\n')

            # Act & Assert
            with pytest.raises(ValueError, match="Could not find repository URL"):
                VersionService.read_repository_url(project_dir)


# ============================================================================
# GitService Tests
# ============================================================================


class TestGitService:
    """Tests for GitService."""

    @pytest.mark.parametrize(
        "subject,expected_type,expected_scope,expected_breaking,expected_desc",
        [
            ("feat: add feature", CommitType.FEAT, None, False, "add feature"),
            ("fix(api): resolve bug", CommitType.FIX, "api", False, "resolve bug"),
            ("feat!: breaking change", CommitType.FEAT, None, True, "breaking change"),
            ("chore(deps): update deps", CommitType.CHORE, "deps", False, "update deps"),
            ("docs: update readme", CommitType.DOCS, None, False, "update readme"),
            ("refactor(core): simplify code", CommitType.REFACTOR, "core", False, "simplify code"),
            ("perf: improve speed", CommitType.PERF, None, False, "improve speed"),
            ("test(unit): add tests", CommitType.TEST, "unit", False, "add tests"),
            ("build: update config", CommitType.BUILD, None, False, "update config"),
            ("ci: fix workflow", CommitType.CI, None, False, "fix workflow"),
            ("revert: undo change", CommitType.REVERT, None, False, "undo change"),
            ("style: format code", CommitType.STYLE, None, False, "format code"),
        ],
    )
    def test_parse_commit_message_conventional(
        self, subject, expected_type, expected_scope, expected_breaking, expected_desc
    ):
        """Test parsing conventional commit messages."""
        # Arrange
        sep = GitService.FIELD_SEPARATOR
        raw = f"abc1234{sep}{subject}{sep}{sep}Test User{sep}test@example.com{sep}2026-01-15T10:00:00+00:00"

        # Act
        result = GitService.parse_commit_message(raw)

        # Assert
        assert result.commit_type == expected_type
        assert result.scope == expected_scope
        assert result.is_breaking == expected_breaking
        assert result.description == expected_desc

    def test_parse_commit_message_non_conventional(self):
        """Test parsing non-conventional commit message."""
        # Arrange
        sep = GitService.FIELD_SEPARATOR
        raw = f"abc1234{sep}Random commit message{sep}{sep}Test User{sep}test@example.com{sep}2026-01-15T10:00:00+00:00"

        # Act
        result = GitService.parse_commit_message(raw)

        # Assert
        assert result.commit_type is None
        assert result.description == "Random commit message"

    def test_parse_commit_message_removes_signoff_from_body(self):
        """Test that Signed-off-by is removed from body."""
        # Arrange
        sep = GitService.FIELD_SEPARATOR
        body = "Some description\n\nSigned-off-by: Name <email>"
        raw = f"abc1234{sep}feat: test{sep}{body}{sep}Test User{sep}test@example.com{sep}2026-01-15T10:00:00+00:00"

        # Act
        result = GitService.parse_commit_message(raw)

        # Assert
        assert "Signed-off-by" not in result.body
        assert "Some description" in result.body

    def test_parse_commit_message_preserves_sha(self):
        """Test that SHA is correctly preserved."""
        # Arrange
        sep = GitService.FIELD_SEPARATOR
        raw = f"abcdef1234567890{sep}feat: test{sep}{sep}Test{sep}test@e.com{sep}2026-01-15T10:00:00+00:00"

        # Act
        result = GitService.parse_commit_message(raw)

        # Assert
        assert result.sha == "abcdef1234567890"
        assert result.sha_short == "abcdef1"

    def test_parse_commit_message_extracts_github_issues(self):
        """Test that GH-* references are extracted from body."""
        # Arrange
        sep = GitService.FIELD_SEPARATOR
        body = "GH-11\nSigned-off-by: Name <email>"
        raw = (
            f"abc1234{sep}fix: update RELEASE.md{sep}{body}"
            f"{sep}Test User{sep}test@example.com{sep}2026-01-15T10:00:00+00:00"
        )

        # Act
        result = GitService.parse_commit_message(raw)

        # Assert
        assert result.github_issues == ["GH-11"]
        assert "GH-11" not in result.body
        assert "Signed-off-by" not in result.body

    def test_parse_commit_message_extracts_multiple_github_issues(self):
        """Test that multiple GH-* references are extracted."""
        # Arrange
        sep = GitService.FIELD_SEPARATOR
        body = "GH-11\nGH-22\nGH-33"
        raw = (
            f"abc1234{sep}feat: big feature{sep}{body}{sep}Test User{sep}test@example.com{sep}2026-01-15T10:00:00+00:00"
        )

        # Act
        result = GitService.parse_commit_message(raw)

        # Assert
        assert result.github_issues == ["GH-11", "GH-22", "GH-33"]
        assert result.body == ""

    def test_parse_commit_message_preserves_non_gh_body(self):
        """Test that non-GH body content is preserved."""
        # Arrange
        sep = GitService.FIELD_SEPARATOR
        body = "Some detailed description\n\nGH-42\n\nMore details here"
        raw = f"abc1234{sep}feat: test{sep}{body}{sep}Test User{sep}test@example.com{sep}2026-01-15T10:00:00+00:00"

        # Act
        result = GitService.parse_commit_message(raw)

        # Assert
        assert result.github_issues == ["GH-42"]
        assert "Some detailed description" in result.body
        assert "More details here" in result.body


# ============================================================================
# ChangelogService Tests
# ============================================================================


class TestChangelogService:
    """Tests for ChangelogService."""

    def test_group_commits_by_type(self, sample_commits):
        """Test grouping commits by type."""
        # Arrange
        service = ChangelogService()

        # Act
        grouped = service.group_commits_by_type(sample_commits)

        # Assert
        assert "Feature" in grouped
        assert "Fix" in grouped
        assert len(grouped["Feature"]) == 1
        assert len(grouped["Fix"]) == 1

    def test_group_commits_by_type_preserves_order(self, sample_commits):
        """Test that Feature comes before Fix in grouping."""
        # Arrange
        service = ChangelogService()

        # Act
        grouped = service.group_commits_by_type(sample_commits)
        keys = list(grouped.keys())

        # Assert
        assert keys.index("Feature") < keys.index("Fix")

    def test_group_commits_handles_unknown_type(self):
        """Test grouping commits with unknown type."""
        # Arrange
        service = ChangelogService()
        commits = [
            CommitInfo(
                sha="abc",
                sha_short="abc",
                commit_type=None,
                scope=None,
                is_breaking=False,
                description="unknown commit",
                body="",
                author_name="Test",
                author_email="test@example.com",
                date=datetime.now(),
                github_issues=[],
            )
        ]

        # Act
        grouped = service.group_commits_by_type(commits)

        # Assert
        assert "Unknown" in grouped
        assert len(grouped["Unknown"]) == 1

    def test_generate_changelog_entry(self, sample_commits):
        """Test changelog entry generation."""
        # Arrange
        service = ChangelogService()

        # Act
        entry = service.generate_changelog_entry("1.3.0", sample_commits, "https://github.com/ossiq/ossiq")

        # Assert
        assert "## v1.3.0" in entry
        assert "### Feature" in entry
        assert "### Fix" in entry
        assert "abc1234" in entry
        assert "def1234" in entry
        # GitHub issues should be inline with the commit description
        assert "(GH-42)" in entry
        # Signed-off-by should NOT be in the output
        assert "Signed-off-by:" not in entry

    def test_generate_changelog_entry_includes_scope(self, sample_commits):
        """Test that scope is included in changelog entry."""
        # Arrange
        service = ChangelogService()

        # Act
        entry = service.generate_changelog_entry("1.3.0", sample_commits, "https://github.com/ossiq/ossiq")

        # Assert
        assert "feat(api):" in entry

    def test_generate_changelog_entry_empty_commits(self):
        """Test changelog entry with no commits."""
        # Arrange
        service = ChangelogService()

        # Act
        entry = service.generate_changelog_entry("1.3.0", [], "https://github.com/ossiq/ossiq")

        # Assert
        assert "## v1.3.0" in entry
        assert "###" not in entry  # No section headers when no commits

    def test_update_changelog_file(self, temp_project):
        """Test updating CHANGELOG.md file."""
        # Arrange
        service = ChangelogService()
        new_entry = "## v1.4.0 (2026-01-15)\n\n* New feature\n"

        # Act
        service.update_changelog_file(temp_project, new_entry, dry_run=False)

        # Assert
        content = (temp_project / "CHANGELOG.md").read_text()
        assert "## v1.4.0" in content
        assert content.index("## v1.4.0") < content.index("## v1.2.3")

    def test_update_changelog_file_dry_run(self, temp_project):
        """Test that dry run doesn't modify changelog."""
        # Arrange
        service = ChangelogService()
        original = (temp_project / "CHANGELOG.md").read_text()

        # Act
        service.update_changelog_file(temp_project, "## v2.0.0\n", dry_run=True)

        # Assert
        assert (temp_project / "CHANGELOG.md").read_text() == original

    def test_update_changelog_file_creates_if_missing(self):
        """Test that changelog is created if it doesn't exist."""
        # Arrange
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            service = ChangelogService()

            # Act
            service.update_changelog_file(project_dir, "## v1.0.0\n\n* Initial\n", dry_run=False)

            # Assert
            content = (project_dir / "CHANGELOG.md").read_text()
            assert "# CHANGELOG" in content
            assert "## v1.0.0" in content


# ============================================================================
# GitHubService Tests
# ============================================================================


class TestGitHubService:
    """Tests for GitHubService."""

    API_URL = "https://api.github.com/repos/ossiq/ossiq"

    def test_derive_api_url_from_github_url(self):
        """Test deriving API URL from GitHub repository URL."""
        # Act
        result = GitHubService.derive_api_url("https://github.com/ossiq/ossiq")

        # Assert
        assert result == "https://api.github.com/repos/ossiq/ossiq"

    def test_derive_api_url_unsupported_format(self):
        """Test error on unsupported repository URL format."""
        # Act & Assert
        with pytest.raises(ValueError, match="Unsupported repository URL format"):
            GitHubService.derive_api_url("https://gitlab.com/user/repo")

    def test_create_release_dry_run(self):
        """Test that dry run doesn't make API calls."""
        # Arrange
        service = GitHubService(api_url=self.API_URL, github_token="test-token")

        # Act
        with patch("requests.post") as mock_post:
            result = service.create_release("v1.0.0", "Release notes", dry_run=True)

        # Assert
        mock_post.assert_not_called()
        assert result is None

    def test_create_release_success(self):
        """Test successful GitHub release creation."""
        # Arrange
        service = GitHubService(api_url=self.API_URL, github_token="test-token")
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"html_url": "https://github.com/ossiq/ossiq/releases/v1.0.0"}

        # Act
        with patch.object(service.session, "post", return_value=mock_response) as mock_post:
            result = service.create_release("v1.0.0", "Release notes", dry_run=False)

        # Assert
        mock_post.assert_called_once()
        assert result == "https://github.com/ossiq/ossiq/releases/v1.0.0"

    def test_create_release_failure(self):
        """Test GitHub release creation failure."""
        # Arrange
        service = GitHubService(api_url=self.API_URL, github_token="test-token")
        mock_response = MagicMock()
        mock_response.status_code = 422
        mock_response.text = "Validation failed"

        # Act & Assert
        with patch.object(service.session, "post", return_value=mock_response):
            with pytest.raises(RuntimeError, match="Failed to create GitHub release"):
                service.create_release("v1.0.0", "Release notes", dry_run=False)

    def test_create_release_no_token(self):
        """Test error when no GitHub token is provided."""
        # Arrange
        service = GitHubService(api_url=self.API_URL, github_token=None)

        # Act & Assert
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="OSSIQ_GITHUB_TOKEN"):
                service.create_release("v1.0.0", "Release notes", dry_run=False)

    def test_create_release_uses_correct_headers(self):
        """Test that correct headers are sent to GitHub API."""
        # Arrange
        service = GitHubService(api_url=self.API_URL, github_token="test-token")
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"html_url": "url"}

        # Act
        with patch.object(service.session, "post", return_value=mock_response) as mock_post:
            service.create_release("v1.0.0", "notes", dry_run=False)

        # Assert
        call_kwargs = mock_post.call_args.kwargs
        assert "Bearer test-token" in call_kwargs["headers"]["Authorization"]
        assert "application/vnd.github+json" in call_kwargs["headers"]["Accept"]

    def test_create_release_uses_correct_payload(self):
        """Test that correct payload is sent to GitHub API."""
        # Arrange
        service = GitHubService(api_url=self.API_URL, github_token="test-token")
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"html_url": "url"}

        # Act
        with patch.object(service.session, "post", return_value=mock_response) as mock_post:
            service.create_release("v1.0.0", "Release notes here", dry_run=False)

        # Assert
        call_kwargs = mock_post.call_args.kwargs
        assert call_kwargs["json"]["tag_name"] == "v1.0.0"
        assert call_kwargs["json"]["name"] == "Release v1.0.0"
        assert call_kwargs["json"]["body"] == "Release notes here"
        assert call_kwargs["json"]["draft"] is False
        assert call_kwargs["json"]["prerelease"] is False
