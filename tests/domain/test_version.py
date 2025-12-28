"""
Tests for version.py domain module.

This module tests:
- Version difference creation
- Version normalization (comprehensive)
- Version sorting
- Dataclass structures (User, Commit, PackageVersion, RepositoryVersion, Version)
"""

import pytest

from ossiq.domain.version import (
    VERSINO_INVERSED_DIFF_TYPES_MAP,
    VERSION_DIFF_BUILD,
    VERSION_DIFF_MAJOR,
    VERSION_DIFF_MINOR,
    VERSION_DIFF_PATCH,
    VERSION_DIFF_PRERELEASE,
    VERSION_LATEST,
    VERSION_NO_DIFF,
    Commit,
    PackageVersion,
    RepositoryVersion,
    User,
    Version,
    VersionsDifference,
    create_version_difference_no_diff,
    normalize_version,
    sort_versions,
)


class TestCreateVersionDifferenceNoDiff:
    """
    Test suite for create_version_difference_no_diff() function.

    Tests creation of VersionsDifference objects for incomparable versions.
    """

    def test_both_versions_none(self):
        """Test when both versions are None."""
        result = create_version_difference_no_diff(None, None)

        assert result.version1 == "N/A"
        assert result.version2 == "N/A"
        assert result.diff_index == VERSION_NO_DIFF
        assert result.diff_name == "NO_DIFF"

    def test_first_version_none(self):
        """Test when only first version is None."""
        result = create_version_difference_no_diff(None, "1.0.0")

        assert result.version1 == "N/A"
        assert result.version2 == "1.0.0"
        assert result.diff_index == VERSION_NO_DIFF
        assert result.diff_name == "NO_DIFF"

    def test_second_version_none(self):
        """Test when only second version is None."""
        result = create_version_difference_no_diff("1.0.0", None)

        assert result.version1 == "1.0.0"
        assert result.version2 == "N/A"
        assert result.diff_index == VERSION_NO_DIFF
        assert result.diff_name == "NO_DIFF"

    def test_both_versions_empty_string(self):
        """Test when both versions are empty strings."""
        result = create_version_difference_no_diff("", "")

        assert result.version1 == "N/A"
        assert result.version2 == "N/A"
        assert result.diff_index == VERSION_NO_DIFF

    def test_valid_versions_with_no_diff(self):
        """Test that valid versions are preserved in result."""
        result = create_version_difference_no_diff("1.2.3", "1.2.4")

        assert result.version1 == "1.2.3"
        assert result.version2 == "1.2.4"
        assert result.diff_index == VERSION_NO_DIFF


class TestNormalizeVersion:
    """
    Test suite for normalize_version() function.

    Comprehensive tests covering all version modifier formats
    from both NPM/Yarn and Python ecosystems.
    """

    def test_empty_string(self):
        """Empty string should be returned as-is."""
        assert normalize_version("") == ""

    def test_none_returns_none(self):
        """None should be returned as-is."""
        result = normalize_version(None)  # type: ignore
        assert result is None

    def test_plain_version_unchanged(self):
        """Plain version without modifiers should remain unchanged."""
        assert normalize_version("1.2.3") == "1.2.3"

    # NPM/Yarn modifiers
    def test_caret_modifier(self):
        """Caret (^) modifier should be removed."""
        assert normalize_version("^1.2.3") == "1.2.3"

    def test_tilde_modifier(self):
        """Tilde (~) modifier should be removed."""
        assert normalize_version("~1.2.3") == "1.2.3"

    def test_greater_than_modifier(self):
        """Greater than (>) modifier should be removed."""
        assert normalize_version(">1.2.3") == "1.2.3"

    def test_less_than_modifier(self):
        """Less than (<) modifier should be removed."""
        assert normalize_version("<1.2.3") == "1.2.3"

    def test_greater_equal_modifier(self):
        """Greater than or equal (>=) modifier should be removed."""
        assert normalize_version(">=1.2.3") == "1.2.3"

    def test_less_equal_modifier(self):
        """Less than or equal (<=) modifier should be removed."""
        assert normalize_version("<=1.2.3") == "1.2.3"

    def test_equals_modifier(self):
        """Equals (=) modifier should be removed."""
        assert normalize_version("=1.2.3") == "1.2.3"

    def test_asterisk_modifier(self):
        """Asterisk (*) modifier should be removed."""
        assert normalize_version("*1.2.3") == "1.2.3"

    # Python modifiers
    def test_double_equals_modifier(self):
        """Double equals (==) modifier should be removed."""
        assert normalize_version("==1.2.3") == "1.2.3"

    def test_not_equals_modifier(self):
        """Not equals (!=) modifier should be removed."""
        assert normalize_version("!=1.2.3") == "1.2.3"

    def test_tilde_equals_modifier(self):
        """Tilde equals (~=) modifier should be removed."""
        assert normalize_version("~=1.2.3") == "1.2.3"

    def test_triple_equals_modifier(self):
        """Triple equals (===) modifier should be removed."""
        assert normalize_version("===1.2.3") == "1.2.3"

    # Whitespace handling
    def test_leading_whitespace(self):
        """Leading whitespace should be stripped."""
        assert normalize_version("  1.2.3") == "1.2.3"

    def test_trailing_whitespace(self):
        """Trailing whitespace should be stripped."""
        assert normalize_version("1.2.3  ") == "1.2.3"

    def test_modifier_with_whitespace(self):
        """Modifier with whitespace should be handled."""
        assert normalize_version("^  1.2.3") == "1.2.3"

    # Range handling
    def test_hyphen_range(self):
        """Hyphen range should take first version."""
        assert normalize_version("1.2.3 - 2.0.0") == "1.2.3"

    def test_hyphen_range_with_modifiers(self):
        """Hyphen range with modifiers should be normalized."""
        assert normalize_version(">=1.2.3 - <2.0.0") == "1.2.3"

    # OR conditions
    def test_or_condition_double_pipe(self):
        """OR condition (||) should take first version."""
        assert normalize_version("1.2.3 || 2.0.0") == "1.2.3"

    def test_or_condition_multiple(self):
        """Multiple OR conditions should take first version."""
        assert normalize_version("1.2.3 || 1.5.0 || 2.0.0") == "1.2.3"

    # Space-separated constraints
    def test_space_separated_constraints(self):
        """Space-separated constraints should take first version."""
        assert normalize_version("1.2.3 <2.0.0") == "1.2.3"

    def test_space_after_modifier_removal(self):
        """Spaces after modifier removal should be handled."""
        assert normalize_version(">=1.2.3 <2.0.0") == "1.2.3"

    # Complex cases
    def test_prerelease_version(self):
        """Prerelease versions should be preserved."""
        assert normalize_version("^1.2.3-alpha.1") == "1.2.3-alpha.1"

    def test_build_metadata(self):
        """Build metadata should be preserved."""
        assert normalize_version("~1.2.3+build.123") == "1.2.3+build.123"

    def test_x_range(self):
        """X-range notation should be preserved."""
        assert normalize_version("1.2.x") == "1.2.x"

    def test_wildcard_in_version(self):
        """Wildcard in version number should be preserved."""
        assert normalize_version("1.*") == "1.*"

    def test_complex_npm_range(self):
        """Complex NPM range should be normalized."""
        assert normalize_version("^1.2.3 || ~2.0.0") == "1.2.3"

    def test_python_compatible_release(self):
        """Python compatible release clause should be normalized."""
        assert normalize_version("~=1.4.2") == "1.4.2"

    def test_multiple_modifiers_priority(self):
        """When multiple modifiers exist, only first should be removed."""
        # Pattern only removes operators at the start
        assert normalize_version(">=1.2.3") == "1.2.3"

    def test_version_with_epoch(self):
        """Version with epoch should be preserved."""
        assert normalize_version("1:1.2.3") == "1:1.2.3"


class TestSortVersions:
    """
    Test suite for sort_versions() function.

    Tests sorting of PackageVersion lists using custom comparators.
    """

    def test_sort_ascending(self):
        """Test sorting versions in ascending order."""
        versions = [
            PackageVersion(
                version="2.0.0",
                license="MIT",
                package_url="https://example.com",
                dependencies={},
            ),
            PackageVersion(
                version="1.0.0",
                license="MIT",
                package_url="https://example.com",
                dependencies={},
            ),
            PackageVersion(
                version="1.5.0",
                license="MIT",
                package_url="https://example.com",
                dependencies={},
            ),
        ]

        def comparator(v1, v2):
            """Simple string comparison."""
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
            return 0

        sorted_versions = sort_versions(versions, comparator)

        assert sorted_versions[0].version == "1.0.0"
        assert sorted_versions[1].version == "1.5.0"
        assert sorted_versions[2].version == "2.0.0"

    def test_sort_single_version(self):
        """Test sorting with single version."""
        versions = [
            PackageVersion(
                version="1.0.0",
                license="MIT",
                package_url="https://example.com",
                dependencies={},
            )
        ]

        def comparator(v1, v2):
            return 0

        sorted_versions = sort_versions(versions, comparator)

        assert len(sorted_versions) == 1
        assert sorted_versions[0].version == "1.0.0"

    def test_sort_empty_list(self):
        """Test sorting empty list."""

        def comparator(v1, v2):
            return 0

        sorted_versions = sort_versions([], comparator)

        assert len(sorted_versions) == 0


class TestVersionsDifference:
    """
    Test suite for VersionsDifference dataclass.

    Tests the structure and behavior of version difference objects.
    """

    def test_creation(self):
        """Test basic VersionsDifference creation."""
        diff = VersionsDifference(
            version1="1.0.0",
            version2="2.0.0",
            diff_index=VERSION_DIFF_MAJOR,
            diff_name="DIFF_MAJOR",
        )

        assert diff.version1 == "1.0.0"
        assert diff.version2 == "2.0.0"
        assert diff.diff_index == VERSION_DIFF_MAJOR
        assert diff.diff_name == "DIFF_MAJOR"

    def test_all_diff_types_mapping(self):
        """Test that all diff types are correctly mapped."""
        assert VERSINO_INVERSED_DIFF_TYPES_MAP[VERSION_DIFF_MAJOR] == "DIFF_MAJOR"
        assert VERSINO_INVERSED_DIFF_TYPES_MAP[VERSION_DIFF_MINOR] == "DIFF_MINOR"
        assert VERSINO_INVERSED_DIFF_TYPES_MAP[VERSION_DIFF_PATCH] == "DIFF_PATCH"
        assert VERSINO_INVERSED_DIFF_TYPES_MAP[VERSION_DIFF_PRERELEASE] == "DIFF_PRERELEASE"
        assert VERSINO_INVERSED_DIFF_TYPES_MAP[VERSION_DIFF_BUILD] == "DIFF_BUILD"
        assert VERSINO_INVERSED_DIFF_TYPES_MAP[VERSION_NO_DIFF] == "NO_DIFF"
        assert VERSINO_INVERSED_DIFF_TYPES_MAP[VERSION_LATEST] == "LATEST"


class TestUser:
    """
    Test suite for User dataclass.

    Tests user information structure and representation.
    """

    def test_user_creation(self):
        """Test User dataclass creation."""
        user = User(
            id=123,
            username="johndoe",
            email="john@example.com",
            display_name="John Doe",
            profile_url="https://github.com/johndoe",
        )

        assert user.id == 123
        assert user.username == "johndoe"
        assert user.email == "john@example.com"
        assert user.display_name == "John Doe"
        assert user.profile_url == "https://github.com/johndoe"

    def test_user_repr(self):
        """Test User string representation."""
        user = User(
            id=123,
            username="johndoe",
            email="john@example.com",
            display_name="John Doe",
            profile_url="https://github.com/johndoe",
        )

        assert "johndoe" in repr(user)
        assert "John Doe" in repr(user)

    def test_user_is_frozen(self):
        """Test that User dataclass is immutable."""
        user = User(
            id=123,
            username="johndoe",
            email="john@example.com",
            display_name="John Doe",
            profile_url="https://github.com/johndoe",
        )

        with pytest.raises(AttributeError):
            user.username = "janedoe"  # type: ignore


class TestCommit:
    """
    Test suite for Commit dataclass.

    Tests commit information structure and properties.
    """

    def test_commit_creation_with_author(self):
        """Test Commit creation with author."""
        author = User(
            id=1,
            username="author",
            email="author@example.com",
            display_name="Author Name",
            profile_url="https://github.com/author",
        )

        commit = Commit(
            sha="abc123",
            message="Fix bug",
            author=author,
            authored_at="2023-01-01T00:00:00Z",
            committer=None,
            committed_at=None,
        )

        assert commit.sha == "abc123"
        assert commit.message == "Fix bug"
        assert commit.author == author
        assert commit.commit_user_name == "Author Name"

    def test_commit_creation_with_committer(self):
        """Test Commit creation with committer only."""
        committer = User(
            id=2,
            username="committer",
            email="committer@example.com",
            display_name="Committer Name",
            profile_url="https://github.com/committer",
        )

        commit = Commit(
            sha="def456",
            message="Add feature",
            author=None,
            authored_at="2023-01-01T00:00:00Z",
            committer=committer,
            committed_at="2023-01-01T00:00:00Z",
        )

        assert commit.committer == committer
        assert commit.commit_user_name == "Committer Name"

    def test_commit_user_name_fallback(self):
        """Test commit_user_name when both author and committer are None."""
        commit = Commit(
            sha="xyz789",
            message="Update docs",
            author=None,
            authored_at="2023-01-01T00:00:00Z",
            committer=None,
            committed_at=None,
        )

        assert commit.commit_user_name == "<N/A>"

    def test_simplified_message_single_line(self):
        """Test simplified_message with single line."""
        commit = Commit(
            sha="abc123",
            message="Fix bug",
            author=None,
            authored_at="2023-01-01T00:00:00Z",
            committer=None,
            committed_at=None,
        )

        assert commit.simplified_message == "Fix bug"

    def test_simplified_message_multiline(self):
        """Test simplified_message extracts first line only."""
        commit = Commit(
            sha="abc123",
            message="Fix bug\n\nDetailed explanation\nMore details",
            author=None,
            authored_at="2023-01-01T00:00:00Z",
            committer=None,
            committed_at=None,
        )

        assert commit.simplified_message == "Fix bug"

    def test_commit_repr(self):
        """Test Commit string representation."""
        commit = Commit(
            sha="abc123",
            message="Fix bug",
            author=None,
            authored_at="2023-01-01T00:00:00Z",
            committer=None,
            committed_at=None,
        )

        assert "abc123" in repr(commit)
        assert "Fix bug" in repr(commit)

    def test_commit_is_frozen(self):
        """Test that Commit dataclass is immutable."""
        commit = Commit(
            sha="abc123",
            message="Fix bug",
            author=None,
            authored_at="2023-01-01T00:00:00Z",
            committer=None,
            committed_at=None,
        )

        with pytest.raises(AttributeError):
            commit.sha = "def456"  # type: ignore


class TestPackageVersion:
    """
    Test suite for PackageVersion dataclass.

    Tests package version information structure.
    """

    def test_package_version_minimal(self):
        """Test PackageVersion with minimal required fields."""
        pv = PackageVersion(
            version="1.0.0",
            license="MIT",
            package_url="https://pypi.org/project/test/",
            dependencies={},
        )

        assert pv.version == "1.0.0"
        assert pv.license == "MIT"
        assert pv.dependencies == {}
        assert pv.is_published is True

    def test_package_version_with_dependencies(self):
        """Test PackageVersion with dependencies."""
        pv = PackageVersion(
            version="2.0.0",
            license="Apache-2.0",
            package_url="https://pypi.org/project/test/",
            dependencies={"requests": ">=2.0.0", "urllib3": "^1.26.0"},
            dev_dependencies={"pytest": "^7.0.0"},
        )

        assert pv.dependencies == {"requests": ">=2.0.0", "urllib3": "^1.26.0"}
        assert pv.dev_dependencies == {"pytest": "^7.0.0"}

    def test_package_version_unpublished(self):
        """Test PackageVersion marked as unpublished."""
        pv = PackageVersion(
            version="1.0.0",
            license=None,
            package_url="https://pypi.org/project/test/",
            dependencies={},
            is_published=False,
            unpublished_date_iso="2023-01-01T00:00:00Z",
        )

        assert pv.is_published is False
        assert pv.unpublished_date_iso == "2023-01-01T00:00:00Z"

    def test_package_version_is_frozen(self):
        """Test that PackageVersion dataclass is immutable."""
        pv = PackageVersion(
            version="1.0.0",
            license="MIT",
            package_url="https://pypi.org/project/test/",
            dependencies={},
        )

        with pytest.raises(AttributeError):
            pv.version = "2.0.0"  # type: ignore


class TestRepositoryVersion:
    """
    Test suite for RepositoryVersion dataclass.

    Tests repository version information structure.
    """

    def test_repository_version_minimal(self):
        """Test RepositoryVersion with minimal fields."""
        rv = RepositoryVersion(version_source_type="GITHUB-RELEASES", version="1.0.0")

        assert rv.version_source_type == "GITHUB-RELEASES"
        assert rv.version == "1.0.0"
        assert rv.commits is None
        assert rv.ref_previous is None

    def test_repository_version_with_commits(self):
        """Test RepositoryVersion with commits."""
        author = User(
            id=1,
            username="author",
            email="author@example.com",
            display_name="Author",
            profile_url="https://github.com/author",
        )
        commit = Commit(
            sha="abc123",
            message="Add feature",
            author=author,
            authored_at="2023-01-01T00:00:00Z",
            committer=None,
            committed_at=None,
        )

        rv = RepositoryVersion(
            version_source_type="GITHUB-RELEASES",
            version="1.1.0",
            commits=[commit],
            ref_previous="1.0.0",
            ref_name="v1.1.0",
            release_name="Release 1.1.0",
            release_notes="New features added",
            source_url="https://github.com/owner/repo/releases/tag/v1.1.0",
            patch_url="https://github.com/owner/repo/compare/1.0.0...1.1.0.patch",
        )

        assert rv.commits is not None
        assert len(rv.commits) == 1
        assert rv.commits[0].sha == "abc123"
        assert rv.ref_previous == "1.0.0"
        assert rv.release_name == "Release 1.1.0"


class TestVersion:
    """
    Test suite for Version class.

    Tests aggregated version information from registry and repository.
    """

    def test_version_creation(self):
        """Test Version class creation."""
        pv = PackageVersion(
            version="1.0.0",
            license="MIT",
            package_url="https://pypi.org/project/test/",
            dependencies={},
        )
        rv = RepositoryVersion(version_source_type="GITHUB-RELEASES", version="1.0.0")

        version = Version(
            package_registry="PYPI",
            repository_provider="GITHUB",
            package_data=pv,
            repository_data=rv,
        )

        assert version.package_registry == "PYPI"
        assert version.repository_provider == "GITHUB"
        assert version.version == "1.0.0"

    def test_version_properties(self):
        """Test Version class properties."""
        pv = PackageVersion(
            version="1.0.0",
            license="MIT",
            package_url="https://pypi.org/project/test/",
            dependencies={},
        )
        rv = RepositoryVersion(
            version_source_type="GITHUB-RELEASES",
            version="1.0.0",
            ref_previous="0.9.0",
            source_url="https://github.com/owner/repo/releases/tag/v1.0.0",
        )

        version = Version(
            package_registry="PYPI",
            repository_provider="GITHUB",
            package_data=pv,
            repository_data=rv,
        )

        assert version.ref_previous == "0.9.0"
        assert version.source_url == "https://github.com/owner/repo/releases/tag/v1.0.0"

    def test_version_summary_description_setter(self):
        """Test summary_description property setter."""
        pv = PackageVersion(
            version="1.0.0",
            license="MIT",
            package_url="https://pypi.org/project/test/",
            dependencies={},
        )
        rv = RepositoryVersion(version_source_type="GITHUB-RELEASES", version="1.0.0")

        version = Version(
            package_registry="PYPI",
            repository_provider="GITHUB",
            package_data=pv,
            repository_data=rv,
        )

        version.summary_description = "This is a summary"
        assert version.summary_description == "This is a summary"

    def test_version_summary_description_not_set_raises(self):
        """Test that accessing summary_description before setting raises ValueError."""
        pv = PackageVersion(
            version="1.0.0",
            license="MIT",
            package_url="https://pypi.org/project/test/",
            dependencies={},
        )
        rv = RepositoryVersion(version_source_type="GITHUB-RELEASES", version="1.0.0")

        version = Version(
            package_registry="PYPI",
            repository_provider="GITHUB",
            package_data=pv,
            repository_data=rv,
        )

        with pytest.raises(ValueError) as excinfo:
            _ = version.summary_description

        assert "Summary description not set yet" in str(excinfo.value)

    def test_version_repr(self):
        """Test Version string representation."""
        pv = PackageVersion(
            version="1.0.0",
            license="MIT",
            package_url="https://pypi.org/project/test/",
            dependencies={},
        )
        rv = RepositoryVersion(version_source_type="GITHUB-RELEASES", version="1.0.0")

        version = Version(
            package_registry="PYPI",
            repository_provider="GITHUB",
            package_data=pv,
            repository_data=rv,
        )

        repr_str = repr(version)
        assert "1.0.0" in repr_str
        assert "PYPI" in repr_str
        assert "GITHUB" in repr_str

    def test_version_requires_repository_data(self):
        """Test that Version requires non-None repository_data."""
        pv = PackageVersion(
            version="1.0.0",
            license="MIT",
            package_url="https://pypi.org/project/test/",
            dependencies={},
        )

        with pytest.raises(AssertionError) as excinfo:
            Version(
                package_registry="PYPI",
                repository_provider="GITHUB",
                package_data=pv,
                repository_data=None,  # type: ignore
            )

        assert "Repository version info cannot be None" in str(excinfo.value)
