"""Tests for service/project/coverage.py."""

from ossiq.domain.common import ConstraintType, SignalCoverage
from ossiq.domain.project import ConstraintSource
from ossiq.domain.repository import Repository
from ossiq.domain.version import VersionsDifference
from ossiq.service.project.coverage import classify_signal_coverage, coverage_gaps
from ossiq.service.project.models import ScanRecord

CONSTRAINT = ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml")
DIFF = VersionsDifference("1.0.0", "2.0.0", 2, diff_name="minor")


def repo() -> Repository:
    return Repository(provider="GITHUB", name="repo", owner="owner", description=None, html_url=None)


def make_record(name: str, coverage: SignalCoverage = SignalCoverage.FULL) -> ScanRecord:
    return ScanRecord(
        package_name=name,
        dependency_name=name,
        is_optional_dependency=False,
        installed_version="1.0.0",
        latest_version="2.0.0",
        versions_diff_index=DIFF,
        time_lag_days=None,
        releases_lag=0,
        cve=[],
        constraint_info=CONSTRAINT,
        signal_coverage=coverage,
    )


class TestClassifySignalCoverage:
    def test_github_repo_that_answered_is_full(self) -> None:
        assert classify_signal_coverage("https://github.com/owner/repo", repo()) == SignalCoverage.FULL

    def test_no_url_declared(self) -> None:
        assert classify_signal_coverage(None, None) == SignalCoverage.NO_REPOSITORY

    def test_non_github_host(self) -> None:
        assert classify_signal_coverage("https://gitlab.com/owner/repo", None) == SignalCoverage.UNSUPPORTED_HOST

    def test_github_url_with_nothing_fetched(self) -> None:
        assert classify_signal_coverage("https://github.com/owner/repo", None) == SignalCoverage.REPOSITORY_UNAVAILABLE

    def test_a_non_github_url_never_reports_a_failed_fetch(self) -> None:
        # The distinction the panel exists for: a GitLab package was never asked about, so it is
        # unmeasured, not unreachable. Passing a Repository cannot change that.
        assert classify_signal_coverage("https://gitlab.com/owner/repo", repo()) == SignalCoverage.UNSUPPORTED_HOST

    def test_repository_without_its_commits(self) -> None:
        state = classify_signal_coverage(
            "https://github.com/owner/repo", repo(), commits_expected=True, has_commits=False
        )
        assert state == SignalCoverage.ACTIVITY_UNAVAILABLE

    def test_repository_with_its_commits(self) -> None:
        state = classify_signal_coverage(
            "https://github.com/owner/repo", repo(), commits_expected=True, has_commits=True
        )
        assert state == SignalCoverage.FULL

    def test_a_channel_that_never_ran_is_not_a_gap(self) -> None:
        # Under --no-stability nobody gets commits. A flag the user set is not missing data, so
        # the whole project would otherwise light up as degraded.
        state = classify_signal_coverage(
            "https://github.com/owner/repo", repo(), commits_expected=False, has_commits=False
        )
        assert state == SignalCoverage.FULL

    def test_a_missing_repository_outranks_a_missing_commit_history(self) -> None:
        # Both fetches failed; the panel names the one that explains the other.
        state = classify_signal_coverage(
            "https://github.com/owner/repo", None, commits_expected=True, has_commits=False
        )
        assert state == SignalCoverage.REPOSITORY_UNAVAILABLE


class TestCoverageGaps:
    def test_fully_covered_project_reports_no_gaps(self) -> None:
        records = [make_record("a"), make_record("b")]
        assert coverage_gaps(records) == {}

    def test_groups_by_state_and_sorts_names(self) -> None:
        records = [
            make_record("zeta", SignalCoverage.UNSUPPORTED_HOST),
            make_record("alpha", SignalCoverage.UNSUPPORTED_HOST),
            make_record("orphan", SignalCoverage.NO_REPOSITORY),
            make_record("covered"),
        ]

        assert coverage_gaps(records) == {
            SignalCoverage.UNSUPPORTED_HOST: ["alpha", "zeta"],
            SignalCoverage.NO_REPOSITORY: ["orphan"],
        }

    def test_one_package_listed_once(self) -> None:
        # A package can appear in both the production and development lists; the panel names it
        # once, or the counts read higher than the project's dependency count.
        records = [
            make_record("shared", SignalCoverage.NO_REPOSITORY),
            make_record("shared", SignalCoverage.NO_REPOSITORY),
        ]

        assert coverage_gaps(records) == {SignalCoverage.NO_REPOSITORY: ["shared"]}
