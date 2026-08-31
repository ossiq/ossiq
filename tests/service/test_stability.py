"""Tests for ossiq.service.project.stability."""

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import pytest

from ossiq.domain.common import ConstraintType, CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.project import ConstraintSource
from ossiq.domain.repository import Repository
from ossiq.domain.version import VERSION_LATEST, VersionsDifference
from ossiq.risk.maintenance import (
    DEPRECATION_STRONG,
    DeprecationEvidence,
    DeprecationSignal,
    MaintenanceState,
)
from ossiq.risk.stability import (
    ENGAGEMENT_BUCKET_DAYS,
    FLOW_DECLINING,
    RESPONSIVENESS_WINDOW_DAYS,
    SECONDS_PER_DAY,
)
from ossiq.risk.triage import ACTION_EVICT, ACTION_REFACTOR, ACTION_RETAIN
from ossiq.service.project.models import ScanRecord
from ossiq.service.project.stability import (
    RepositoryStability,
    engagement_series,
    maintenance_observations,
    populate_stability,
    repository_stability,
)

WEEK_ZERO = 1_700_000_000
SECONDS_PER_WEEK = 7 * SECONDS_PER_DAY
NOW = datetime.fromtimestamp(WEEK_ZERO + 60 * SECONDS_PER_WEEK, tz=UTC)

GITHUB_URL = "https://github.com/example/project"
GITLAB_URL = "https://gitlab.com/example/project"


def commits_payload(timestamps: Sequence[float], *, bot: bool = False) -> list[dict]:
    """GitHub-shaped commit list: one entry per timestamp, order doesn't matter."""
    author = {"login": "dependabot[bot]", "type": "Bot"} if bot else {"login": "someone", "type": "User"}
    return [
        {
            "commit": {"committer": {"date": datetime.fromtimestamp(ts, tz=UTC).isoformat()}},
            "author": author,
        }
        for ts in timestamps
    ]


def stale_commits(n: int = 25) -> list[dict]:
    """n daily commits ending long before NOW - regular activity that has since gone silent."""
    return commits_payload([WEEK_ZERO + i * SECONDS_PER_DAY for i in range(n)])


def active_commits(n: int = 25) -> list[dict]:
    """n daily commits ending at NOW - recently active."""
    now_ts = NOW.timestamp()
    return commits_payload([now_ts - i * SECONDS_PER_DAY for i in range(n)])


def make_cve(epss: float | None) -> CVE:
    return CVE(
        id="CVE-2026-0001",
        cve_ids=("CVE-2026-0001",),
        source=CveDatabase.OSV,
        package_name="example",
        package_registry=ProjectPackagesRegistry.PYPI,
        summary="example vulnerability",
        severity=Severity.HIGH,
        affected_versions=("1.0.0",),
        published=None,
        link="https://example.test/advisory",
        epss=epss,
    )


def make_record(
    package_name: str,
    *,
    repo_url: str | None = GITHUB_URL,
    cve: list[CVE] | None = None,
    repository: Repository | None = None,
    deprecation: DeprecationEvidence | None = None,
) -> ScanRecord:
    return ScanRecord(
        package_name=package_name,
        dependency_name=package_name,
        is_optional_dependency=False,
        installed_version="1.0.0",
        latest_version="1.0.0",
        versions_diff_index=VersionsDifference("1.0.0", "1.0.0", VERSION_LATEST, "ignored"),
        time_lag_days=0,
        releases_lag=0,
        cve=cve or [],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
        repo_url=repo_url,
        repository=repository,
        deprecation=deprecation,
    )


class TestRepositoryStability:
    def test_empty_payload_is_unmeasured(self) -> None:
        assert repository_stability([], NOW) is None

    def test_single_commit_is_measured_but_gap_fields_stay_unknown(self) -> None:
        stability = repository_stability(commits_payload([WEEK_ZERO]), NOW)

        assert stability is not None
        assert stability.commits_sampled == 1
        assert stability.span_days == pytest.approx(0.0)
        assert stability.gap_cv is None
        assert stability.median_gap_days is None
        assert stability.silence_p is None

    def test_gap_fields_populated_from_regular_commits(self) -> None:
        timestamps = [WEEK_ZERO + i * SECONDS_PER_DAY for i in range(25)]
        stability = repository_stability(commits_payload(timestamps), NOW)

        assert stability is not None
        assert stability.commits_sampled == 25
        assert stability.gap_cv == pytest.approx(0.0)
        assert stability.median_gap_days == pytest.approx(1.0)
        assert stability.span_days == pytest.approx(24.0)
        assert stability.silence_p == pytest.approx(0.0)

    def test_no_activity_leaves_engagement_trend_none(self) -> None:
        stability = repository_stability(active_commits(), NOW)
        assert stability is not None
        assert stability.flow_trend is None
        assert stability.engagement is None

    def test_bot_commits_leave_the_repository_unmeasured(self) -> None:
        timestamps = [WEEK_ZERO + i * SECONDS_PER_DAY for i in range(25)]
        assert repository_stability(commits_payload(timestamps, bot=True), NOW) is None


BUCKET_COUNT = RESPONSIVENESS_WINDOW_DAYS // ENGAGEMENT_BUCKET_DAYS


def issue_node(*, opened_days_ago: int, closed_days_ago: int | None = None) -> dict:
    created = NOW - timedelta(days=opened_days_ago)
    closed = None if closed_days_ago is None else (NOW - timedelta(days=closed_days_ago)).isoformat()
    return {
        "createdAt": created.isoformat(),
        "closedAt": closed,
        "author": {"login": "reporter", "__typename": "User"},
    }


def bucket_open_days(index: int) -> int:
    """Days-ago that lands an item in bucket `index` (0 = oldest)."""
    return (BUCKET_COUNT - 1 - index) * ENGAGEMENT_BUCKET_DAYS + ENGAGEMENT_BUCKET_DAYS // 2


class TestEngagementSeries:
    def test_closed_counted_in_the_bucket_it_closed_regardless_of_open_date(self) -> None:
        latest = BUCKET_COUNT - 1
        activity = {
            "issues": [issue_node(opened_days_ago=bucket_open_days(1), closed_days_ago=bucket_open_days(latest))],
            "pulls": [],
        }
        series = engagement_series(activity, NOW.timestamp())
        assert series.buckets[1].issues_opened == 1
        assert series.buckets[latest].issues_closed == 1

    def test_declining_flow_trend(self) -> None:
        issues = []
        for index in range(BUCKET_COUNT):
            issues += [issue_node(opened_days_ago=bucket_open_days(index)) for _ in range(5)]
            if index < BUCKET_COUNT // 2:
                issues += [
                    issue_node(opened_days_ago=bucket_open_days(index), closed_days_ago=bucket_open_days(index))
                    for _ in range(5)
                ]
        series = engagement_series({"issues": issues, "pulls": []}, NOW.timestamp())
        assert series.flow_trend == FLOW_DECLINING

    def test_bots_are_filtered(self) -> None:
        bot_issue = issue_node(opened_days_ago=bucket_open_days(BUCKET_COUNT // 2))
        bot_issue["author"] = {"login": "dependabot[bot]", "__typename": "Bot"}
        series = engagement_series({"issues": [bot_issue], "pulls": []}, NOW.timestamp())
        assert all(bucket.issues_opened == 0 for bucket in series.buckets)


def stability_stub(*, silence_p: float | None = 0.5, silence_days: float | None = 5.0, flow_trend: str | None = None):
    return RepositoryStability(silence_p=silence_p, silence_days=silence_days, flow_trend=flow_trend)


class TestMaintenanceObservations:
    def test_strong_deprecation_drops_the_commit_recency_observations(self) -> None:
        deprecation = DeprecationEvidence(frozenset({DeprecationSignal.ARCHIVED}), None)
        record = make_record("x", deprecation=deprecation)
        record.stability = stability_stub(flow_trend="declining")
        record.days_since_push = 3
        assert maintenance_observations(record) == {"deprecation_strength": DEPRECATION_STRONG}

    def test_flow_trend_is_dropped_on_a_freshly_pushed_repo(self) -> None:
        record = make_record("x")
        record.stability = stability_stub(flow_trend="declining")
        record.days_since_push = 10  # fresh
        assert maintenance_observations(record)["flow_trend"] is None

    def test_flow_trend_is_kept_once_activity_has_slowed(self) -> None:
        record = make_record("x")
        record.stability = stability_stub(flow_trend="declining")
        record.days_since_push = 200  # aging
        assert maintenance_observations(record)["flow_trend"] == "declining"

    def test_none_deprecation_strength_alone_is_not_an_observation(self) -> None:
        record = make_record("x")  # no repository, no stability, no deprecation markers
        assert all(value is None for value in maintenance_observations(record).values())


class TestPopulateStability:
    def test_assigns_stability_and_triage_to_every_record(self) -> None:
        records = [make_record("alpha"), make_record("beta")]
        project = populate_stability(records, {GITHUB_URL: active_commits()}, NOW)

        assert all(record.stability is not None for record in records)
        assert all(record.triage is not None for record in records)
        assert all(record.maintenance is not None for record in records)
        assert project.scored_packages == 2
        assert project.unmaintained_packages == 0

    def test_non_github_repository_stays_unknown_never_unstable(self) -> None:
        record = make_record("alpha", repo_url=GITLAB_URL)
        project = populate_stability([record], {GITHUB_URL: active_commits()}, NOW)

        assert record.stability is None
        assert record.maintenance is None
        assert record.triage is not None
        assert record.triage.action == ACTION_RETAIN
        assert project.unknown_packages == 1
        assert project.scored_packages == 0

    def test_missing_repo_url_stays_unknown(self) -> None:
        record = make_record("alpha", repo_url=None)
        project = populate_stability([record], {}, NOW)
        assert record.maintenance is None
        assert project.unknown_packages == 1

    def test_counts_unmaintained_packages(self) -> None:
        record = make_record("alpha")
        project = populate_stability([record], {GITHUB_URL: stale_commits()}, NOW)
        assert project.unmaintained_packages == 1
        assert record.triage is not None
        assert record.triage.action == ACTION_REFACTOR

    def test_deprecated_evidence_drives_the_state_and_triage(self) -> None:
        deprecation = DeprecationEvidence(frozenset({DeprecationSignal.ARCHIVED}), successor="flask-restx")
        repository = Repository("github", "flask-restplus", "noirbizarre", None, GITHUB_URL, archived=True)
        record = make_record("flask-restplus", repository=repository, deprecation=deprecation)
        project = populate_stability([record], {GITHUB_URL: active_commits()}, NOW)

        assert record.maintenance is not None
        assert record.maintenance.state == MaintenanceState.DEPRECATED
        assert record.triage is not None
        assert record.triage.action == ACTION_REFACTOR
        assert project.deprecated_packages == 1
        assert project.unmaintained_packages == 1

    def test_a_busy_repository_is_never_triaged_for_refactor(self) -> None:
        record = make_record("alpha")
        project = populate_stability([record], {GITHUB_URL: active_commits()}, NOW)
        assert record.maintenance is not None
        assert project.unmaintained_packages == 0
        assert record.triage is not None
        assert record.triage.action == ACTION_RETAIN

    def test_shared_repository_is_measured_once_and_reused(self) -> None:
        records = [make_record("alpha"), make_record("beta")]
        populate_stability(records, {GITHUB_URL: active_commits()}, NOW)
        assert records[0].stability is records[1].stability

    def test_duplicate_package_names_count_once(self) -> None:
        records = [make_record("alpha"), make_record("alpha")]
        project = populate_stability(records, {GITHUB_URL: active_commits()}, NOW)
        assert project.scored_packages == 1

    def test_exploit_on_a_dead_repository_evicts(self) -> None:
        record = make_record("alpha", cve=[make_cve(0.42)])
        populate_stability([record], {GITHUB_URL: stale_commits()}, NOW)
        assert record.triage is not None
        assert record.triage.action == ACTION_EVICT

    def test_no_data_at_all_leaves_every_record_unscored(self) -> None:
        records = [make_record("alpha"), make_record("beta")]
        project = populate_stability(records, {}, NOW)
        assert (project.scored_packages, project.unmaintained_packages, project.unknown_packages) == (0, 0, 2)

    def test_single_commit_flows_through_without_an_unstable_verdict(self) -> None:
        record = make_record("alpha")
        project = populate_stability([record], {GITHUB_URL: commits_payload([WEEK_ZERO])}, NOW)

        assert record.stability is not None
        assert record.stability.commits_sampled == 1
        assert record.maintenance is None
        assert record.triage is not None
        assert record.triage.action == ACTION_RETAIN
        assert project.scored_packages == 0
