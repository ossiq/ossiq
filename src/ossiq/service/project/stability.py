"""
Computes repository stability and maintenance state across the dependency graph.

Neither stability nor maintenance composes: "at least one dependency is unmaintained" is not a
probability, so there is deliberately no project-level index. The project view reports counts,
including how many packages could not be assessed at all.
"""

import statistics
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from ossiq.risk.maintenance import (
    MAINTENANCE_THRESHOLD,
    NOT_MAINTAINED,
    MaintenanceAssessment,
    MaintenanceState,
    assess_maintenance,
    gated_observations,
    push_age_bucket,
)
from ossiq.risk.stability import (
    ENGAGEMENT_BUCKET_DAYS,
    MIN_GAPS,
    RESPONSIVENESS_WINDOW_DAYS,
    SECONDS_PER_DAY,
    EngagementBucket,
    EngagementSeries,
    commit_gaps,
    commit_timestamps,
    flow_ratio,
    flow_trend,
    gap_dispersion,
    has_stopped,
    is_bot_author,
    silence_survival,
)
from ossiq.risk.triage import TriageResult, triage
from ossiq.service.project import models
from ossiq.timeutil import age_days_from_iso

__all__ = (
    "MaintenanceAssessment",
    "ProjectStability",
    "RepositoryStability",
    "TriageResult",
    "engagement_series",
    "populate_stability",
    "repository_stability",
)


def iso_epoch(value: str | None) -> float | None:
    """Epoch seconds for a GraphQL ISO-8601 timestamp, or None."""
    return datetime.fromisoformat(value).timestamp() if value else None


def engagement_series(activity: Mapping, boundary: float) -> EngagementSeries:
    """Reduce one repo's raw GraphQL activity payload to ~30-day flow buckets and a trend verdict.

    `boundary` is epoch seconds (now, or the scan's cutoff). Bots are filtered before counting.
    Items are bucketed by *opened* date; closes / merges land in the bucket they closed in,
    regardless of when they opened - the cohort-matched denominator arXiv:2508.01358's cumulative
    totals lacked. Bucket index 0 is the oldest in the window.
    """

    bucket_count = RESPONSIVENESS_WINDOW_DAYS // ENGAGEMENT_BUCKET_DAYS
    bucket_seconds = ENGAGEMENT_BUCKET_DAYS * SECONDS_PER_DAY

    def bucket_of(epoch: float | None) -> int | None:
        if epoch is None:
            return None
        offset = boundary - epoch
        if offset < 0 or offset >= bucket_count * bucket_seconds:
            return None
        return bucket_count - 1 - int(offset // bucket_seconds)

    issues_opened = [0] * bucket_count
    issues_closed = [0] * bucket_count
    prs_opened = [0] * bucket_count
    prs_merged = [0] * bucket_count

    def tally(nodes: Iterable[Mapping], opened: list[int], done: list[int], done_field: str) -> None:
        for node in nodes:
            if is_bot_author(node.get("author")):
                continue
            opened_bucket = bucket_of(iso_epoch(node.get("createdAt")))
            if opened_bucket is not None:
                opened[opened_bucket] += 1
            done_bucket = bucket_of(iso_epoch(node.get(done_field)))
            if done_bucket is not None:
                done[done_bucket] += 1

    tally(activity.get("issues") or [], issues_opened, issues_closed, "closedAt")
    tally(activity.get("pulls") or [], prs_opened, prs_merged, "mergedAt")

    buckets = [
        EngagementBucket(
            index=index,
            issues_opened=issues_opened[index],
            issues_closed=issues_closed[index],
            prs_opened=prs_opened[index],
            prs_merged=prs_merged[index],
        )
        for index in range(bucket_count)
    ]
    ratios = [flow_ratio(b.issues_opened + b.prs_opened, b.issues_closed + b.prs_merged) for b in buckets]
    return EngagementSeries(buckets, flow_trend(ratios))


@dataclass(frozen=True)
class RepositoryStability:
    """Repository stability signals for one package's upstream repository.

    The commit-gap fields drive the validated `has_stopped` dormancy test; the engagement trends
    are directional inputs to the maintenance-state model. Neither is a score.
    """

    gap_cv: float | None = None
    """Coefficient of variation of inter-commit gaps from the last 100 commits - volume-free,
    unlike a weekly-bucket CV. None below MIN_GAPS gaps."""

    median_gap_days: float | None = None
    """Median inter-commit gap, in days, from the sampled commits."""

    silence_days: float | None = None
    """Days since the most recent sampled commit."""

    silence_p: float | None = None
    """Empirical probability, from this repo's own gap history, of a silence this long."""

    commits_sampled: int = 0
    """Non-bot commits that entered the gap measurement."""

    span_days: float | None = None
    """Time span, in days, covered by the sampled commits."""

    flow_trend: str | None = None
    """Direction of the issue / PR flow ratio over the engagement window: `improving` / `stable`
    / `declining`. None without a GraphQL activity sample or too few active buckets."""

    engagement: EngagementSeries | None = None
    """Raw ~30-day flow buckets behind flow_trend, for offline recalibration."""


@dataclass(frozen=True)
class ProjectStability:
    """Project-wide maintenance counts. There is no project index - maintenance does not compose."""

    scored_packages: int
    """Distinct packages with a maintenance assessment."""

    unmaintained_packages: int
    """Assessed packages whose most probable state is `abandoned` or `deprecated`."""

    deprecated_packages: int
    """Assessed packages whose most probable state is `deprecated`."""

    unknown_packages: int
    """Packages with no assessment: no repository, no deprecation evidence, nothing to go on."""


def repository_stability(
    commits: list[dict], now: datetime | None, activity: Mapping | None = None
) -> RepositoryStability | None:
    """Build the stability record from a repository's last 100 commits and activity sample.

    None when no non-bot commit was sampled at all - a repo that doesn't exist, is private, or
    was rate-limited. Any repository with at least one sampled commit gets a record;
    `commits_sampled` / `span_days` populate even without enough gaps for `gap_cv`, and the
    engagement trends populate only when `activity` is present.
    """

    boundary = (now or datetime.now(tz=UTC)).timestamp()
    timestamps = commit_timestamps(commits)
    if not timestamps:
        return None

    gaps = commit_gaps(timestamps)
    silence_days = (boundary - max(timestamps)) / SECONDS_PER_DAY
    engagement = engagement_series(activity, boundary) if activity else None

    return RepositoryStability(
        gap_cv=gap_dispersion(gaps) if len(gaps) >= MIN_GAPS else None,
        median_gap_days=statistics.median(gaps) if gaps else None,
        silence_days=silence_days,
        silence_p=silence_survival(gaps, silence_days),
        commits_sampled=len(timestamps),
        span_days=(max(timestamps) - min(timestamps)) / SECONDS_PER_DAY,
        flow_trend=engagement.flow_trend if engagement else None,
        engagement=engagement,
    )


def maintenance_observations(record: "models.ScanRecord") -> dict[str, object]:
    """The observation dict for one record, before None values are dropped by the model.

    A `"none"` deprecation strength on its own is not enough to assess a package: a repository we
    never measured and found no markers on stays unknown rather than pinned to the prior. The
    other two gates live in `gated_observations`, shared with the calibration harness.
    """

    stability = record.stability
    deprecation = record.deprecation
    strength = deprecation.strength if deprecation is not None and deprecation.signals else None
    stopped = has_stopped(stability.silence_p, stability.silence_days) if stability is not None else None
    return gated_observations(
        deprecation_strength=strength,
        has_stopped=stopped,
        push_age=push_age_bucket(record.days_since_push),
        flow_trend=stability.flow_trend if stability is not None else None,
    )


def populate_stability(
    records: Iterable["models.ScanRecord"],
    commits: Mapping[str, list[dict]],
    now: datetime | None = None,
    activity: Mapping[str, dict] | None = None,
) -> ProjectStability:
    """Assign `record.stability`, `record.maintenance` and `record.triage` on every record.

    `commits` and `activity` are keyed by repository URL, so packages sharing a monorepo are
    measured once and the result reused. `activity` is empty when the responsiveness channel is
    disabled (no token / --no-stability-responsiveness).
    """

    by_url: dict[str, RepositoryStability | None] = {}
    by_package: dict[str, MaintenanceAssessment | None] = {}

    for record in records:
        url = record.repo_url or ""
        repo_commits = commits.get(url)
        if repo_commits:
            if url not in by_url:
                repo_activity = activity.get(url) if activity else None
                by_url[url] = repository_stability(repo_commits, now, repo_activity)
            record.stability = by_url[url]

        if record.repository is not None:
            record.days_since_push = age_days_from_iso(record.repository.pushed_at, now=now)

        record.maintenance = assess_maintenance(maintenance_observations(record))
        unstable = None
        if record.maintenance is not None:
            unstable = record.maintenance.p_not_maintained >= MAINTENANCE_THRESHOLD
        record.triage = triage(record.cve, unstable)

        if record.maintenance is not None or record.package_name not in by_package:
            by_package[record.package_name] = record.maintenance

    scored = [assessment for assessment in by_package.values() if assessment is not None]
    return ProjectStability(
        scored_packages=len(scored),
        unmaintained_packages=sum(1 for assessment in scored if assessment.state in NOT_MAINTAINED),
        deprecated_packages=sum(1 for assessment in scored if assessment.state == MaintenanceState.DEPRECATED),
        unknown_packages=len(by_package) - len(scored),
    )
