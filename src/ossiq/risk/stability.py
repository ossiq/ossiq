"""
Repository stability formulas - commit-gap dormancy and engagement-flow trends.

The commit channel (gap sampling -> `gap_cv` / `silence_p` / `has_stopped`) is validated and
drives triage: see TODO.md and `docs/explanation/repository-stability.md`.

The engagement channel is directional rather than absolute. It tracks issue / pull-request
*flow* (items closed vs opened) over ~30-day buckets and reports the trend - the same
self-referential trick `has_stopped` uses for commits, comparing
a repository against its own recent history rather than a cross-repo corridor. The
arXiv:2504.00542 corridor normalizer it replaces did not transfer to a 120-day GitHub sample:
arXiv:2508.01358 found phi_i = 0 across all 90 repositories it studied, and the 39-repo
calibration run here reproduced the collapse for every channel.

Both channels feed the maintenance-state model in `risk/maintenance.py` as observations, not
a weighted sum.
"""

import math
import re
import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

MIN_GAPS = 20
"""Below this many inter-commit gaps, gap_dispersion isn't trustworthy - too few points."""

MIN_SILENCE_DAYS = 90
"""Absolute floor under the dormancy conjunction: `has_stopped` cannot fire until a repository
has been silent this long, whatever its own gap history says. A month or two of quiet is common
for a low-churn library (`pypa/distlib`, `pypa/setuptools`); three months is the point where an
unusually long silence starts to look like abandonment rather than a lull. Also the floor that
stops a hyperactive repo's random long weekend tripping the p-value alone."""

SILENCE_ALPHA = 0.05
"""p-value below which the current silence counts as unusual for this repository's own history."""

RESPONSIVENESS_WINDOW_DAYS = 180
"""Look-back window for the engagement channel: six ~30-day buckets, enough to fit a flow trend
without paginating a busy repo's whole year of issues (which trips GitHub's secondary rate
limit). Per-bucket `closed` counts (not cumulative totals) keep the ratio current - the fix for
the "denominator drag" arXiv:2508.01358 identified."""

ENGAGEMENT_BUCKET_DAYS = 30
"""Bucket width for the engagement flow series."""

ENGAGEMENT_SINCE_GRID_DAYS = 7
"""The activity-window start is snapped down to a 7-day grid. Its ISO string is part of the
GraphQL POST cache key, so snapping keeps `since` identical across a week of re-scans - the
window then slides in weekly jumps, which the look-back does not notice, and a repeat scan
inside the stability cache TTL costs zero GraphQL requests instead of refetching all of them
because `since` moved by a few seconds."""

MIN_BUCKETS_FOR_TREND = 3
"""Below this many measured buckets, the flow trend is None (unmeasured) rather than 'stable'."""

FLOW_TREND_SLOPE = 0.03
"""|OLS slope of flow_ratio per bucket| at or above which the flow trend is called directional."""

SECONDS_PER_DAY = 24 * 60 * 60

BOT_LOGIN_RE = re.compile(r".*\[bot\]$|^(dependabot|renovate|pre-commit-ci|github-actions)$", re.IGNORECASE)


def is_bot_author(author: Mapping | None) -> bool:
    """True when a GitHub actor is a bot account.

    Handles the REST commit shape (`type: "Bot"`) and the GraphQL shape (`__typename: "Bot"`),
    plus the bot login patterns. Applied to commit authors and to issue / PR / comment authors -
    a weekly dependabot commit or a stream of renovate PRs otherwise makes a dead repo read as
    healthy and inflates phi_p.
    """

    author = author or {}
    if author.get("type") == "Bot" or author.get("__typename") == "Bot":
        return True
    return bool(BOT_LOGIN_RE.match(author.get("login") or ""))


def is_bot_commit(commit: Mapping) -> bool:
    """True when a commit's GitHub author is a bot account - see is_bot_author."""

    return is_bot_author(commit.get("author"))


def commit_timestamps(commits: Sequence[Mapping]) -> list[float]:
    """Epoch-second committer dates for non-bot commits, unsorted.

    Uses commit.committer.date, not commit.author.date - author dates survive rebase and
    cherry-pick and are occasionally in the future.
    """

    timestamps = []
    for commit in commits:
        if is_bot_commit(commit):
            continue
        date_str = ((commit.get("commit") or {}).get("committer") or {}).get("date")
        if date_str is None:
            continue
        timestamps.append(datetime.fromisoformat(date_str).timestamp())
    return timestamps


def commit_gaps(timestamps: Sequence[float]) -> list[float]:
    """Inter-commit gaps in days, oldest -> newest. `timestamps` need not be pre-sorted."""

    ordered = sorted(timestamps)
    return [(later - earlier) / SECONDS_PER_DAY for earlier, later in zip(ordered, ordered[1:], strict=False)]


def gap_dispersion(gaps: Sequence[float]) -> float | None:
    """Coefficient of variation of inter-commit gaps. 1.0 == memoryless (Exponential) - volume-free
    by construction, unlike a weekly-bucket commit CV. None when there's no variance to measure."""

    if len(gaps) < 2:
        return None
    mean = statistics.mean(gaps)
    if math.isclose(mean, 0.0):
        return None
    return statistics.stdev(gaps) / mean


def silence_survival(gaps: Sequence[float], silence_days: float) -> float | None:
    """Empirical probability, from this repo's own gap history, of a gap at least this long.

    Empirical rather than fitted, because real gap distributions are overdispersed: the fraction
    of historical gaps exceeding `silence_days`, once there are enough gaps to resolve a
    percentile (>= MIN_GAPS). Falls back to a fitted exponential tail below that. None when there
    are no gaps at all to compare against.
    """

    if not gaps:
        return None
    if len(gaps) >= MIN_GAPS:
        return sum(1 for gap in gaps if gap > silence_days) / len(gaps)
    mean_gap = statistics.mean(gaps)
    if math.isclose(mean_gap, 0.0):
        return None
    return math.exp(-silence_days / mean_gap)


def has_stopped(silence_p: float | None, silence_days: float | None) -> bool | None:
    """Is the current silence unusual for this repository, on its own history?

    A conjunction: the p-value clears calm-but-alive repos (a 60-day typical gap makes a 90-day
    silence unremarkable); the MIN_SILENCE_DAYS floor clears both a hyperactive repo's long
    weekend and a low-churn library's ordinary two-month lull. None when either input is
    unavailable.
    """

    if silence_p is None or silence_days is None:
        return None
    return silence_p < SILENCE_ALPHA and silence_days >= MIN_SILENCE_DAYS


FLOW_IMPROVING = "improving"
FLOW_STABLE = "stable"
FLOW_DECLINING = "declining"


@dataclass(frozen=True)
class EngagementBucket:
    """One ~30-day slice of issue / pull-request flow. `index` 0 is the oldest bucket in the window.

    `*_closed` / `*_merged` count items that closed *in* this bucket regardless of when they
    opened - the cohort-matched denominator that arXiv:2508.01358's cumulative totals lacked.
    """

    index: int
    issues_opened: int
    issues_closed: int
    prs_opened: int
    prs_merged: int


@dataclass(frozen=True)
class EngagementSeries:
    """Bucketed engagement flow plus the flow-trend verdict fitted over it. `buckets` is persisted
    raw so the trend can be re-fitted offline, the same rule the gap fields follow."""

    buckets: list[EngagementBucket]
    flow_trend: str | None


def flow_ratio(opened: int, closed: int) -> float | None:
    """closed / max(opened, 1). > 1 draining backlog, ~= 1 keeping pace, -> 0 falling behind.

    None when the bucket had no issue / PR movement at all - that is no signal, not "behind".
    """

    if opened == 0 and closed == 0:
        return None
    return closed / max(opened, 1)


def trend_slope(values: Sequence[float | None]) -> float | None:
    """Least-squares slope of the non-None `values` against their real bucket index.

    Dropping empty buckets but keeping their index means a run of quiet months still spreads
    the fit rather than collapsing it. None below MIN_BUCKETS_FOR_TREND measured points.
    """

    points = [(index, value) for index, value in enumerate(values) if value is not None]
    if len(points) < MIN_BUCKETS_FOR_TREND:
        return None
    return statistics.linear_regression([x for x, _ in points], [y for _, y in points]).slope


def flow_trend(flow_ratios: Sequence[float | None]) -> str | None:
    """Direction of the issue / PR flow ratio across the buckets, oldest -> newest.

    The OLS slope is the baseline call. A sharp recent drop - the last two measured buckets
    averaging under 60% of the earlier median - forces 'declining' even on a shallow slope,
    because that is exactly the "outflow just stopped" case the trend exists to catch. None
    below MIN_BUCKETS_FOR_TREND measured buckets.
    """

    slope = trend_slope(flow_ratios)
    if slope is None:
        return None
    measured = [ratio for ratio in flow_ratios if ratio is not None]
    earlier, recent = measured[:-2], measured[-2:]
    if earlier and recent:
        earlier_median = statistics.median(earlier)
        if earlier_median > 0 and statistics.mean(recent) < 0.6 * earlier_median:
            return FLOW_DECLINING
    if slope <= -FLOW_TREND_SLOPE:
        return FLOW_DECLINING
    if slope >= FLOW_TREND_SLOPE:
        return FLOW_IMPROVING
    return FLOW_STABLE


def engagement_window_since(now: datetime | None = None) -> str:
    """ISO-8601 (UTC) start of the engagement look-back window, for the GraphQL `since` filter.

    Snapped down to ENGAGEMENT_SINCE_GRID_DAYS so repeated scans inside the stability cache
    window produce the identical string and hit the GraphQL POST cache. Pass the scan's cutoff
    date as `now` for a reproducible historical scan; snapping a fixed date is idempotent.
    """

    boundary = now or datetime.now(tz=UTC)
    grid_seconds = ENGAGEMENT_SINCE_GRID_DAYS * SECONDS_PER_DAY
    snapped = (boundary.timestamp() // grid_seconds) * grid_seconds
    start = datetime.fromtimestamp(snapped, tz=UTC) - timedelta(days=RESPONSIVENESS_WINDOW_DAYS)
    return start.strftime("%Y-%m-%dT00:00:00Z")
