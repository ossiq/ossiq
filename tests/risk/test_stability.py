"""Tests for the repository-stability formulas (commit gaps + engagement-flow trends)."""

import math
import statistics
from datetime import datetime, timedelta

import pytest

from ossiq.risk.stability import (
    ENGAGEMENT_SINCE_GRID_DAYS,
    FLOW_DECLINING,
    FLOW_IMPROVING,
    FLOW_STABLE,
    MIN_BUCKETS_FOR_TREND,
    MIN_GAPS,
    MIN_SILENCE_DAYS,
    RESPONSIVENESS_WINDOW_DAYS,
    SECONDS_PER_DAY,
    SILENCE_ALPHA,
    commit_gaps,
    commit_timestamps,
    engagement_window_since,
    flow_ratio,
    flow_trend,
    gap_dispersion,
    has_stopped,
    is_bot_author,
    is_bot_commit,
    silence_survival,
    trend_slope,
)

WEEK_ZERO = 1_700_000_000


def commit_at(date_str: str, *, login: str = "someone", account_type: str = "User") -> dict:
    """GitHub-shaped commit: just the fields is_bot_commit/commit_timestamps look at."""
    return {"commit": {"committer": {"date": date_str}}, "author": {"login": login, "type": account_type}}


class TestIsBotCommit:
    def test_bot_account_type_is_filtered(self) -> None:
        assert is_bot_commit(commit_at("2026-01-01T00:00:00Z", login="some-app", account_type="Bot"))

    def test_bracketed_bot_login_is_filtered(self) -> None:
        assert is_bot_commit(commit_at("2026-01-01T00:00:00Z", login="dependabot[bot]"))

    def test_known_bot_login_without_brackets_is_filtered(self) -> None:
        assert is_bot_commit(commit_at("2026-01-01T00:00:00Z", login="renovate"))

    def test_ordinary_contributor_is_not_filtered(self) -> None:
        assert not is_bot_commit(commit_at("2026-01-01T00:00:00Z", login="octocat"))

    def test_missing_author_is_not_filtered(self) -> None:
        assert not is_bot_commit({"commit": {"committer": {"date": "2026-01-01T00:00:00Z"}}, "author": None})


class TestCommitTimestamps:
    def test_uses_committer_date_not_author_date(self) -> None:
        commit = {
            "commit": {
                "author": {"date": "2020-01-01T00:00:00Z"},
                "committer": {"date": "2026-01-01T00:00:00Z"},
            },
            "author": {"login": "octocat", "type": "User"},
        }
        assert commit_timestamps([commit]) == [datetime.fromisoformat("2026-01-01T00:00:00Z").timestamp()]

    def test_filters_bot_commits(self) -> None:
        assert commit_timestamps([commit_at("2026-01-01T00:00:00Z", login="dependabot[bot]")]) == []

    def test_skips_commits_without_a_date(self) -> None:
        assert commit_timestamps([{"commit": {}, "author": None}]) == []


class TestCommitGaps:
    def test_computes_consecutive_gaps_in_days(self) -> None:
        timestamps = [WEEK_ZERO, WEEK_ZERO + SECONDS_PER_DAY, WEEK_ZERO + 3 * SECONDS_PER_DAY]
        assert commit_gaps(timestamps) == pytest.approx([1.0, 2.0])

    def test_sorts_unsorted_timestamps_first(self) -> None:
        timestamps = [WEEK_ZERO + 3 * SECONDS_PER_DAY, WEEK_ZERO, WEEK_ZERO + SECONDS_PER_DAY]
        assert commit_gaps(timestamps) == pytest.approx([1.0, 2.0])

    def test_single_timestamp_has_no_gaps(self) -> None:
        assert commit_gaps([WEEK_ZERO]) == []

    def test_empty_input_has_no_gaps(self) -> None:
        assert commit_gaps([]) == []


class TestGapDispersion:
    def test_constant_gaps_have_zero_dispersion(self) -> None:
        assert gap_dispersion([1.0, 1.0, 1.0]) == 0.0

    def test_known_sequence(self) -> None:
        assert gap_dispersion([8.0, 10.0, 12.0]) == pytest.approx(0.2)

    def test_needs_two_gaps(self) -> None:
        assert gap_dispersion([5.0]) is None
        assert gap_dispersion([]) is None

    def test_zero_mean_is_undefined(self) -> None:
        assert gap_dispersion([0.0, 0.0]) is None


class TestSilenceSurvival:
    def test_empirical_fraction_at_min_gaps(self) -> None:
        gaps = [1.0] * (MIN_GAPS - 1) + [100.0]
        assert silence_survival(gaps, 50.0) == pytest.approx(1 / MIN_GAPS)

    def test_falls_back_to_exponential_below_min_gaps(self) -> None:
        gaps = [10.0] * (MIN_GAPS - 1)
        mean_gap = statistics.mean(gaps)
        assert silence_survival(gaps, 20.0) == pytest.approx(math.exp(-20.0 / mean_gap))

    def test_no_gaps_is_undefined(self) -> None:
        assert silence_survival([], 30.0) is None

    def test_zero_mean_fallback_is_undefined(self) -> None:
        assert silence_survival([0.0] * (MIN_GAPS - 1), 30.0) is None


class TestHasStopped:
    def test_stops_when_both_conditions_hold(self) -> None:
        assert has_stopped(0.01, MIN_SILENCE_DAYS) is True

    def test_calm_but_alive_is_not_stopped(self) -> None:
        assert has_stopped(0.5, MIN_SILENCE_DAYS + 100) is False

    def test_hyperactive_repository_is_not_stopped(self) -> None:
        assert has_stopped(0.0, MIN_SILENCE_DAYS - 1) is False

    def test_none_inputs_are_unmeasured(self) -> None:
        assert has_stopped(None, 40.0) is None
        assert has_stopped(0.01, None) is None
        assert has_stopped(None, None) is None


class TestIsBotAuthor:
    def test_graphql_bot_typename_is_filtered(self) -> None:
        assert is_bot_author({"__typename": "Bot", "login": "some-app"})

    def test_rest_bot_type_is_filtered(self) -> None:
        assert is_bot_author({"type": "Bot"})

    def test_bracketed_and_known_bot_logins_are_filtered(self) -> None:
        assert is_bot_author({"login": "renovate[bot]"})
        assert is_bot_author({"login": "dependabot"})

    def test_human_and_missing_authors_are_not_filtered(self) -> None:
        assert not is_bot_author({"__typename": "User", "login": "octocat"})
        assert not is_bot_author(None)
        assert not is_bot_author({})


class TestFlowRatio:
    def test_keeping_pace_is_about_one(self) -> None:
        assert flow_ratio(5, 5) == pytest.approx(1.0)

    def test_draining_backlog_exceeds_one(self) -> None:
        assert flow_ratio(2, 6) == pytest.approx(3.0)

    def test_falling_behind_trends_to_zero(self) -> None:
        assert flow_ratio(8, 0) == 0.0

    def test_no_movement_is_no_signal(self) -> None:
        assert flow_ratio(0, 0) is None

    def test_closing_old_backlog_with_nothing_new(self) -> None:
        assert flow_ratio(0, 3) == pytest.approx(3.0)


class TestTrendSlope:
    def test_rising_series_has_positive_slope(self) -> None:
        assert trend_slope([1.0, 2.0, 3.0, 4.0, 5.0]) == pytest.approx(1.0)

    def test_flat_series_has_zero_slope(self) -> None:
        assert trend_slope([2.0, 2.0, 2.0, 2.0]) == pytest.approx(0.0)

    def test_below_min_buckets_is_none(self) -> None:
        assert trend_slope([1.0] * (MIN_BUCKETS_FOR_TREND - 1)) is None

    def test_none_values_are_dropped_but_keep_their_index(self) -> None:
        # x = [0, 2, 4, 6], y = [0, 2, 4, 6]  -> slope 1.0
        assert trend_slope([0.0, None, 2.0, None, 4.0, None, 6.0]) == pytest.approx(1.0)


class TestFlowTrend:
    def test_none_below_min_buckets(self) -> None:
        assert flow_trend([1.0, 1.0]) is None

    def test_steady_ratio_is_stable(self) -> None:
        assert flow_trend([1.0, 1.0, 1.0, 1.0, 1.0, 1.0]) == FLOW_STABLE

    def test_rising_ratio_is_improving(self) -> None:
        assert flow_trend([0.2, 0.4, 0.6, 0.8, 1.0, 1.2]) == FLOW_IMPROVING

    def test_falling_ratio_is_declining(self) -> None:
        assert flow_trend([1.2, 1.0, 0.8, 0.6, 0.4, 0.2]) == FLOW_DECLINING

    def test_sharp_recent_drop_forces_declining_on_a_shallow_slope(self) -> None:
        # long flat history at ~1.0, then the last two buckets collapse
        assert flow_trend([1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 0.1, 0.0]) == FLOW_DECLINING


class TestEngagementWindowSince:
    def test_snapped_to_the_grid_and_stable_within_it(self) -> None:
        base = datetime.fromisoformat("2026-08-30T14:23:57+00:00")
        first = engagement_window_since(base)
        # any time inside the same 7-day grid cell yields the identical string
        later = engagement_window_since(datetime.fromisoformat("2026-09-02T09:00:00+00:00"))
        assert first == later
        assert first.endswith("T00:00:00Z")

    def test_moves_by_whole_grid_steps(self) -> None:
        step = timedelta(days=ENGAGEMENT_SINCE_GRID_DAYS)
        base = datetime.fromisoformat("2026-08-30T00:00:00+00:00")
        assert engagement_window_since(base + step) != engagement_window_since(base)

    def test_start_is_about_a_window_before_now(self) -> None:
        now = datetime.fromisoformat("2026-08-30T12:00:00+00:00")
        start = datetime.fromisoformat(engagement_window_since(now).replace("Z", "+00:00"))
        age_days = (now - start).days
        assert RESPONSIVENESS_WINDOW_DAYS <= age_days <= RESPONSIVENESS_WINDOW_DAYS + ENGAGEMENT_SINCE_GRID_DAYS


def test_gap_constants_are_sane() -> None:
    assert MIN_GAPS >= 2
    assert 0 < SILENCE_ALPHA < 1
    assert MIN_SILENCE_DAYS > 0
    assert RESPONSIVENESS_WINDOW_DAYS > 0
    assert MIN_BUCKETS_FOR_TREND >= 2
