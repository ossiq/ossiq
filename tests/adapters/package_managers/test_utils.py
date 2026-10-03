"""
Tests for ossiq.adapters.package_managers.utils.
"""

from datetime import UTC, datetime, timedelta

import pytest

from ossiq.adapters.package_managers.utils import parse_exclude_newer, parse_friendly_span

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


class TestParseExcludeNewer:
    def test_rfc3339_timestamp(self):
        assert parse_exclude_newer("2026-09-18T00:00:00Z", now=NOW) == datetime(2026, 9, 18, tzinfo=UTC)

    def test_offset_timestamp_keeps_its_offset(self):
        parsed = parse_exclude_newer("2026-09-18T02:00:00+02:00", now=NOW)
        assert parsed == datetime(2026, 9, 18, tzinfo=UTC)

    def test_date_only_is_end_of_that_local_day(self):
        parsed = parse_exclude_newer("2026-09-18", now=NOW)
        assert parsed == datetime(2026, 9, 19).astimezone()

    @pytest.mark.parametrize(
        ("span", "delta"),
        [
            ("P7D", timedelta(days=7)),
            ("P1W", timedelta(weeks=1)),
            ("PT24H", timedelta(hours=24)),
            ("P1DT30M", timedelta(days=1, minutes=30)),
            ("P1W2D", timedelta(days=9)),
        ],
    )
    def test_iso_span_counts_back_from_now(self, span: str, delta: timedelta):
        assert parse_exclude_newer(span, now=NOW) == NOW - delta

    @pytest.mark.parametrize(
        ("span", "delta"),
        [
            ("7 days", timedelta(days=7)),
            ("1 week", timedelta(weeks=1)),
            ("24h", timedelta(hours=24)),
            ("1w 2d", timedelta(days=9)),
            ("2 days, 3 hours", timedelta(days=2, hours=3)),
            ("1d12h", timedelta(days=1, hours=12)),
            ("90m", timedelta(minutes=90)),
            ("1 wk", timedelta(weeks=1)),
        ],
    )
    def test_friendly_span_counts_back_from_now(self, span: str, delta: timedelta):
        assert parse_exclude_newer(span, now=NOW) == NOW - delta

    # Every value here is one uv 0.12 drops without applying a cutoff: calendar units, fractions,
    # "ago", uppercase units, and the string "false".
    @pytest.mark.parametrize(
        "value",
        ["P1M", "P1Y", "1 month", "1.5 days", "7 days ago", "3 DAYS", "false", "P", "PT", "P0D", "soon", "", None, 5],
    )
    def test_values_uv_rejects_return_none(self, value: object):
        assert parse_exclude_newer(value, now=NOW) is None

    def test_boolean_false_means_no_cutoff(self):
        assert parse_exclude_newer(False, now=NOW) is None


class TestParseFriendlySpan:
    def test_unknown_unit_rejects_the_whole_value(self):
        assert parse_friendly_span("2 days 3 fortnights") is None

    def test_zero_span_is_no_span(self):
        assert parse_friendly_span("0 days") is None
