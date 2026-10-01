"""
Tests for ossiq.adapters.package_managers.utils.
"""

from datetime import UTC, datetime, timedelta

import pytest

from ossiq.adapters.package_managers.utils import parse_exclude_newer

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
            ("P1M", timedelta(days=31)),
            ("P1Y", timedelta(days=366)),
        ],
    )
    def test_iso_span_counts_back_from_now(self, span: str, delta: timedelta):
        assert parse_exclude_newer(span, now=NOW) == NOW - delta

    @pytest.mark.parametrize("value", ["7 days", "P", "PT", "P0D", "soon", "", None, False, 5])
    def test_unreadable_values_return_none(self, value: object):
        assert parse_exclude_newer(value, now=NOW) is None
