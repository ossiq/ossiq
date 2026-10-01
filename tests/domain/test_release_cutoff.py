"""
Tests for ReleaseCutoff in ossiq.domain.release_cutoff.
"""

from datetime import UTC, datetime

from ossiq.domain.release_cutoff import ReleaseCutoff

GLOBAL = datetime(2026, 9, 18, tzinfo=UTC)
LATER = datetime(2026, 9, 25, tzinfo=UTC)


class TestCutoffFor:
    def test_package_without_override_gets_default(self):
        assert ReleaseCutoff(default=GLOBAL).cutoff_for("idna") == GLOBAL

    def test_override_replaces_default_even_when_later(self):
        cutoff = ReleaseCutoff(default=GLOBAL, per_package={"idna": LATER})
        assert cutoff.cutoff_for("idna") == LATER

    def test_none_override_lifts_cutoff(self):
        cutoff = ReleaseCutoff(default=GLOBAL, per_package={"six": None})
        assert cutoff.cutoff_for("six") is None

    def test_no_default_leaves_other_packages_unrestricted(self):
        cutoff = ReleaseCutoff(per_package={"idna": GLOBAL})
        assert cutoff.cutoff_for("requests") is None
