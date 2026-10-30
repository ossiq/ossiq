"""
Tests for ReleaseCutoff in ossiq.domain.release_cutoff.
"""

from datetime import UTC, datetime, timedelta

from ossiq.domain.release_cutoff import ReleaseCutoff

SOURCE = "uv exclude-newer"
GLOBAL = datetime(2026, 9, 18, tzinfo=UTC)
LATER = datetime(2026, 9, 25, tzinfo=UTC)


class TestCutoffFor:
    def test_package_without_override_gets_default(self):
        assert ReleaseCutoff(SOURCE, default=GLOBAL).cutoff_for("idna") == GLOBAL

    def test_override_replaces_default_even_when_later(self):
        cutoff = ReleaseCutoff(SOURCE, default=GLOBAL, per_package={"idna": LATER})
        assert cutoff.cutoff_for("idna") == LATER

    def test_none_override_lifts_cutoff(self):
        cutoff = ReleaseCutoff(SOURCE, default=GLOBAL, per_package={"six": None})
        assert cutoff.cutoff_for("six") is None

    def test_no_default_leaves_other_packages_unrestricted(self):
        cutoff = ReleaseCutoff(SOURCE, per_package={"idna": GLOBAL})
        assert cutoff.cutoff_for("requests") is None

    def test_lookup_name_is_normalized(self):
        cutoff = ReleaseCutoff(SOURCE, default=GLOBAL, per_package={"typing-extensions": None})
        assert cutoff.cutoff_for("Typing_Extensions") is None

    def test_scoped_glob_lifts_every_package_in_the_scope(self):
        cutoff = ReleaseCutoff(SOURCE, default=GLOBAL, per_package={"@types/*": None})
        assert cutoff.cutoff_for("@types/node") is None
        assert cutoff.cutoff_for("@typed/node") == GLOBAL

    def test_prefix_glob_does_not_lift_the_bare_name(self):
        # normalize_dist_name("react-*") would cut the pattern to "react" and lift it too.
        cutoff = ReleaseCutoff(SOURCE, default=GLOBAL, per_package={"react-*": None})
        assert cutoff.cutoff_for("react-dom") is None
        assert cutoff.cutoff_for("react") == GLOBAL

    def test_exact_entry_wins_over_a_glob(self):
        cutoff = ReleaseCutoff(SOURCE, default=GLOBAL, per_package={"react-*": None, "react-dom": LATER})
        assert cutoff.cutoff_for("react-dom") == LATER


class TestAdmits:
    def test_release_at_the_cutoff_is_admitted(self):
        assert ReleaseCutoff(SOURCE, default=GLOBAL).admits("idna", GLOBAL)

    def test_release_after_the_cutoff_is_refused(self):
        assert not ReleaseCutoff(SOURCE, default=GLOBAL).admits("idna", GLOBAL + timedelta(seconds=1))

    def test_unknown_publish_time_is_admitted(self):
        assert ReleaseCutoff(SOURCE, default=GLOBAL).admits("idna", None)

    def test_exempt_package_admits_anything(self):
        cutoff = ReleaseCutoff(SOURCE, default=GLOBAL, per_package={"six": None})
        assert cutoff.admits("six", LATER)
