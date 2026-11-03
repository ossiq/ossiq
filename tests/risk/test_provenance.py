"""Tests for the pure supply-chain policy: which releases build evidence rules out."""

from dataclasses import replace

import pytest

from ossiq.domain.provenance import ProvenancePolicy, SourceLevel, TrustTier
from ossiq.domain.version import PackageVersion
from ossiq.risk.provenance import build_violations, is_excluded, source_violation

NONE, PROV, TRUSTED = TrustTier.NONE, TrustTier.PROVENANCE, TrustTier.TRUSTED_PUBLISHER
NO_DOWNGRADE = ProvenancePolicy(no_downgrade=True)


def major_of(version: str):
    head = version.split(".")[0]
    return int(head) if head.isdigit() else None


def release(version: str, tier: TrustTier | None, published: str | None, *, pre: bool = False) -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url="",
        declared_dependencies={},
        published_date_iso=f"{published}T00:00:00Z" if published else None,
        is_prerelease=pre,
        trust_tier=tier,
    )


def violated(releases, policy=NO_DOWNGRADE, name="pkg") -> set[str]:
    return set(build_violations(releases, policy, name, major_of))


class TestNothingConfigured:
    def test_no_rule_means_no_violations(self):
        releases = [release("1.0.0", TRUSTED, "2024-01-01"), release("1.0.1", NONE, "2024-02-01")]

        assert build_violations(releases, ProvenancePolicy(), "pkg", major_of) == {}


class TestNoDowngrade:
    def test_a_release_weaker_than_an_earlier_one_is_flagged(self):
        releases = [release("1.0.0", TRUSTED, "2024-01-01"), release("1.0.1", NONE, "2024-02-01")]

        assert violated(releases) == {"1.0.1"}

    def test_the_reason_names_both_tiers(self):
        releases = [release("1.0.0", PROV, "2024-01-01"), release("1.0.1", NONE, "2024-02-01")]

        (reason,) = build_violations(releases, NO_DOWNGRADE, "pkg", major_of)["1.0.1"]

        assert "no provenance" in reason and "earlier releases of this major line had provenance" in reason

    def test_a_drop_from_trusted_publisher_to_plain_provenance_is_a_downgrade(self):
        releases = [release("1.0.0", TRUSTED, "2024-01-01"), release("1.0.1", PROV, "2024-02-01")]

        assert violated(releases) == {"1.0.1"}

    def test_a_release_that_recovers_the_tier_is_not_flagged_but_the_dip_stays(self):
        releases = [
            release("1.0.0", TRUSTED, "2024-01-01"),
            release("1.0.1", NONE, "2024-02-01"),
            release("1.0.2", TRUSTED, "2024-03-01"),
        ]

        assert violated(releases) == {"1.0.1"}

    def test_a_package_that_never_had_evidence_is_not_flagged(self):
        releases = [release("1.0.0", NONE, "2024-01-01"), release("1.0.1", NONE, "2024-02-01")]

        assert violated(releases) == set()

    def test_gaining_evidence_is_not_a_downgrade(self):
        releases = [release("1.0.0", NONE, "2024-01-01"), release("1.0.1", TRUSTED, "2024-02-01")]

        assert violated(releases) == set()

    def test_a_new_major_line_is_not_judged_against_the_old_one(self):
        releases = [release("1.0.0", TRUSTED, "2024-01-01"), release("2.0.0", NONE, "2024-02-01")]

        assert violated(releases) == set()

    def test_a_maintenance_release_is_judged_against_its_own_line_only(self):
        # v2 adopted trusted publishing; a later v1.x patch never had it and is not a downgrade.
        releases = [
            release("1.0.0", NONE, "2024-01-01"),
            release("2.0.0", TRUSTED, "2024-02-01"),
            release("1.0.1", NONE, "2024-03-01"),
        ]

        assert violated(releases) == set()

    def test_order_is_publish_time_not_version_number(self):
        # 1.1.0 was published first; the later, lower 1.0.9 does not make it a downgrade.
        releases = [release("1.1.0", NONE, "2024-01-01"), release("1.0.9", TRUSTED, "2024-02-01")]

        assert violated(releases) == set()

    def test_input_order_does_not_matter(self):
        releases = [release("1.0.1", NONE, "2024-02-01"), release("1.0.0", TRUSTED, "2024-01-01")]

        assert violated(releases) == {"1.0.1"}

    def test_releases_published_at_the_same_instant_are_not_earlier_than_each_other(self):
        releases = [release("1.0.0", TRUSTED, "2024-01-01"), release("1.0.1", NONE, "2024-01-01")]

        assert violated(releases) == set()


class TestPrereleases:
    def test_a_stable_release_ignores_prerelease_history(self):
        releases = [release("1.0.0-rc.1", TRUSTED, "2024-01-01", pre=True), release("1.0.0", NONE, "2024-02-01")]

        assert violated(releases) == set()

    def test_a_prerelease_is_judged_against_stable_and_prerelease_history(self):
        releases = [
            release("1.0.0", TRUSTED, "2024-01-01"),
            release("1.1.0-rc.1", NONE, "2024-02-01", pre=True),
        ]

        assert violated(releases) == {"1.1.0-rc.1"}

    def test_a_stable_release_is_still_judged_against_earlier_stable_ones(self):
        releases = [
            release("1.0.0", TRUSTED, "2024-01-01"),
            release("1.0.1-rc.1", TRUSTED, "2024-02-01", pre=True),
            release("1.0.1", NONE, "2024-03-01"),
        ]

        assert violated(releases) == {"1.0.1"}


class TestUnknownEvidence:
    def test_a_release_with_unknown_tier_is_never_flagged(self):
        releases = [release("1.0.0", TRUSTED, "2024-01-01"), release("1.0.1", None, "2024-02-01")]

        assert violated(releases) == set()

    def test_an_unknown_tier_is_not_history(self):
        releases = [release("1.0.0", None, "2024-01-01"), release("1.0.1", NONE, "2024-02-01")]

        assert violated(releases) == set()

    def test_an_undated_release_is_not_compared(self):
        releases = [release("1.0.0", TRUSTED, "2024-01-01"), release("1.0.1", NONE, None)]

        assert violated(releases) == set()

    def test_an_undated_release_is_not_history(self):
        releases = [release("1.0.0", TRUSTED, None), release("1.0.1", NONE, "2024-02-01")]

        assert violated(releases) == set()

    def test_a_malformed_timestamp_reads_as_undated(self):
        bad = replace(release("1.0.0", TRUSTED, "2024-01-01"), published_date_iso="not-a-date")

        assert violated([bad, release("1.0.1", NONE, "2024-02-01")]) == set()

    def test_an_unparseable_version_is_left_out_of_line_comparisons(self):
        releases = [release("weird", TRUSTED, "2024-01-01"), release("weird2", NONE, "2024-02-01")]

        assert violated(releases) == set()


class TestMinimumBuild:
    def test_a_release_below_the_floor_is_flagged(self):
        policy = ProvenancePolicy(min_build=PROV)
        releases = [release("1.0.0", NONE, "2024-01-01"), release("1.0.1", PROV, "2024-02-01")]

        assert violated(releases, policy) == {"1.0.0"}

    def test_a_trusted_publisher_floor_flags_plain_provenance(self):
        policy = ProvenancePolicy(min_build=TRUSTED)

        assert violated([release("1.0.0", PROV, "2024-01-01")], policy) == {"1.0.0"}

    def test_the_floor_needs_no_publish_date(self):
        policy = ProvenancePolicy(min_build=PROV)

        assert violated([release("1.0.0", NONE, None)], policy) == {"1.0.0"}

    def test_an_unknown_tier_is_not_below_the_floor(self):
        policy = ProvenancePolicy(min_build=TRUSTED)

        assert violated([release("1.0.0", None, "2024-01-01")], policy) == set()

    def test_a_release_can_break_both_rules_and_gets_both_reasons(self):
        policy = ProvenancePolicy(no_downgrade=True, min_build=TRUSTED)
        releases = [release("1.0.0", TRUSTED, "2024-01-01"), release("1.0.1", NONE, "2024-02-01")]

        assert len(build_violations(releases, policy, "pkg", major_of)["1.0.1"]) == 2


class TestExclusions:
    @pytest.mark.parametrize("entry", ["pkg", "pkg@1.0.1"])
    def test_an_excluded_release_is_not_flagged(self, entry):
        policy = ProvenancePolicy(no_downgrade=True, min_build=PROV, exclude=(entry,))
        releases = [release("1.0.0", TRUSTED, "2024-01-01"), release("1.0.1", NONE, "2024-02-01")]

        assert violated(releases, policy) == set()

    def test_a_version_entry_leaves_other_releases_judged(self):
        policy = ProvenancePolicy(min_build=PROV, exclude=("pkg@1.0.0",))
        releases = [release("1.0.0", NONE, "2024-01-01"), release("1.0.1", NONE, "2024-02-01")]

        assert violated(releases, policy) == {"1.0.1"}

    def test_an_exclusion_for_another_package_changes_nothing(self):
        policy = ProvenancePolicy(min_build=PROV, exclude=("other",))

        assert violated([release("1.0.0", NONE, "2024-01-01")], policy) == {"1.0.0"}

    def test_an_excluded_release_still_counts_as_history(self):
        policy = ProvenancePolicy(no_downgrade=True, exclude=("pkg@1.0.0",))
        releases = [release("1.0.0", TRUSTED, "2024-01-01"), release("1.0.1", NONE, "2024-02-01")]

        assert violated(releases, policy) == {"1.0.1"}


class TestIsExcluded:
    def test_a_bare_name_covers_every_release(self):
        assert is_excluded(["chokidar"], "chokidar", "4.0.3")

    def test_a_name_and_version_cover_that_release_only(self):
        assert is_excluded(["chokidar@4.0.3"], "chokidar", "4.0.3")
        assert not is_excluded(["chokidar@4.0.3"], "chokidar", "4.0.4")

    def test_a_scoped_name_is_not_read_as_a_version(self):
        assert is_excluded(["@types/node"], "@types/node", "18.0.0")
        assert not is_excluded(["@types/node"], "@types", "18.0.0")

    def test_a_scoped_name_with_a_version(self):
        assert is_excluded(["@types/node@18.0.0"], "@types/node", "18.0.0")
        assert not is_excluded(["@types/node@18.0.0"], "@types/node", "18.0.1")

    def test_nothing_is_excluded_by_an_empty_list(self):
        assert not is_excluded([], "pkg", "1.0.0")


@pytest.mark.parametrize("tier", list(TrustTier))
def test_a_history_of_one_tier_never_flags_a_downgrade(tier):
    releases = [release(f"1.0.{i}", tier, f"2024-0{i + 1}-01") for i in range(5)]

    assert violated(releases) == set()


@pytest.mark.parametrize("weaker, stronger", [(NONE, PROV), (PROV, TRUSTED), (NONE, TRUSTED)])
def test_a_stricter_floor_only_adds_violations(weaker, stronger):
    releases = [release(f"1.0.{i}", tier, f"2024-0{i + 1}-01") for i, tier in enumerate([NONE, PROV, TRUSTED, NONE])]

    loose = violated(releases, ProvenancePolicy(min_build=weaker))
    strict = violated(releases, ProvenancePolicy(min_build=stronger))

    assert loose <= strict


class TestSourceViolation:
    FLOOR = ProvenancePolicy(min_source=SourceLevel.PROTECTED_HISTORY)

    def test_a_repository_below_the_floor_is_a_violation(self):
        reason = source_violation(self.FLOOR, SourceLevel.VERSION_CONTROLLED)

        assert reason == "source repository is version-controlled, below the required protected-history"

    @pytest.mark.parametrize("level", [SourceLevel.PROTECTED_HISTORY, SourceLevel.REVIEWED])
    def test_a_repository_at_or_above_the_floor_passes(self, level):
        assert source_violation(self.FLOOR, level) is None

    def test_an_unmeasured_repository_never_violates(self):
        assert source_violation(self.FLOOR, None) is None

    def test_no_floor_asks_for_nothing(self):
        assert source_violation(ProvenancePolicy(), SourceLevel.VERSION_CONTROLLED) is None
