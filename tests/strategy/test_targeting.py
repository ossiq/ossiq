"""Tests for select_target: the pure selector over a pre-tagged candidate ladder."""

import dataclasses
import random
from datetime import UTC, datetime, timedelta
from typing import Any

from ossiq.domain.common import RecommendationRung
from ossiq.domain.release_cutoff import ReleaseCutoff
from ossiq.strategy.motive import PackageFacts
from ossiq.strategy.pyramid import PYRAMID, UpdateStrategy
from ossiq.strategy.targeting import Candidate, select_target

IN_RANGE = RecommendationRung.IN_RANGE
IN_MAJOR = RecommendationRung.IN_MAJOR
LATEST = RecommendationRung.LATEST

BASE_FACTS = PackageFacts(
    package_name="example",
    installed_version="1.0.0",
    cve_epss_scores=(),
    maintenance_state=None,
    is_registry_deprecated=False,
    deprecation_strength="none",
)


def make_facts(**overrides: Any) -> PackageFacts:
    return dataclasses.replace(BASE_FACTS, **overrides)


def test_requests_security_takes_nearest_clear_not_latest() -> None:
    facts = make_facts(cve_epss_scores=(0.5,))
    candidates = [
        Candidate("2.29.0", IN_RANGE, has_cve=True),
        Candidate("2.30.0", IN_RANGE, has_cve=True),
        Candidate("2.31.0", IN_RANGE, has_cve=True),
        Candidate("2.32.0", IN_RANGE, has_cve=False),
        Candidate("2.33.0", IN_RANGE, has_cve=False),
        Candidate("2.34.2", IN_RANGE, has_cve=False),
    ]

    security = select_target(facts, UpdateStrategy.SECURITY, candidates)
    assert security.target_version == "2.32.0"

    standard = select_target(facts, UpdateStrategy.STANDARD, candidates)
    assert standard.target_version == "2.34.2"


def test_pydantic_across_all_five_tiers() -> None:
    facts = make_facts()  # no CVE, no maintenance signal — drift only
    candidates = (
        [Candidate(f"1.10.{n}", IN_MAJOR, has_cve=False) for n in range(14, 27)]
        + [Candidate(f"2.{n}.0", LATEST, has_cve=False) for n in range(14)]
        + [Candidate("2.13.5", LATEST, has_cve=False)]
    )

    security = select_target(facts, UpdateStrategy.SECURITY, candidates)
    assert security.target_version is None
    assert security.withheld_reason is not None

    # The named done-criterion for the version ladder (TODO #1): drift alone must still reach
    # the newest same-major patch under the default tier, not just under `latest`. Regression
    # test for rule 7 - without it, `standard`'s base IN_RANGE reach leaves this None, which is
    # the exact 0%-vs-90% benchmark scenario TODO #1 was filed over.
    standard = select_target(facts, UpdateStrategy.STANDARD, candidates)
    assert standard.target_version == "1.10.26"
    assert standard.rung == IN_MAJOR
    assert standard.requires_widening is True

    latest = select_target(facts, UpdateStrategy.LATEST, candidates)
    assert latest.target_version == "2.13.5"
    assert latest.requires_widening is True


def test_every_reachable_candidate_cve_affected_still_picks_newest() -> None:
    facts = make_facts(cve_epss_scores=(0.5,))
    candidates = [
        Candidate("1.1.0", IN_RANGE, has_cve=True),
        Candidate("1.2.0", IN_RANGE, has_cve=True),
        Candidate("1.3.0", IN_RANGE, has_cve=True),
    ]

    selection = select_target(facts, UpdateStrategy.SECURITY, candidates)
    assert selection.target_version == "1.3.0"
    assert selection.escalation is not None


def test_freshness_tier_maximises_minimal_diff_tier_minimises() -> None:
    facts = make_facts(cve_epss_scores=(0.5,))
    candidates = [
        Candidate("1.1.0", IN_RANGE, has_cve=False),
        Candidate("1.2.0", IN_RANGE, has_cve=False),
        Candidate("1.3.0", IN_RANGE, has_cve=False),
    ]

    minimal_diff = select_target(facts, UpdateStrategy.SECURITY, candidates)
    freshness = select_target(facts, UpdateStrategy.STANDARD, candidates)

    assert minimal_diff.target_version == "1.1.0"
    assert freshness.target_version == "1.3.0"


def test_no_admitted_motive_withholds_and_names_lowest_tier() -> None:
    facts = make_facts()  # only DRIFT
    candidates = [Candidate("1.1.0", IN_RANGE, has_cve=False)]

    selection = select_target(facts, UpdateStrategy.SECURITY, candidates)
    assert selection.target_version is None
    assert selection.withheld_reason is not None
    assert "standard" in selection.withheld_reason


def test_end_of_life_escalates_reach_at_deprecation_tier() -> None:
    facts = make_facts(maintenance_state="abandoned")
    candidates = [
        Candidate("1.1.0", IN_MAJOR, has_cve=False),
        Candidate("2.0.0", LATEST, has_cve=False),
    ]

    selection = select_target(facts, UpdateStrategy.DEPRECATION, candidates)
    assert selection.target_version is not None
    assert selection.requires_widening is True


def test_no_candidates_in_reach_yields_no_target_without_withheld_reason() -> None:
    facts = make_facts()
    candidates: list[Candidate] = []
    selection = select_target(facts, UpdateStrategy.STANDARD, candidates)
    assert selection.target_version is None
    assert selection.withheld_reason is None


def test_cooldown_prefers_the_newest_aged_release_over_a_fresher_one() -> None:
    """The reported defect: status recommended 0.10.0 (5d) while apply held it, with 0.9.0 (12d)
    sitting unrecommended in between."""
    facts = make_facts(installed_version="0.8.0")
    candidates = [
        Candidate("0.9.0", IN_RANGE, has_cve=False, age_days=12),
        Candidate("0.10.0", IN_RANGE, has_cve=False, age_days=5),
    ]

    selection = select_target(facts, UpdateStrategy.STANDARD, candidates, cooldown_period=7)
    assert selection.target_version == "0.9.0"
    assert selection.cooldown_hold is None
    assert selection.cooldown_bypassed is False


def test_cooldown_of_zero_is_a_no_op() -> None:
    facts = make_facts(installed_version="0.8.0")
    candidates = [
        Candidate("0.9.0", IN_RANGE, has_cve=False, age_days=12),
        Candidate("0.10.0", IN_RANGE, has_cve=False, age_days=5),
    ]

    assert select_target(facts, UpdateStrategy.STANDARD, candidates, cooldown_period=0).target_version == "0.10.0"
    assert select_target(facts, UpdateStrategy.STANDARD, candidates).target_version == "0.10.0"


def test_nothing_aged_leaves_no_target_and_records_the_hold() -> None:
    facts = make_facts()
    candidates = [
        Candidate("1.1.0", IN_RANGE, has_cve=False, age_days=3),
        Candidate("1.2.0", IN_RANGE, has_cve=False, age_days=1),
    ]

    selection = select_target(facts, UpdateStrategy.STANDARD, candidates, cooldown_period=7)
    assert selection.target_version is None
    assert selection.withheld_reason is None  # the tier admitted drift; the cooldown is the blocker
    assert selection.cooldown_hold is not None
    assert selection.cooldown_hold.version == "1.2.0"
    assert selection.cooldown_hold.age_days == 1
    assert selection.cooldown_hold.cooldown_period == 7


def test_exploitable_cve_outranks_the_cooldown() -> None:
    facts = make_facts(cve_epss_scores=(0.5,))
    candidates = [
        Candidate("1.1.0", IN_RANGE, has_cve=True, age_days=40),
        Candidate("1.2.0", IN_RANGE, has_cve=False, age_days=2),
    ]

    for tier in (UpdateStrategy.SECURITY, UpdateStrategy.STANDARD):
        selection = select_target(facts, tier, candidates, cooldown_period=7)
        assert selection.target_version == "1.2.0", tier
        assert selection.cooldown_bypassed is True, tier
        assert selection.cooldown_hold is None, tier


def test_end_of_life_outranks_the_cooldown() -> None:
    facts = make_facts(maintenance_state="abandoned")
    candidates = [Candidate("2.0.0", LATEST, has_cve=False, age_days=2)]

    selection = select_target(facts, UpdateStrategy.DEPRECATION, candidates, cooldown_period=7)
    assert selection.target_version == "2.0.0"
    assert selection.cooldown_bypassed is True


def test_escalation_over_the_settled_ladder_not_the_raw_one() -> None:
    """Rule 8's widening walk must see the cooldown-filtered ladder, or it reaches past an aged
    same-major release to a fresh breaking major."""
    facts = make_facts()
    candidates = [
        Candidate("1.10.1", IN_MAJOR, has_cve=False, age_days=30),
        Candidate("2.0.0", LATEST, has_cve=False, age_days=2),
    ]

    selection = select_target(facts, UpdateStrategy.LATEST, candidates, cooldown_period=7)
    assert selection.target_version == "1.10.1"
    assert selection.cooldown_bypassed is False


def test_a_release_with_no_publish_date_is_never_held() -> None:
    """Missing registry data must not withhold a bump — the same rule is_held_for_cooldown uses."""
    facts = make_facts()
    candidates = [Candidate("1.1.0", IN_RANGE, has_cve=False, age_days=None)]

    selection = select_target(facts, UpdateStrategy.STANDARD, candidates, cooldown_period=7)
    assert selection.target_version == "1.1.0"
    assert selection.cooldown_hold is None
    assert selection.cooldown_bypassed is False


def _random_candidates(rng: random.Random, n: int) -> list[Candidate]:
    rung_cycle = [IN_RANGE, IN_MAJOR, LATEST]
    current = 0
    candidates = []
    for i in range(n):
        if rng.random() < 0.3 and current < 2:
            current += 1
        candidates.append(Candidate(f"1.0.{i}", rung_cycle[current], has_cve=rng.random() < 0.4))
    return candidates


def test_monotonic_across_tiers() -> None:
    rng = random.Random(1234)
    for _ in range(300):
        facts = make_facts(
            cve_epss_scores=tuple(rng.choice([None, 0.001, 0.5]) for _ in range(rng.randint(0, 2))),
            maintenance_state=rng.choice([None, "maintained", "winding_down", "abandoned", "deprecated"]),
            is_registry_deprecated=rng.random() < 0.1,
            deprecation_strength=rng.choice(["none", "weak", "strong"]),
        )
        candidates = _random_candidates(rng, rng.randint(0, 6))
        version_index = {c.version: i for i, c in enumerate(candidates)}

        indices = []
        for tier in PYRAMID:
            selection = select_target(facts, tier, candidates)
            idx = version_index[selection.target_version] if selection.target_version else -1
            indices.append(idx)

        assert indices == sorted(indices), (facts, candidates, indices)


# The package manager's release cutoff (uv exclude-newer): enforced, per package, unlike the cooldown.

UV_CUTOFF_AT = datetime(2026, 9, 24, tzinfo=UTC)
UV_CUTOFF = ReleaseCutoff("uv exclude-newer", default=UV_CUTOFF_AT)


def published(days_before_cutoff: int) -> datetime:
    return UV_CUTOFF_AT - timedelta(days=days_before_cutoff)


def test_release_cutoff_drops_what_the_installer_refuses() -> None:
    facts = make_facts()
    candidates = [
        Candidate("1.1.0", IN_RANGE, has_cve=False, age_days=30, published_at=published(20)),
        Candidate("1.2.0", IN_RANGE, has_cve=False, age_days=8, published_at=published(-2)),
    ]

    selection = select_target(facts, UpdateStrategy.STANDARD, candidates, release_cutoff=UV_CUTOFF)
    assert selection.target_version == "1.1.0"
    assert selection.cooldown_hold is None


def test_release_cutoff_hold_names_the_package_manager() -> None:
    facts = make_facts()
    candidates = [
        Candidate("1.1.0", IN_RANGE, has_cve=False, age_days=9, published_at=published(-1)),
        Candidate("1.2.0", IN_RANGE, has_cve=False, age_days=8, published_at=published(-2)),
    ]

    selection = select_target(facts, UpdateStrategy.STANDARD, candidates, cooldown_period=7, release_cutoff=UV_CUTOFF)
    assert selection.target_version is None
    assert selection.cooldown_hold is not None
    assert selection.cooldown_hold.version == "1.2.0"
    assert selection.cooldown_hold.enforced_by == "uv exclude-newer"
    assert selection.cooldown_hold.cutoff == UV_CUTOFF_AT


def test_no_motive_outranks_the_release_cutoff() -> None:
    """A CVE outranks OSS IQ's cooldown, but a fix the installer refuses is no answer at all."""
    for facts in (make_facts(cve_epss_scores=(0.5,)), make_facts(maintenance_state="abandoned")):
        candidates = [Candidate("1.2.0", IN_RANGE, has_cve=False, age_days=2, published_at=published(-5))]

        selection = select_target(
            facts, UpdateStrategy.STANDARD, candidates, cooldown_period=7, release_cutoff=UV_CUTOFF
        )
        assert selection.target_version is None
        assert selection.cooldown_bypassed is False
        assert selection.cooldown_hold is not None
        assert selection.cooldown_hold.enforced_by == "uv exclude-newer"


def test_a_fix_the_cutoff_refuses_is_named_in_the_escalation() -> None:
    facts = make_facts(cve_epss_scores=(0.5,))
    candidates = [
        Candidate("1.1.0", IN_RANGE, has_cve=True, age_days=40, published_at=published(30)),
        Candidate("1.2.0", IN_RANGE, has_cve=False, age_days=2, published_at=published(-5)),
    ]

    selection = select_target(facts, UpdateStrategy.SECURITY, candidates, release_cutoff=UV_CUTOFF)
    assert selection.target_version == "1.1.0"
    assert selection.escalation is not None
    assert "1.2.0 clears it but uv exclude-newer refuses it" in selection.escalation


def test_the_stricter_of_cooldown_and_release_cutoff_wins() -> None:
    facts = make_facts()
    # Admitted by uv (published before its cutoff) but younger than OSS IQ's 7-day cooldown.
    young = Candidate("1.2.0", IN_RANGE, has_cve=False, age_days=3, published_at=published(1))
    aged = Candidate("1.1.0", IN_RANGE, has_cve=False, age_days=30, published_at=published(25))

    selection = select_target(
        facts, UpdateStrategy.STANDARD, [aged, young], cooldown_period=7, release_cutoff=UV_CUTOFF
    )
    assert selection.target_version == "1.1.0"

    held = select_target(facts, UpdateStrategy.STANDARD, [young], cooldown_period=7, release_cutoff=UV_CUTOFF)
    assert held.cooldown_hold is not None
    assert held.cooldown_hold.enforced_by is None  # OSS IQ's own cooldown, not uv's


def test_a_package_exempt_from_the_cutoff_is_not_held() -> None:
    facts = make_facts(package_name="six")
    exempting = ReleaseCutoff("uv exclude-newer", default=UV_CUTOFF_AT, per_package={"six": None})
    candidates = [Candidate("1.2.0", IN_RANGE, has_cve=False, age_days=30, published_at=published(-5))]

    selection = select_target(facts, UpdateStrategy.STANDARD, candidates, release_cutoff=exempting)
    assert selection.target_version == "1.2.0"


def test_a_release_with_no_publish_instant_passes_the_cutoff() -> None:
    facts = make_facts()
    candidates = [Candidate("1.1.0", IN_RANGE, has_cve=False, age_days=None, published_at=None)]

    selection = select_target(facts, UpdateStrategy.STANDARD, candidates, release_cutoff=UV_CUTOFF)
    assert selection.target_version == "1.1.0"


def test_no_tier_or_motive_ever_targets_past_the_release_cutoff() -> None:
    rng = random.Random(4321)
    for _ in range(300):
        facts = make_facts(
            cve_epss_scores=tuple(rng.choice([None, 0.001, 0.5]) for _ in range(rng.randint(0, 2))),
            maintenance_state=rng.choice([None, "maintained", "winding_down", "abandoned", "deprecated"]),
        )
        candidates = [
            dataclasses.replace(c, age_days=rng.randint(0, 60), published_at=published(rng.randint(-10, 10)))
            for c in _random_candidates(rng, rng.randint(0, 6))
        ]
        refused = {c.version for c in candidates if c.published_at is not None and c.published_at > UV_CUTOFF_AT}

        for tier in PYRAMID:
            selection = select_target(
                facts, tier, candidates, cooldown_period=rng.choice([0, 7]), release_cutoff=UV_CUTOFF
            )
            assert selection.target_version not in refused, (facts, candidates, tier)


def test_a_cve_fix_past_the_declared_range_authorizes_the_widening() -> None:
    facts = make_facts(installed_version="2.31.0", cve_epss_scores=(0.5,))
    candidates = [
        Candidate("2.31.1", IN_RANGE, has_cve=True),
        Candidate("2.32.4", IN_MAJOR, has_cve=False),
    ]

    selection = select_target(facts, UpdateStrategy.SECURITY, candidates)

    assert selection.target_version == "2.32.4"
    assert selection.requires_widening is True
    assert selection.escalation is not None
    assert selection.widening_authorized is True


def test_end_of_life_authorizes_the_widening_at_the_deprecation_tier() -> None:
    facts = make_facts(maintenance_state="abandoned")
    candidates = [
        Candidate("1.1.0", IN_MAJOR, has_cve=False),
        Candidate("2.0.0", LATEST, has_cve=False),
    ]

    selection = select_target(facts, UpdateStrategy.DEPRECATION, candidates)

    assert selection.rung == IN_MAJOR
    assert selection.widening_authorized is True


def test_a_fix_inside_the_declared_range_needs_no_authorization() -> None:
    facts = make_facts(cve_epss_scores=(0.5,))
    candidates = [
        Candidate("1.1.0", IN_RANGE, has_cve=True),
        Candidate("1.2.0", IN_RANGE, has_cve=False),
    ]

    selection = select_target(facts, UpdateStrategy.SECURITY, candidates)

    assert selection.requires_widening is False
    assert selection.widening_authorized is False


def test_widening_for_drift_alone_is_not_authorized() -> None:
    """Rule 8 reaches past the tier too, but only an escalating motive earns the authorization."""
    candidates = [Candidate("1.10.26", IN_MAJOR, has_cve=False)]

    selection = select_target(make_facts(), UpdateStrategy.STANDARD, candidates)

    assert selection.target_version == "1.10.26"
    assert selection.requires_widening is True
    assert selection.escalation is not None
    assert selection.widening_authorized is False


def test_widening_is_not_authorized_when_every_reachable_version_has_a_cve() -> None:
    facts = make_facts(cve_epss_scores=(0.5,))
    candidates = [
        Candidate("1.1.0", IN_RANGE, has_cve=True),
        Candidate("2.0.0", LATEST, has_cve=True),
    ]

    selection = select_target(facts, UpdateStrategy.SECURITY, candidates)

    assert selection.target_version == "2.0.0"
    assert selection.requires_widening is True
    assert selection.widening_authorized is False


def test_the_latest_tier_needs_no_authorization_to_widen() -> None:
    facts = make_facts(cve_epss_scores=(0.5,))
    candidates = [
        Candidate("1.1.0", IN_RANGE, has_cve=True),
        Candidate("1.2.0", IN_MAJOR, has_cve=False),
    ]

    selection = select_target(facts, UpdateStrategy.LATEST, candidates)

    assert selection.requires_widening is True
    assert selection.widening_authorized is False
