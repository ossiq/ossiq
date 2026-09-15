"""Tests for select_target: the pure selector over a pre-tagged candidate ladder."""

import dataclasses
import random
from typing import Any

from ossiq.domain.common import RecommendationRung
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
