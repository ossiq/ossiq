"""Structural invariants of the pyramid tables themselves."""

import pytest

from ossiq.domain.common import RecommendationRung
from ossiq.strategy.overrides import parse_strategy
from ossiq.strategy.pyramid import (
    ADMITTED_MOTIVES,
    MAX_REACH,
    PYRAMID,
    RUNG_ORDER,
    UpdateStrategy,
    tier_reaches,
)


def test_admitted_motives_is_cumulative() -> None:
    for lower, higher in zip(PYRAMID, PYRAMID[1:], strict=False):
        assert ADMITTED_MOTIVES[lower] <= ADMITTED_MOTIVES[higher], f"{higher} must admit every motive {lower} admits"


def test_max_reach_is_non_decreasing() -> None:
    for lower, higher in zip(PYRAMID, PYRAMID[1:], strict=False):
        assert RUNG_ORDER[MAX_REACH[lower]] <= RUNG_ORDER[MAX_REACH[higher]]


def test_parse_strategy_round_trips_every_member() -> None:
    for tier in UpdateStrategy:
        assert parse_strategy(tier.value) is tier


def test_parse_strategy_rejects_unknown_value() -> None:
    with pytest.raises(ValueError, match="security"):
        parse_strategy("not-a-tier")


@pytest.mark.parametrize("tier", PYRAMID)
def test_every_tier_reaches_the_declared_range(tier: UpdateStrategy) -> None:
    assert tier_reaches(tier, RecommendationRung.IN_RANGE)


@pytest.mark.parametrize("rung", [RecommendationRung.IN_MAJOR, RecommendationRung.LATEST])
@pytest.mark.parametrize(
    ("tier", "reaches"),
    [
        (UpdateStrategy.SECURITY, False),
        (UpdateStrategy.DEPRECATION, False),
        (UpdateStrategy.STANDARD, False),
        (UpdateStrategy.LATEST, True),
        (UpdateStrategy.CUTTING_EDGE, True),
    ],
)
def test_only_the_freshness_tiers_reach_past_the_range(tier: UpdateStrategy, reaches: bool, rung: RecommendationRung):
    assert tier_reaches(tier, rung) is reaches
