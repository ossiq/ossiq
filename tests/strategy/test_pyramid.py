"""Structural invariants of the pyramid tables themselves."""

import pytest

from ossiq.strategy.overrides import parse_strategy
from ossiq.strategy.pyramid import ADMITTED_MOTIVES, MAX_REACH, PYRAMID, RUNG_ORDER, UpdateStrategy


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
