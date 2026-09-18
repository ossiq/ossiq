"""Tests for parse_overrides / parse_strategy and StrategyPlan."""

import pytest

from ossiq.strategy.overrides import StrategyPlan, parse_overrides
from ossiq.strategy.pyramid import UpdateStrategy


def test_parse_overrides_happy_path() -> None:
    parsed = parse_overrides(["lodash=cutting-edge", "requests=security"])
    assert dict(parsed) == {"lodash": UpdateStrategy.CUTTING_EDGE, "requests": UpdateStrategy.SECURITY}


def test_parse_overrides_scoped_npm_name() -> None:
    parsed = parse_overrides(["@scope/pkg=latest"])
    assert dict(parsed) == {"@scope/pkg": UpdateStrategy.LATEST}


def test_parse_overrides_duplicate_conflict_raises() -> None:
    with pytest.raises(ValueError, match="Conflicting"):
        parse_overrides(["lodash=security", "lodash=latest"])


def test_parse_overrides_duplicate_agreement_is_fine() -> None:
    parsed = parse_overrides(["lodash=security", "lodash=security"])
    assert dict(parsed) == {"lodash": UpdateStrategy.SECURITY}


def test_parse_overrides_unknown_tier_raises() -> None:
    with pytest.raises(ValueError):
        parse_overrides(["lodash=not-a-tier"])


def test_parse_overrides_malformed_spec_raises() -> None:
    with pytest.raises(ValueError):
        parse_overrides(["lodash"])


def test_parse_overrides_none_input() -> None:
    assert parse_overrides(None) == ()


def test_strategy_plan_for_package_falls_back_to_default() -> None:
    plan = StrategyPlan(default=UpdateStrategy.STANDARD, overrides={"lodash": UpdateStrategy.CUTTING_EDGE})
    assert plan.for_package("lodash") is UpdateStrategy.CUTTING_EDGE
    assert plan.for_package("requests") is UpdateStrategy.STANDARD


def test_strategy_plan_max_tier_mixed() -> None:
    plan = StrategyPlan(
        default=UpdateStrategy.SECURITY,
        overrides={"lodash": UpdateStrategy.CUTTING_EDGE, "requests": UpdateStrategy.STANDARD},
    )
    assert plan.max_tier is UpdateStrategy.CUTTING_EDGE


def test_strategy_plan_max_tier_is_default_when_no_overrides() -> None:
    plan = StrategyPlan(default=UpdateStrategy.LATEST)
    assert plan.max_tier is UpdateStrategy.LATEST


def test_strategy_plan_prerelease_packages() -> None:
    plan = StrategyPlan(
        default=UpdateStrategy.STANDARD,
        overrides={"lodash": UpdateStrategy.CUTTING_EDGE, "requests": UpdateStrategy.LATEST},
    )
    assert plan.prerelease_packages == ("lodash",)
