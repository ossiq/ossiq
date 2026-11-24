"""The derived views of an update plan."""

from __future__ import annotations

from ossiq.domain.common import UpdateStrategy
from ossiq.domain.update_plan import UpdatePlan


def plan_at(strategy: UpdateStrategy, available: dict[UpdateStrategy, int]) -> UpdatePlan:
    return UpdatePlan(
        project_name="demo",
        project_path="/p",
        registry_type="NPM",
        package_manager_name="npm",
        direct_entries=[],
        transitive_entries=[],
        strategy=strategy,
        available_at_higher_tier=available,
    )


def test_higher_tier_counts_keep_only_tiers_above_the_run_lowest_first() -> None:
    plan = plan_at(
        UpdateStrategy.STANDARD,
        {
            UpdateStrategy.CUTTING_EDGE: 3,
            UpdateStrategy.SECURITY: 5,
            UpdateStrategy.STANDARD: 1,
            UpdateStrategy.LATEST: 2,
        },
    )

    assert plan.higher_tier_counts == [(UpdateStrategy.LATEST, 2), (UpdateStrategy.CUTTING_EDGE, 3)]


def test_a_plan_with_nothing_withheld_has_no_higher_tiers() -> None:
    assert plan_at(UpdateStrategy.SECURITY, {}).higher_tier_counts == []
