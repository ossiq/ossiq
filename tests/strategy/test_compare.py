"""compare_target: one verdict for a proposed target, judged against the recommendation."""

import pytest
from packaging.version import Version

from ossiq.strategy.compare import TargetVerdict, compare_target


def compare(a: str, b: str) -> int:
    return (Version(a) > Version(b)) - (Version(a) < Version(b))


def verdict_for(target: str, recommended: str | None = "11.1.1", **flags: object):
    kwargs: dict = {"is_deprecated": False, "is_yanked": False, "has_qualifying_cve": False, "breaking_change": None}
    kwargs.update(flags)
    return compare_target(target, recommended, compare=compare, **kwargs)


def test_the_recommendation_itself_is_recommended():
    result = verdict_for("11.1.1")

    assert result.verdict == TargetVerdict.RECOMMENDED
    assert result.reasons == ()
    assert result.better_available is None


def test_an_older_clean_target_is_suboptimal_and_names_the_better_one():
    result = verdict_for("10.0.0")

    assert result.verdict == TargetVerdict.SUBOPTIMAL
    assert result.better_available == "11.1.1"


def test_the_benchmark_case_deprecated_and_older():
    """D2: uuid 9.0.1 (npm-deprecated) was proposed while 11.1.1 was recommended."""
    result = verdict_for("9.0.1", is_deprecated=True)

    assert result.verdict == TargetVerdict.DEPRECATED
    assert result.better_available == "11.1.1"
    assert any("deprecated" in reason for reason in result.reasons)


def test_the_worst_problem_wins_but_every_problem_is_named():
    result = verdict_for("9.0.1", is_deprecated=True, has_qualifying_cve=True)

    assert result.verdict == TargetVerdict.VULNERABLE
    assert len(result.reasons) == 2


def test_a_yanked_target_counts_as_deprecated():
    assert verdict_for("10.0.0", is_yanked=True).verdict == TargetVerdict.DEPRECATED


def test_a_breaking_target_beyond_the_recommendation():
    result = verdict_for("14.0.2", breaking_change="ESM-only from 12.0.0")

    assert result.verdict == TargetVerdict.BREAKING
    assert result.better_available == "11.1.1"


def test_a_clean_target_past_the_recommendation_asks_why():
    result = verdict_for("11.2.0")

    assert result.verdict == TargetVerdict.BEYOND_RECOMMENDATION
    assert "held the recommendation back" in result.reasons[0]


@pytest.mark.parametrize("target", ["4.1.2", "6.0.0"])
def test_no_recommendation_means_no_better_answer(target):
    result = verdict_for(target, recommended=None)

    assert result.verdict == TargetVerdict.BEYOND_RECOMMENDATION
    assert result.better_available is None
