"""Hold an agent's chosen target up against OSS IQ's own recommendation.

`update_context` used to diff installed -> target and stop there, so a target with no module-system
break and no rejected candidate read as approval - even a deprecated release older than the one
OSS IQ recommends. This module turns the facts about the target into one verdict.

It compares against the recommendation; it never makes one. `recommended_version` has exactly one
writer (`service.project.strategy.apply_update_strategy`), and a second target-picker here would be
a second answer to the same question.
"""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum


class TargetVerdict(StrEnum):
    """How a proposed target compares, worst first."""

    VULNERABLE = "vulnerable"
    """The target is itself affected by a qualifying CVE of the installed version."""

    DEPRECATED = "deprecated"
    """The maintainer deprecated or yanked the target release."""

    BREAKING = "breaking"
    """The target crosses a known module-system/API break for this project."""

    RECOMMENDED = "recommended"
    """The target is OSS IQ's own recommendation."""

    SUBOPTIMAL = "suboptimal"
    """Clean, but older than what OSS IQ recommends."""

    BEYOND_RECOMMENDATION = "beyond_recommendation"
    """Clean and newer than the recommendation (or OSS IQ recommends no move): something held the
    recommendation back - the tier, the cooldown, or a gate - so check why before going further."""


@dataclass(frozen=True)
class TargetComparison:
    """One verdict about a proposed target, the reasons behind it, and what to take instead."""

    verdict: TargetVerdict
    reasons: tuple[str, ...]
    better_available: str | None


def compare_target(
    target: str,
    recommended: str | None,
    *,
    is_deprecated: bool,
    is_yanked: bool,
    has_qualifying_cve: bool,
    breaking_change: str | None,
    compare: Callable[[str, str], int],
) -> TargetComparison:
    """Compare a proposed target with OSS IQ's recommendation.

    Every problem found is listed in `reasons`; the verdict is the worst of them, so a vulnerable
    and deprecated target reads `vulnerable` and still names the deprecation.

    Args:
        target: The version the caller intends to move to.
        recommended: OSS IQ's `recommended_version`, or None when it recommends no move.
        is_deprecated: The target release carries a registry deprecation.
        is_yanked: The target release was yanked.
        has_qualifying_cve: The target is affected by a CVE at/above the EPSS noise floor, or an
            unscored one - the same rule the candidate ladder uses.
        breaking_change: The known break the target crosses, e.g. "ESM-only from 5.0.0".
        compare: Registry version ordering; negative when the first argument is older.

    Returns:
        The verdict, its reasons, and the recommendation when it is the better choice.
    """
    reasons: list[str] = []
    problems: list[TargetVerdict] = []
    if has_qualifying_cve:
        problems.append(TargetVerdict.VULNERABLE)
        reasons.append(f"{target} is itself affected by a known CVE")
    if is_deprecated or is_yanked:
        problems.append(TargetVerdict.DEPRECATED)
        reasons.append(f"{target} is {'yanked' if is_yanked else 'deprecated'} by its maintainer")
    if breaking_change:
        problems.append(TargetVerdict.BREAKING)
        reasons.append(f"{target} crosses a known break: {breaking_change}")

    if problems:
        verdict = problems[0]
    elif recommended is not None and compare(target, recommended) == 0:
        verdict = TargetVerdict.RECOMMENDED
    elif recommended is not None and compare(target, recommended) < 0:
        verdict = TargetVerdict.SUBOPTIMAL
        reasons.append(f"{target} is older than the recommended {recommended}")
    else:
        verdict = TargetVerdict.BEYOND_RECOMMENDATION
        reasons.append(
            f"{target} is newer than the recommended {recommended}; check what held the recommendation back"
            if recommended is not None
            else f"OSS IQ recommends no move; check why before taking {target}"
        )

    better = recommended if verdict != TargetVerdict.RECOMMENDED and recommended not in (None, target) else None
    return TargetComparison(verdict=verdict, reasons=tuple(reasons), better_available=better)
