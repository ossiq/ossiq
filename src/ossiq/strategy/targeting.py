"""The selector: picks one target version out of a pre-tagged candidate ladder.

`select_target` does **no version parsing**. It is handed an ascending list of `Candidate`s, each
already tagged with the lowest rung that reaches it and whether a qualifying CVE affects it. That
is what keeps this module trivially testable and free of registry coupling — all version semantics
live in `service.project.strategy.build_candidates`.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from ossiq.domain.common import RecommendationRung
from ossiq.strategy.motive import PackageFacts, UpdateMotive, classify_motives
from ossiq.strategy.pyramid import (
    ADMITTED_MOTIVES,
    ESCALATING_MOTIVES,
    MAX_REACH,
    MINIMAL_DIFF_TIERS,
    PYRAMID,
    RUNG_ORDER,
    UpdateStrategy,
)


@dataclass(frozen=True)
class Candidate:
    """One reachable version, pre-tagged by the service layer.

    `rung` is the lowest ladder rung that reaches this version (IN_RANGE / IN_MAJOR / LATEST) —
    it must agree with `service.project.ladder.compute_version_ladder` on the same input.
    """

    version: str
    rung: RecommendationRung
    has_cve: bool
    """Affected by a CVE that qualifies as UpdateMotive.EXPLOITABLE_CVE (at/above the noise
    floor, or unscored)."""


@dataclass(frozen=True)
class StrategySelection:
    """The selector's verdict for one package under one strategy."""

    strategy: UpdateStrategy
    target_version: str | None
    rung: RecommendationRung | None
    motives: frozenset[UpdateMotive]
    requires_widening: bool
    withheld_reason: str | None
    """Set only when no motive was admitted at this tier — human-readable, names the lowest tier
    that would have moved this package."""
    available_at: UpdateStrategy | None
    """The same lowest-admitting tier as `withheld_reason`, as data rather than text — powers the
    "N more updates available under --update-strategy X" footer without parsing a message."""
    escalation: str | None
    """Set when reach was pushed past the tier's base MAX_REACH, or when every reachable
    candidate still carries a qualifying CVE."""


def _lowest_admitting_tier(facts: PackageFacts) -> UpdateStrategy:
    """The lowest tier in the pyramid whose admitted motives overlap this package's motives.

    DRIFT is unconditional, so STANDARD always qualifies at the latest — this never falls through
    the loop.
    """
    detected = classify_motives(facts)
    for tier in PYRAMID:
        if ADMITTED_MOTIVES[tier] & detected:
            return tier
    return PYRAMID[-1]  # unreachable given DRIFT is always classified; kept for exhaustiveness


def select_target(facts: PackageFacts, strategy: UpdateStrategy, candidates: Sequence[Candidate]) -> StrategySelection:
    """Pick the target version for one package under one strategy tier.

    Algorithm:
      1. Intersect the tier's admitted motives with this package's detected motives. Empty ->
         no target, `withheld_reason` names the lowest tier that would have moved it.
      2. Compute reach: the tier's MAX_REACH, escalated to LATEST when an ESCALATING_MOTIVES
         member was admitted (a CVE or end-of-life motive). Filter candidates to that reach.
      3. Minimal-diff tiers (security, deprecation) take the *first* (nearest) candidate that
         resolves the admitted motive: CVE-clear when EXPLOITABLE_CVE is admitted, otherwise
         simply the nearest candidate in reach.
      4. Freshness tiers (standard, latest, cutting-edge) take the *newest* candidate in reach,
         never a CVE-affected one while a clear candidate exists in reach.
      5. A higher tier's target is never lower than a lower tier's — this falls out of the
         construction (superset of motives, reach at least as far) rather than being special-cased
         here; minimal-diff tiers are the deliberate exception, since lowering the diff *is* the
         point there.
      6. If every candidate in reach still carries a qualifying CVE, take the newest anyway and
         set `escalation` — never silently stay on the installed version.
      7. Freshness tiers only: if drift alone leaves nothing in reach (e.g. an exact pin broken
         by an API change, with newer releases sitting only at IN_MAJOR/LATEST), reach still
         escalates to the newest candidate overall, same as rule 6 — a package must never come
         back with no target solely because its only newer releases sit past this tier's base
         reach. Minimal-diff tiers are exempt: drift alone is not their motive to move at all.
    """
    detected = classify_motives(facts)
    admitted = ADMITTED_MOTIVES[strategy] & detected

    if not admitted:
        lowest = _lowest_admitting_tier(facts)
        return StrategySelection(
            strategy=strategy,
            target_version=None,
            rung=None,
            motives=frozenset(),
            requires_widening=False,
            withheld_reason=f"no motive admitted at {strategy}; available under --update-strategy {lowest}",
            available_at=lowest,
            escalation=None,
        )

    escalate = bool(admitted & ESCALATING_MOTIVES)
    reach = RecommendationRung.LATEST if escalate else MAX_REACH[strategy]
    in_reach = [c for c in candidates if RUNG_ORDER[c.rung] <= RUNG_ORDER[reach]]

    if not in_reach:
        # Rule 7: a freshness tier must never leave a package stuck with no target merely
        # because its only newer releases sit beyond this tier's base reach - the named
        # regression this guards against is an exact pin held back by an API-breaking major
        # (e.g. pydantic==1.10.13 with only 1.10.x/2.x releases, both past IN_RANGE). Widen one
        # rung at a time, same as the old ladder fallback's ascending walk, so a same-major patch
        # is preferred over jumping straight to a breaking major when both exist.
        if strategy not in MINIMAL_DIFF_TIERS and candidates:
            for wider_reach in (RecommendationRung.IN_MAJOR, RecommendationRung.LATEST):
                if RUNG_ORDER[wider_reach] <= RUNG_ORDER[reach]:
                    continue
                widened = [c for c in candidates if RUNG_ORDER[c.rung] <= RUNG_ORDER[wider_reach]]
                if not widened:
                    continue
                newest = widened[-1]
                return StrategySelection(
                    strategy=strategy,
                    target_version=newest.version,
                    rung=newest.rung,
                    motives=admitted,
                    requires_widening=RUNG_ORDER[newest.rung] > RUNG_ORDER[RecommendationRung.IN_RANGE],
                    withheld_reason=None,
                    available_at=None,
                    escalation=(
                        f"no version of {facts.package_name} within {strategy} reach; "
                        f"nearest reachable is {newest.version}"
                    ),
                )
        return StrategySelection(
            strategy=strategy,
            target_version=None,
            rung=None,
            motives=admitted,
            requires_widening=False,
            withheld_reason=None,
            available_at=None,
            escalation=None,
        )

    clear = [c for c in in_reach if not c.has_cve]

    if strategy in MINIMAL_DIFF_TIERS:
        if UpdateMotive.EXPLOITABLE_CVE in admitted:
            pick = clear[0] if clear else in_reach[-1]
        else:
            pick = in_reach[0]
    else:
        pick = clear[-1] if clear else in_reach[-1]

    escalation: str | None = None
    if not clear:
        escalation = f"every reachable version of {facts.package_name} still carries a qualifying CVE"
    elif escalate and RUNG_ORDER[pick.rung] > RUNG_ORDER[MAX_REACH[strategy]]:
        motive_names = ", ".join(sorted(m.value for m in admitted & ESCALATING_MOTIVES))
        escalation = f"no version of {facts.package_name} within its declared range resolves: {motive_names}"

    return StrategySelection(
        strategy=strategy,
        target_version=pick.version,
        rung=pick.rung,
        motives=admitted,
        requires_widening=RUNG_ORDER[pick.rung] > RUNG_ORDER[RecommendationRung.IN_RANGE],
        withheld_reason=None,
        available_at=None,
        escalation=escalation,
    )
