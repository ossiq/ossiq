"""The dependency update pyramid: five named tiers, each a strict superset of the one below.

A strategy is not one dial, it is two axes, kept separate on purpose:

- **Motive** (`ADMITTED_MOTIVES`) — *why* a package is allowed to move.
- **Reach** (`MAX_REACH`) — *how far up the version ladder* it may go on that motive.

Everything else in this module is bookkeeping over those two tables.
"""

from collections.abc import Mapping
from enum import StrEnum

from ossiq.domain.common import RUNG_ORDER, RecommendationRung
from ossiq.strategy.motive import UpdateMotive

# RUNG_ORDER is domain.common's — re-exported here because the reach ceilings below are what makes
# it useful, and every caller that compares a rung against a ceiling imports both together.
__all__ = [
    "ADMITTED_MOTIVES",
    "DEFAULT_STRATEGY",
    "ESCALATING_MOTIVES",
    "MAX_REACH",
    "MINIMAL_DIFF_TIERS",
    "MODULE_BREAK_TIERS",
    "PRERELEASE_TIERS",
    "PYRAMID",
    "RUNG_ORDER",
    "UpdateStrategy",
    "includes",
    "tier_index",
]


class UpdateStrategy(StrEnum):
    """A tier of the update pyramid, from the smallest diff to the newest possible version."""

    SECURITY = "security"
    DEPRECATION = "deprecation"
    STANDARD = "standard"
    LATEST = "latest"
    CUTTING_EDGE = "cutting-edge"


PYRAMID: tuple[UpdateStrategy, ...] = (
    UpdateStrategy.SECURITY,
    UpdateStrategy.DEPRECATION,
    UpdateStrategy.STANDARD,
    UpdateStrategy.LATEST,
    UpdateStrategy.CUTTING_EDGE,
)

DEFAULT_STRATEGY = UpdateStrategy.STANDARD

ESCALATING_MOTIVES: frozenset[UpdateMotive] = frozenset({UpdateMotive.EXPLOITABLE_CVE, UpdateMotive.END_OF_LIFE})
"""Motives that push reach past a tier's base MAX_REACH — "stay inside a range that has no safe
version" is not an answer."""

ADMITTED_MOTIVES: Mapping[UpdateStrategy, frozenset[UpdateMotive]] = {
    UpdateStrategy.SECURITY: frozenset({UpdateMotive.EXPLOITABLE_CVE}),
    UpdateStrategy.DEPRECATION: frozenset({UpdateMotive.EXPLOITABLE_CVE, UpdateMotive.END_OF_LIFE}),
    UpdateStrategy.STANDARD: frozenset({UpdateMotive.EXPLOITABLE_CVE, UpdateMotive.END_OF_LIFE, UpdateMotive.DRIFT}),
    UpdateStrategy.LATEST: frozenset({UpdateMotive.EXPLOITABLE_CVE, UpdateMotive.END_OF_LIFE, UpdateMotive.DRIFT}),
    UpdateStrategy.CUTTING_EDGE: frozenset(
        {UpdateMotive.EXPLOITABLE_CVE, UpdateMotive.END_OF_LIFE, UpdateMotive.DRIFT}
    ),
}
"""Why a package is allowed to move at each tier. Cumulative by construction: every tier admits
every motive of the tier below it — that is what makes the pyramid a pyramid."""

MAX_REACH: Mapping[UpdateStrategy, RecommendationRung] = {
    UpdateStrategy.SECURITY: RecommendationRung.IN_RANGE,
    UpdateStrategy.DEPRECATION: RecommendationRung.IN_RANGE,
    UpdateStrategy.STANDARD: RecommendationRung.IN_RANGE,
    UpdateStrategy.LATEST: RecommendationRung.LATEST,
    UpdateStrategy.CUTTING_EDGE: RecommendationRung.LATEST,
}
"""How far up the ladder a tier may reach absent escalation. SECURITY/DEPRECATION/STANDARD cap at
IN_RANGE; a motive in ESCALATING_MOTIVES pushes the effective reach to LATEST regardless of tier."""

MINIMAL_DIFF_TIERS: frozenset[UpdateStrategy] = frozenset({UpdateStrategy.SECURITY, UpdateStrategy.DEPRECATION})
"""Tiers that minimise the diff rather than maximise freshness — the bottom two."""

PRERELEASE_TIERS: frozenset[UpdateStrategy] = frozenset({UpdateStrategy.CUTTING_EDGE})
"""Tiers that admit prereleases. Handled at prefetch time (allow_prerelease), not in the ladder or
here — see strategy/README.md."""


MODULE_BREAK_TIERS: frozenset[UpdateStrategy] = frozenset({UpdateStrategy.LATEST, UpdateStrategy.CUTTING_EDGE})
"""Tiers that may recommend a release a CommonJS consumer can only load through `require(esm)` -
and only when the scan's runtime supports it. Everything below stays on the installed module
system; an escalating motive with no clean answer left there is the one exception, at every tier."""


def tier_index(strategy: UpdateStrategy) -> int:
    """Position of `strategy` in the pyramid, 0 (security) through 4 (cutting-edge)."""
    return PYRAMID.index(strategy)


def includes(strategy: UpdateStrategy, other: UpdateStrategy) -> bool:
    """True when `strategy` sits at or above `other` in the pyramid."""
    return tier_index(strategy) >= tier_index(other)
