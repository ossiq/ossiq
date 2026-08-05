"""
P_supplychain quantifies unvetted dependency risk independent of known CVEs.
Newly published package versions lack sufficient exposure to static analysis,
community auditing, and maintainer triage. V1 models version recency as a distinct
hazard metric, initializing at maximum weight upon release (t=0) and decaying to
zero across a configurable cooldown window.
"""

import math

from ossiq.service.project.models import ScanRecord

FRESH_HAZARD_WEIGHT = 0.20


def compute_p_supplychain(
    record: ScanRecord,
    cooldown_days: int = 7,
    fresh_hazard_weight: float = FRESH_HAZARD_WEIGHT,
) -> float | None:
    """
    Return supply-chain hazard probability or None if unknown.

    `fresh_hazard` is folded through `math.prod` as a one-item list rather than returned directly
    because it won't stay the only hazard: later signals (e.g. typosquatting/provenance, a
    maintainer-change flag) will each contribute their own independent probability to this same
    list. `1 - prod(1 - h_i)` is how independent probabilities combine into "at least one hazard
    fired," so adding an entry to the list is all a future signal will need to do here.
    """

    if record.version_age_days is None:
        return None

    age = max(record.version_age_days, 0)

    if age >= cooldown_days:
        return 0.0

    hazard = fresh_hazard_weight * (1.0 - age / cooldown_days)

    return 1.0 - math.prod([1.0 - hazard])
