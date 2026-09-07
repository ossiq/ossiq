"""
EPSS (Exploit Prediction Scoring System) aggregation formulas.

Per FIRST's EPSS user guide, §3 ("EPSS Can Scale, to Produce System, Network,
and Enterprise-level Exploit Predictions"): the probability that at least one
of several independent vulnerabilities is exploited is 1 - prod(1 - EPSS_i).
"""

import math
from collections.abc import Iterable

from ossiq.domain.cve import CVE


def package_epss(cves: Iterable[CVE]) -> float | None:
    """Highest EPSS among a package's CVEs; None when none carries a score."""

    scores = [cve.epss for cve in cves if cve.epss is not None]
    if not scores:
        return None
    return max(scores)


def grouped_epss(scores: Iterable[float]) -> float | None:
    """EPSSg over a group: 1 - prod(1 - s). None when the group has no scored member."""

    clamped = [max(0.0, min(score, 1.0)) for score in scores]
    if not clamped:
        return None
    return 1 - math.prod(1 - score for score in clamped)
