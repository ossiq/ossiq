"""
P_vuln estimates the probability that a known CVE affecting an installed
dependency is exploited within its remediation window.
"""

import math
from collections.abc import Iterable

from ossiq.domain.cve import CVE

REACHABILITY_FACTOR: dict[bool | None, float] = {True: 1.0, None: 0.5, False: 0.1}
EPSS_CLAMP_MAX = 0.99
NEGLIGENT_FIX_AGE_DAYS = 30
NEGLIGENCE_BUMP_WEIGHT = 0.15


def compute_p_vuln(
    cves: Iterable[CVE],
    window_days: float | None,
    horizon_days: int = 365,
    negligent_fix_age_days: int = NEGLIGENT_FIX_AGE_DAYS,
    negligence_bump_weight: float = NEGLIGENCE_BUMP_WEIGHT,
) -> float | None:
    """Return the known-vulnerability exploitation probability, or None if unknown.

    Each CVE contributes a daily hazard rate derived from its EPSS score (clamped to
    avoid a rate of infinity) and scaled down when the code isn't reachable. The
    hazard rates sum and compound over the exposure window (window_days capped by
    horizon_days) into a single exploitation probability. An overdue fix adds one
    flat negligence penalty regardless of how many CVEs are overdue. Zero CVEs yields
    0.0; missing EPSS or window/horizon data yields None rather than an implicit zero.
    """

    cve_list = list(cves)
    if not cve_list:
        return 0.0

    if window_days is None or window_days < 0:
        return None

    if horizon_days < 0:
        return None

    if any(cve.epss is None for cve in cve_list):
        return None

    lambda_total = 0.0

    for cve in cve_list:
        assert cve.epss is not None  # guaranteed by the guard clause above
        epss = max(0.0, min(cve.epss, EPSS_CLAMP_MAX))
        reachability_factor = REACHABILITY_FACTOR[cve.reachable]
        lambda_total += -math.log(1 - (epss * reachability_factor)) / 365

    exposure_days = min(window_days, horizon_days)
    p_vuln = 1 - math.exp(-lambda_total * exposure_days)

    is_negligent = any(
        cve.fix_age_days is not None and cve.fix_age_days > negligent_fix_age_days \
        for cve in cve_list
    )  # fmt: off

    if is_negligent:
        p_vuln = 1 - (1 - p_vuln) * (1 - negligence_bump_weight)

    return max(0.0, min(p_vuln, 1.0))
