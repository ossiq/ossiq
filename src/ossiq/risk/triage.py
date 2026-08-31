"""
Dependency triage: the join between the tactical (EPSS) and strategic (CSI) pipelines.

The two metrics are never multiplied into one number. EPSS answers "is a known CVE being
exploited", which is a patch decision; repository stability answers "will this project still be
maintained", which is a refactor decision. Stability only decides *how* to react to an exploit
signal:

    high EPSS + unstable repo -> evict     no upstream fix is coming
    high EPSS + stable repo   -> patch     maintainers will ship a fix
    low EPSS  + unstable repo -> refactor  maintenance debt, no exploit pressure
    otherwise                 -> retain

What counts as "unstable" is the caller's decision, deliberately not this module's. See
`service.project.stability` for the one place that defines it, and why it is currently dormancy
rather than the CSI threshold.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from ossiq.domain.cve import CVE

EPSS_NOISE_THRESHOLD = 0.005
"""Below a 0.5% chance of exploitation an alert is noise. Such CVEs are counted and reported,
never silently dropped."""

EPSS_EXPLOIT_THRESHOLD = 0.10
"""At or above a 10% chance of exploitation the vulnerability is treated as an active threat."""

ACTION_EVICT = "evict"
ACTION_PATCH = "patch"
ACTION_REFACTOR = "refactor"
ACTION_RETAIN = "retain"


@dataclass(frozen=True)
class TriageResult:
    """The recommended operational action for one package, and the evidence behind it."""

    action: str
    reason: str
    max_epss: float | None
    """Highest EPSS among CVEs at or above the noise threshold. None when nothing qualifies."""

    suppressed_cves: int
    """CVEs carrying an EPSS score below the noise threshold."""


def triage(
    cves: Iterable[CVE],
    unstable: bool | None,
    *,
    noise: float = EPSS_NOISE_THRESHOLD,
    exploit: float = EPSS_EXPLOIT_THRESHOLD,
) -> TriageResult:
    """Decide the action for one package from its CVEs and its repository's stability verdict.

    `unstable` is None when the repository could not be measured. Unknown is not unstable: such a
    package keeps its exploit-driven action and is never marked for refactoring on absent
    evidence.
    """

    scored = [cve.epss for cve in cves if cve.epss is not None]
    active = [score for score in scored if score >= noise]
    max_epss = max(active) if active else None
    suppressed = len(scored) - len(active)

    under_threat = max_epss is not None and max_epss >= exploit
    is_unstable = unstable is True

    if under_threat and is_unstable:
        reason = "High exploit probability on a dormant repository; an upstream fix is unlikely."
        return TriageResult(ACTION_EVICT, reason, max_epss, suppressed)

    if under_threat:
        reason = "Active exploit probability, and the repository is active enough to ship a fix."
        return TriageResult(ACTION_PATCH, reason, max_epss, suppressed)

    if is_unstable:
        reason = "No exploit pressure, but the repository shows no development activity."
        return TriageResult(ACTION_REFACTOR, reason, max_epss, suppressed)

    return TriageResult(ACTION_RETAIN, "No significant exploit or stability signal.", max_epss, suppressed)
