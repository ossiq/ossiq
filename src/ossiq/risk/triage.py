"""
Dependency triage: the join between the tactical (EPSS) and strategic (maintenance-state)
pipelines.

The two metrics are never multiplied into one number. EPSS answers "is a known CVE being
exploited", which is a patch decision; repository stability answers "will this project still be
maintained", which is a refactor decision. Stability only decides *how* to react to an exploit
signal:

    high EPSS + unstable repo -> evict     no upstream fix is coming
    high EPSS + stable repo   -> patch     maintainers will ship a fix
    low EPSS  + unstable repo -> refactor  maintenance debt, no exploit pressure
    otherwise                 -> retain

What counts as "unstable" is the caller's decision, deliberately not this module's. See
`service.project.stability` for the one place that defines it: the maintenance-state model's
P(not maintained) crossing MAINTENANCE_THRESHOLD, not a bare dormancy check.
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

    cve_data_unavailable: bool = False
    """True when this scan's CVE fetch was degraded (unreachable, rate-limited, or partial), so
    an absence of evidence in `cves` means "couldn't check", not "confirmed clean". Reflects the
    scan-level fetch status regardless of which action or reason was chosen."""


def triage(
    cves: Iterable[CVE],
    unstable: bool | None,
    *,
    cve_data_unavailable: bool = False,
    noise: float = EPSS_NOISE_THRESHOLD,
    exploit: float = EPSS_EXPLOIT_THRESHOLD,
) -> TriageResult:
    """Decide the action for one package from its CVEs and its repository's stability verdict.

    `unstable=None` (repository unmeasured) and `cve_data_unavailable=True` (CVE fetch degraded)
    both mean "no evidence," never "clean": the package keeps its exploit-driven action rather
    than being promoted to refactor, or retained with a reason that claims confirmed safety it
    doesn't have.

    Args:
        cves: The package's known CVEs.
        unstable: Whether the repository is winding down, or None if it couldn't be measured.
        cve_data_unavailable: True when this scan's CVE fetch was degraded, so an empty `cves`
            can't be read as "confirmed clean."
        noise: EPSS floor below which a CVE is suppressed from `max_epss`.
        exploit: EPSS floor at or above which exploitation counts as an active threat.

    Returns:
        The recommended action with its supporting evidence.
    """

    scored = [cve.epss for cve in cves if cve.epss is not None]
    active = [score for score in scored if score >= noise]
    max_epss = max(active) if active else None
    suppressed = len(scored) - len(active)

    under_threat = max_epss is not None and max_epss >= exploit
    is_unstable = unstable is True

    if under_threat and is_unstable:
        reason = "High exploit probability on a dormant repository; an upstream fix is unlikely."
        return TriageResult(ACTION_EVICT, reason, max_epss, suppressed, cve_data_unavailable)

    if under_threat:
        reason = "Active exploit probability, and the repository is active enough to ship a fix."
        return TriageResult(ACTION_PATCH, reason, max_epss, suppressed, cve_data_unavailable)

    if is_unstable:
        reason = "No exploit pressure, but the repository shows no development activity."
        return TriageResult(ACTION_REFACTOR, reason, max_epss, suppressed, cve_data_unavailable)

    if cve_data_unavailable:
        reason = "CVE data could not be retrieved for this scan; exploit signal unknown, not confirmed clean."
    elif suppressed:
        # "No significant exploit" next to a listed HIGH CVE read as a contradiction; the CVE is
        # there, it is just scored below the floor this matrix treats as noise.
        reason = f"No exploit signal above the EPSS noise floor; {suppressed} CVE(s) scored below EPSS {noise}."
    else:
        reason = "No significant exploit or stability signal."
    return TriageResult(ACTION_RETAIN, reason, max_epss, suppressed, cve_data_unavailable)
