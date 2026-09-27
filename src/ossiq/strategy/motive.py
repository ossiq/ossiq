"""What a ScanRecord's evidence reduces to: four flags a strategy can gate on.

Two deliberate divergences from `risk.triage`, both load-bearing here:

- Unscored CVEs count as exploitable. `triage` drops `epss is None` entirely because it is
  advisory there. This module gates *writes*, so absent evidence must not read as absent risk.
- `WINDING_DOWN` is not end-of-life. Only `NOT_MAINTAINED` states (ABANDONED/DEPRECATED), an
  explicit registry/repo deprecation marker, or `DeprecationEvidence.strength == DEPRECATION_STRONG`
  qualify. Winding-down already surfaces as `Consider alternative` in `next_action`, which is the
  right severity for it.

Reuses `EPSS_NOISE_THRESHOLD` from `risk.triage` — the floor is defined once.
"""

from dataclasses import dataclass
from enum import StrEnum

from ossiq.risk.maintenance import DEPRECATION_STRONG, NOT_MAINTAINED
from ossiq.risk.triage import EPSS_NOISE_THRESHOLD


class UpdateMotive(StrEnum):
    """Why a package is allowed to move, independent of how far it may move."""

    EXPLOITABLE_CVE = "exploitable_cve"
    """A CVE at/above EPSS_NOISE_THRESHOLD, or unscored (fail-safe)."""

    SUPPRESSED_CVE = "suppressed_cve"
    """A CVE below the noise floor. Reported for visibility, never a motive that unlocks a tier."""

    END_OF_LIFE = "end_of_life"
    """Deprecated / abandoned upstream, per the NOT_MAINTAINED states or an explicit marker."""

    DRIFT = "drift"
    """Simply behind the registry. The baseline motive every package carries."""


@dataclass(frozen=True)
class PackageFacts:
    """Everything a strategy needs, and nothing more.

    Built from a ScanRecord by `service.project.strategy.facts_from_record` — this package never
    sees a ScanRecord.
    """

    package_name: str
    installed_version: str
    cve_epss_scores: tuple[float | None, ...]
    """One entry per CVE affecting the installed version; None means that CVE carries no EPSS
    score. Empty when the package has no known CVE."""

    maintenance_state: str | None
    """The maintenance model's most probable state (risk.maintenance.MaintenanceState value), or
    None when unmeasured."""

    is_registry_deprecated: bool
    """An explicit registry/repo deprecation marker (ScanRecord.is_installed_deprecated)."""

    deprecation_strength: str
    """risk.maintenance.DeprecationEvidence.strength: "none", "weak", or "strong"."""


def is_qualifying_score(score: float | None, noise: float = EPSS_NOISE_THRESHOLD) -> bool:
    """Whether a CVE with this EPSS score counts toward EXPLOITABLE_CVE: at/above the floor, or
    unscored - absent evidence must not read as absent risk when the output is a write."""
    return score is None or score >= noise


def classify_motives(facts: PackageFacts, *, noise: float = EPSS_NOISE_THRESHOLD) -> frozenset[UpdateMotive]:
    """Reduce a package's evidence to the motive set a strategy admits against.

    DRIFT is unconditional — every package is a candidate for plain drift; whether there is
    actually somewhere newer to go is decided by the candidate list in `targeting.select_target`,
    not here.
    """
    motives: set[UpdateMotive] = {UpdateMotive.DRIFT}

    if any(is_qualifying_score(score, noise) for score in facts.cve_epss_scores):
        motives.add(UpdateMotive.EXPLOITABLE_CVE)
    if any(score is not None and score < noise for score in facts.cve_epss_scores):
        motives.add(UpdateMotive.SUPPRESSED_CVE)

    is_end_of_life = (
        facts.maintenance_state in NOT_MAINTAINED
        or facts.is_registry_deprecated
        or facts.deprecation_strength == DEPRECATION_STRONG
    )
    if is_end_of_life:
        motives.add(UpdateMotive.END_OF_LIFE)

    return frozenset(motives)
