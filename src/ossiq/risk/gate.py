"""Deterministic pass/quarantine/block verdict for the Health Score.

The Gate is a fast, dependency-free checkpoint independent of the
probability-based Expected Exposure estimate: it is meant to run inline in CI
or an agent's pre-install check using only already-cached scan data, with no
new network calls.

Reachability analysis does not exist yet, so the critical-CVE block condition
below only checks severity and fix availability, not whether the vulnerable
code path is actually reachable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from ossiq.domain.cve import Severity

if TYPE_CHECKING:
    from ossiq.service.project.models import ScanRecord

GateStatus = Literal["pass", "quarantine", "block"]
GateDecision = tuple[GateStatus, str]


def get_gate_decision(record: ScanRecord, cooldown_days: int = 7) -> GateDecision:
    """Return a deterministic Gate verdict and its human-readable reason.

    Conditions are evaluated in stable precedence order: installed-package
    unpublished, then deprecated, then a critical CVE with an available fix,
    then a cooldown check for very recently published installed versions.
    A non-positive cooldown_days disables the cooldown rule.
    """
    if record.is_installed_package_unpublished:
        return "block", "package does not exist (possible hallucination)"

    if record.is_installed_deprecated:
        return "block", "package deprecated by maintainers"

    if any(cve.severity == Severity.CRITICAL and cve.fix_available for cve in record.cve):
        return "block", "critical CVE with an available fix has not been applied"

    if cooldown_days > 0 and record.version_age_days is not None and record.version_age_days < cooldown_days:
        if record.cve:
            return "pass", "cooldown bypassed: installed version already carries a CVE"
        return "quarantine", f"{record.version_age_days}d old (cooldown < {cooldown_days}d)"

    return "pass", "ok"
