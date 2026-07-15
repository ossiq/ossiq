"""Compact, agent-oriented verdict built from existing scan/package results.

Pure mapping layer consumed by both the ``--format agent`` CLI renderers and the
local MCP server. No I/O and no new analysis — it only reshapes data already
produced by ``service.package`` and ``service.project`` into a small JSON-ready
verdict an AI agent can act on directly.
"""

from typing import Any

from ossiq.domain.cve import CVE
from ossiq.domain.version import VERSION_DIFF_MAJOR
from ossiq.service.package import PackageDetailResult
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.service.update_impact import TransitiveImpact

# JSON-ready verdict shape. The output is JSON, so a plain dict is the natural
# (and lazy) carrier; the type alias documents intent without a dataclass.
AgentVerdict = dict[str, Any]

VERDICT_OK = "ok"
VERDICT_WARN = "warn"
VERDICT_BLOCK = "block"


def cve_summary(cve: CVE) -> dict[str, str]:
    """Reduce a CVE to the fields an agent needs to reason about risk."""
    return {"id": cve.id, "severity": str(cve.severity), "summary": cve.summary}


def worst_verdict(verdicts: list[str]) -> str:
    """Collapse per-item verdicts into the most severe overall verdict."""
    if VERDICT_BLOCK in verdicts:
        return VERDICT_BLOCK
    if VERDICT_WARN in verdicts:
        return VERDICT_WARN
    return VERDICT_OK


def build_add_verdict(detail: PackageDetailResult, requested_version: str | None = None) -> AgentVerdict:
    """Verdict for adding a single package (prospective or already installed)."""
    insight = detail.insight
    recommended = insight.recommended_version if insight else None
    latest = insight.latest_version if insight else None

    if detail.is_prospective:
        cves = detail.prospective_cves
        package_name = detail.prospective_name or ""
    else:
        first = detail.records[0] if detail.records else None
        cves = first.cve if first else []
        package_name = first.package_name if first else ""

    reasons = [warning.message for warning in detail.warnings]
    for cve in cves:
        reasons.append(f"{cve.id} ({cve.severity}) affects latest version {latest}")

    prefer_recommended = bool(recommended and latest and recommended != latest)
    if prefer_recommended:
        reasons.append(f"recommend {recommended} rather than latest {latest}")

    # A "critical" rule (e.g. single-version typosquat risk) is a hard block.
    has_critical_warning = any(warning.severity == "critical" for warning in detail.warnings)
    if has_critical_warning:
        verdict = VERDICT_BLOCK
    elif detail.warnings or cves or prefer_recommended:
        verdict = VERDICT_WARN
    else:
        verdict = VERDICT_OK

    result: AgentVerdict = {
        "operation": "add",
        "registry": detail.packages_registry.lower(),
        "package": package_name,
        "verdict": verdict,
        "recommended_version": recommended,
        "reasons": reasons,
        "cves": [cve_summary(cve) for cve in cves],
        "warnings": [warning.rule_id for warning in detail.warnings],
    }
    if requested_version:
        result["requested_version"] = requested_version
    return result


def impact_summary(impact: TransitiveImpact) -> dict[str, Any]:
    """Reduce a transitive impact to from/to plus a conflict flag."""
    return {
        "package": impact.package_name,
        "from": impact.current_version,
        "to": impact.projected_version,
        "conflict": impact.has_conflict,
    }


def build_update_entry(record: ScanRecord) -> dict[str, Any] | None:
    """Build one update entry, or None when the package needs no action."""
    installed = record.installed_version
    recommended = record.recommended_version
    cves = record.cve
    is_major_drift = record.versions_diff_index.diff_index == VERSION_DIFF_MAJOR
    can_fix = recommended is not None and recommended != installed

    actionable = (
        bool(cves)
        or can_fix
        or is_major_drift
        or record.is_installed_deprecated
        or record.is_installed_yanked
        or record.is_installed_package_unpublished
    )
    if not actionable:
        return None

    reasons: list[str] = [f"{cve.id} ({cve.severity})" for cve in cves]
    if record.is_installed_yanked:
        reasons.append("installed version is yanked")
    if record.is_installed_package_unpublished:
        reasons.append("package is unpublished")
    if record.is_installed_deprecated:
        reasons.append("installed version is deprecated")
    if is_major_drift:
        reasons.append(f"major version drift behind {record.latest_version}")
    if can_fix:
        reasons.append(f"recommend updating {installed} -> {recommended}")

    # Block when there is no safe escape: a CVE with no fixed recommendation, or
    # the installed version is yanked/unpublished.
    stuck_on_cve = bool(cves) and not can_fix
    if record.is_installed_yanked or record.is_installed_package_unpublished or stuck_on_cve:
        verdict = VERDICT_BLOCK
    else:
        verdict = VERDICT_WARN

    return {
        "package": record.package_name,
        "from": installed,
        "to": recommended,
        "verdict": verdict,
        "reasons": reasons,
        "cves": [cve_summary(cve) for cve in cves],
        "transitive_impact": [impact_summary(impact) for impact in record.update_transitive_impacts],
    }


def build_update_verdict(scan: ScanResult) -> AgentVerdict:
    """Verdict for updating a project's direct dependencies."""
    direct_records = scan.production_packages + scan.optional_packages
    entries = [entry for entry in (build_update_entry(record) for record in direct_records) if entry is not None]
    return {
        "operation": "update",
        "registry": scan.packages_registry.lower(),
        "verdict": worst_verdict([entry["verdict"] for entry in entries]),
        "updates": entries,
    }
