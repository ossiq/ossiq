"""Compact, agent-oriented decision built from existing scan/package results.

Pure mapping layer consumed by both the ``--format agent`` CLI renderers and the
local MCP server. No I/O and no new analysis — it only reshapes data already
produced by ``service.package`` and ``service.project`` into a small JSON-ready
decision an AI agent can act on directly.
"""

from typing import Any

from ossiq.domain.common import RecommendationRung
from ossiq.domain.cve import CVE
from ossiq.domain.version import VERSION_DIFF_MAJOR, VERSION_DIFF_MINOR, VERSION_DIFF_PATCH
from ossiq.risk.maintenance import NOT_MAINTAINED
from ossiq.service.package import PackageDetailResult
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.service.project.next_action import (
    CHECK_FOR_THE_FIX,
    CHECK_RELEASE_NOTES,
    CONSTRAINED_CHECK_NEWER,
    FIND_ALTERNATIVE,
    NEXT_ACTION_PRIORITY,
    UPDATE_IMMEDIATELY,
    has_in_range_upgrade,
    next_action_label,
)
from ossiq.service.update_impact import TransitiveImpact

# JSON-ready decision shape. The output is JSON, so a plain dict is the natural
# (and lazy) carrier; the type alias documents intent without a dataclass.
AgentDecision = dict[str, Any]

DO_NOT_INSTALL = "do not install"
INSTALL_WITH_CAUTION = "install with caution"
INSTALL = "install"
NO_ACTION = "no action needed"

BEHIND_DIFFS: frozenset[int] = frozenset({VERSION_DIFF_MAJOR, VERSION_DIFF_MINOR, VERSION_DIFF_PATCH})


def cve_summary(cve: CVE) -> dict[str, str]:
    """Reduce a CVE to the fields an agent needs to reason about risk."""
    return {"id": cve.id, "severity": str(cve.severity), "summary": cve.summary}


def build_add_decide(detail: PackageDetailResult, requested_version: str | None = None) -> AgentDecision:
    """Decision for adding a single package (prospective or already installed).

    No triage/stability signal here by design: the `add` path has no installed repository history
    to sample, so there is nothing for the dormancy or maintenance-state channels to measure.
    """
    insight = detail.insight
    recommended = insight.recommended_version if insight else None
    latest = insight.latest_version if insight else None
    first = detail.records[0] if detail.records else None

    if detail.is_prospective:
        cves = detail.prospective_cves
        package_name = detail.prospective_name or ""
    else:
        cves = first.cve if first else []
        package_name = first.package_name if first else ""

    reasons = [warning.message for warning in detail.warnings]
    for cve in cves:
        reasons.append(f"{cve.id} ({cve.severity}) affects latest version {latest}")

    prefer_recommended = bool(recommended and latest and recommended != latest)
    if prefer_recommended:
        reasons.append(f"recommend {recommended} rather than latest {latest}")

    # A "critical" rule (e.g. single-version typosquat risk) is a hard stop.
    if any(warning.severity == "critical" for warning in detail.warnings):
        next_action = DO_NOT_INSTALL
    elif detail.warnings or cves or prefer_recommended:
        next_action = INSTALL_WITH_CAUTION
    else:
        next_action = INSTALL

    result: AgentDecision = {
        "operation": "add",
        "registry": detail.packages_registry.lower(),
        "package": package_name,
        "next_action": next_action,
        "recommended_version": recommended,
        # A prospective add has no declared constraint yet, so the ladder is meaningless — only
        # populated for a package already installed in the project.
        "latest_in_range": first.latest_in_range if not detail.is_prospective and first else None,
        "latest_in_major": first.latest_in_major if not detail.is_prospective and first else None,
        "reasons": reasons,
        "cves": [cve_summary(cve) for cve in cves],
        "warnings": [warning.rule_id for warning in detail.warnings],
    }
    if requested_version:
        result["requested_version"] = requested_version
    return result


def triage_summary(record: ScanRecord) -> dict[str, Any] | None:
    """Reduce a record's triage decision to the fields an agent needs, or None when it has none.

    Advisory only: the triage action never changes the headline ``next_action``. The maintenance
    model's threshold behind "refactor" is not yet fully calibrated, so an agent is told what the
    signal says without having its build blocked on it.
    """
    result = record.triage
    if result is None:
        return None

    summary: dict[str, Any] = {"action": result.action, "reason": result.reason}
    if result.max_epss is not None:
        summary["max_epss"] = round(result.max_epss, 4)
    if result.suppressed_cves:
        summary["suppressed_cves"] = result.suppressed_cves
    if record.maintenance is not None:
        summary["maintenance_state"] = record.maintenance.state
        summary["maintenance_risk"] = round(record.maintenance.p_not_maintained, 4)
    if record.deprecation is not None and record.deprecation.signals:
        summary["deprecation_signals"] = sorted(record.deprecation.signals)
        if record.deprecation.successor:
            summary["deprecation_successor"] = record.deprecation.successor
    return summary


def impact_summary(impact: TransitiveImpact) -> dict[str, Any]:
    """Reduce a transitive impact to from/to plus a conflict flag."""
    return {
        "package": impact.package_name,
        "from": impact.current_version,
        "to": impact.projected_version,
        "conflict": impact.has_conflict,
    }


def agent_next_action(record: ScanRecord) -> str:
    """The headline action for one update entry.

    `next_action_label` plus two escalations the console view carries as badges rather than
    ladder rules: a CVE with no available fix outranks plain version drift, and an installed
    version gone from the registry (when nothing else is due) means leave the package.
    """
    label = next_action_label(record)
    can_fix = has_in_range_upgrade(record)

    if (
        record.cve
        and not can_fix
        and label
        in (
            None,
            UPDATE_IMMEDIATELY,
            CHECK_RELEASE_NOTES,
            CONSTRAINED_CHECK_NEWER,
        )
    ):
        return CHECK_FOR_THE_FIX
    gone = record.is_installed_package_unpublished or (
        (record.is_installed_deprecated or record.is_installed_yanked) and not can_fix
    )
    if label is None and gone:
        return FIND_ALTERNATIVE
    return label or UPDATE_IMMEDIATELY


def build_update_entry(record: ScanRecord) -> dict[str, Any] | None:
    """Build one update entry, or None when the package needs no action."""
    installed = record.installed_version
    recommended = record.recommended_version
    cves = record.cve
    diff_index = record.versions_diff_index.diff_index
    is_major_drift = diff_index == VERSION_DIFF_MAJOR
    can_fix = has_in_range_upgrade(record)
    unmaintained_state = record.maintenance.state if record.maintenance is not None else None
    unmaintained = unmaintained_state in NOT_MAINTAINED

    actionable = (
        bool(cves)
        or can_fix
        or diff_index in BEHIND_DIFFS
        or unmaintained
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
    if unmaintained:
        reasons.append(f"upstream looks {unmaintained_state}")
    if is_major_drift:
        reasons.append(f"major version drift behind {record.latest_version}")
    elif diff_index in BEHIND_DIFFS and not can_fix:
        reasons.append(f"behind the latest {record.latest_version}")
    if diff_index in BEHIND_DIFFS and not can_fix and record.version_constraint:
        reasons.append(f"declared range {record.version_constraint} caps this below {record.latest_version}")
    if can_fix:
        reasons.append(f"recommend updating {installed} -> {recommended}")

    entry: dict[str, Any] = {
        "package": record.package_name,
        "next_action": agent_next_action(record),
        "from": installed,
        "to": recommended,
        "latest_in_range": record.latest_in_range,
        "latest_in_major": record.latest_in_major,
        "reasons": reasons,
        "cves": [cve_summary(cve) for cve in cves],
        "transitive_impact": [impact_summary(impact) for impact in record.update_transitive_impacts],
    }
    # A ladder pick that only exists by widening the declared constraint (IN_MAJOR/LATEST) is not
    # something the writers will apply on their own — see build_update_plan's held_for_widening.
    # Flag it explicitly so a consumer doesn't read "to" as a safe target to write as-is.
    if record.recommended_from_rung in (RecommendationRung.IN_MAJOR, RecommendationRung.LATEST):
        entry["requires_constraint_widening"] = True
        reasons.append(f"declared range {record.version_constraint} must be widened to reach {recommended}")
    triage = triage_summary(record)
    if triage is not None:
        entry["triage"] = triage
    return entry


def headline_next_action(entries: list[dict[str, Any]]) -> str:
    """The most urgent next action across the update entries, by ladder priority."""
    labels = {entry["next_action"] for entry in entries}
    for label in NEXT_ACTION_PRIORITY:
        if label in labels:
            return label
    return NO_ACTION


def build_update_decide(scan: ScanResult) -> AgentDecision:
    """Decision for updating a project's direct dependencies."""
    direct_records = scan.production_packages + scan.optional_packages
    entries = [entry for entry in (build_update_entry(record) for record in direct_records) if entry is not None]
    return {
        "operation": "update",
        "registry": scan.packages_registry.lower(),
        "next_action": headline_next_action(entries),
        "updates": entries,
    }
