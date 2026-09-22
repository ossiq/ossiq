"""Compact, agent-oriented decision built from existing scan/package results.

Pure mapping layer consumed by both the ``--format agent`` CLI renderers and the
local MCP server. No I/O and no new analysis — it only reshapes data already
produced by ``service.package`` and ``service.project`` into a small JSON-ready
decision an AI agent can act on directly.
"""

from typing import Any

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import (
    ENGINE_CONTEXT_KEY_BY_REGISTRY,
    WIDENING_RUNGS,
    DataCompleteness,
    EngineContext,
)
from ossiq.domain.compatibility import CompatibilityFacts
from ossiq.domain.cve import CVE
from ossiq.domain.version import VERSION_DIFF_MAJOR, VERSION_DIFF_MINOR, VERSION_DIFF_PATCH, PackageVersion
from ossiq.risk.maintenance import NOT_MAINTAINED
from ossiq.service.package import PackageDetailResult
from ossiq.service.project.breaking_changes import compute_latest_compatible_major, module_system_label
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.service.project.next_action import (
    CHECK_FOR_THE_FIX,
    CHECK_RELEASE_NOTES,
    CONSTRAINED_CHECK_NEWER,
    FIND_ALTERNATIVE,
    NEXT_ACTION_PRIORITY,
    UPDATE_IMMEDIATELY,
    engine_mismatch_summary,
    has_in_range_upgrade,
    next_action_label,
)
from ossiq.service.update_impact import TransitiveImpact
from ossiq.solver.version_matchers import engine_compatibility

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

    # An empty CompatibilityFacts for the prospective case keeps the three ladder keys present and
    # null, rather than making each one carry its own guard.
    ladder = first.compatibility if (not detail.is_prospective and first) else CompatibilityFacts()

    result: AgentDecision = {
        "operation": "add",
        "registry": detail.packages_registry.lower(),
        "package": package_name,
        "next_action": next_action,
        "recommended_version": recommended,
        # A prospective add has no declared constraint yet, so the ladder is meaningless — only
        # populated for a package already installed in the project.
        "latest_in_range": ladder.latest_in_range,
        "latest_in_major": ladder.latest_in_major,
        "latest_compatible_major": ladder.latest_compatible_major,
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
    if result.cve_data_unavailable:
        summary["cve_data_unavailable"] = True
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


def build_update_entry(record: ScanRecord, engine_context: EngineContext | None = None) -> dict[str, Any]:
    """Build one update entry for a direct dependency.

    B7: every direct dependency gets an entry, even when nothing needs to change. Previously a
    package that cleared none of the actionability checks below was omitted entirely - but an
    agent reading the response has no way to tell "this package is fine" from "this package was
    never analysed" when an entry is simply missing. "Nothing to change" is now an explicit
    per-package statement (next_action=NO_ACTION, empty reasons) instead of an omission.
    """
    engine_context = engine_context or EngineContext()
    facts = record.compatibility
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

    # Every entry carries the full version picture regardless of actionability - installed,
    # latest-in-range, latest-in-major, and latest overall - per the defect report's B7 correct
    # behaviour. latest_version (the absolute newest) was previously only implicit in "to"/the
    # ladder fields and could differ from both, e.g. a pinned major behind an API break.
    base: dict[str, Any] = {
        "package": record.package_name,
        # Two npm aliases of one package produce two entries sharing "package"; without the
        # manifest key a consumer cannot tell which declaration each one answers for, nor which
        # line of package.json to edit. Omitted when it adds nothing, matching the export.
        **(
            {"dependency_name": record.dependency_name}
            if record.dependency_name and record.dependency_name != record.package_name
            else {}
        ),
        "from": installed,
        "latest_version": record.latest_version,
        "latest_in_range": facts.latest_in_range,
        "latest_in_major": facts.latest_in_major,
        "latest_compatible_major": facts.latest_compatible_major,
        "module_system": record.compatibility.module_system.value if record.compatibility.module_system else None,
        "recommended_module_system": (
            record.compatibility.recommended_module_system.value
            if record.compatibility.recommended_module_system
            else None
        ),
        "breaking_change": record.compatibility.breaking_change,
        "engine_requirement": record.compatibility.engine_requirement,
        "engine_compatible": record.compatibility.engine_compatible,
    }

    if not actionable:
        return {
            **base,
            "next_action": NO_ACTION,
            "to": installed,
            "reasons": [],
            "cves": [],
            "transitive_impact": [],
        }

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
    # Only blame the declared range when it genuinely admits nothing newer. A tier that refused to
    # move the package produces the same "no writable target", and this reason then contradicted
    # strategy_withheld_reason further down in the very same entry.
    if (
        diff_index in BEHIND_DIFFS
        and not can_fix
        and record.version_constraint_declared
        and not (record.strategy_selection is not None and record.strategy_selection.withheld_reason)
        and facts.latest_in_range in (None, installed)
    ):
        reasons.append(f"declared range {record.version_constraint_declared} caps this below {record.latest_version}")
    if can_fix:
        reasons.append(f"recommend updating {installed} -> {recommended}")
    for rc in record.rejected_candidates:
        reasons.append(f"{rc.version} rejected: {rc.full_reason}")
    if facts.breaking_change:
        reasons.append(facts.breaking_change)
    if facts.engine_compatible is False:
        # engine_mismatch_reason's own sentence, not a raw dict interpolated into user-facing
        # text - the same string the console shows and the gate wrote into rejected_candidates.
        mismatch = engine_mismatch_summary(record, engine_context.versions)
        if mismatch:
            reasons.append(f"{mismatch} ({engine_context.source})")

    entry: dict[str, Any] = {
        **base,
        "next_action": agent_next_action(record),
        "to": recommended,
        "reasons": reasons,
        "cves": [cve_summary(cve) for cve in cves],
        "transitive_impact": [impact_summary(impact) for impact in record.update_transitive_impacts],
    }
    # A ladder pick that only exists by widening the declared constraint (IN_MAJOR/LATEST) is not
    # something the writers will apply on their own — see build_update_plan's held_for_widening.
    # Flag it explicitly so a consumer doesn't read "to" as a safe target to write as-is.
    if record.recommended_from_rung in WIDENING_RUNGS:
        entry["requires_constraint_widening"] = True
        # A transitive-only dep has no declaration of its own; naming it would print "declared
        # range None must be widened".
        if record.version_constraint_declared:
            reasons.append(
                f"declared range {record.version_constraint_declared} must be widened to reach {recommended}"
            )
        else:
            reasons.append(f"{recommended} is outside the declared range")
    # A pick whose major line is a known break means every installable release was gated and
    # build_candidates' escape hatch admitted the newest anyway. It can sit inside the declared
    # range, so requires_constraint_widening above would not flag it - same second look the CLI
    # asks a human for (commands.plan.confirm_acknowledged). The break itself is already in
    # `reasons` and in `breaking_change`; this is the machine-readable gate.
    if facts.breaking_change:
        entry["carries_known_break"] = True
    triage = triage_summary(record)
    if triage is not None:
        entry["triage"] = triage
    if record.strategy_selection is not None:
        entry["motives"] = sorted(m.value for m in record.strategy_selection.motives)
        if record.strategy_selection.withheld_reason:
            entry["strategy_withheld_reason"] = record.strategy_selection.withheld_reason
    return entry


def headline_next_action(entries: list[dict[str, Any]]) -> str:
    """The most urgent next action across the update entries, by ladder priority."""
    labels = {entry["next_action"] for entry in entries}
    for label in NEXT_ACTION_PRIORITY:
        if label in labels:
            return label
    return NO_ACTION


def data_completeness_summary(completeness: DataCompleteness) -> dict[str, Any]:
    """B8 point 2: in a machine-readable format, a degraded data source must be visible inside
    the document itself, not just as a side-channel console warning - an agent or script reading
    this JSON never sees show_scan_progress's warning (agent/MCP callers bypass it entirely via
    the silent on_step callback), so without this the degradation is invisible to exactly the
    consumer who most needs to know about it.

    The same argument applies to *why* a source degraded and to the API quota behind it: an agent
    that can see "3 repositories not found" retries nothing, where one that sees a bare `partial`
    may well re-run the whole scan into an exhausted quota.
    """
    return {
        "overall": completeness.overall.value,
        "sources": [
            {
                "step": step,
                "status": status.value,
                **(
                    {"failures": [{"reason": reason.value, "count": count} for reason, count in failures]}
                    if (failures := completeness.diagnostics_for(step).failures)
                    else {}
                ),
            }
            for step, status in sorted(completeness.by_step.items())
        ],
        "api_budgets": [
            {
                "resource": budget.resource,
                "limit": budget.limit,
                "remaining": budget.remaining,
                "reset_at": budget.reset_at,
                "needed": budget.needed,
            }
            for budget in completeness.budgets
        ],
    }


def runtime_context_summary(scan: ScanResult) -> dict[str, Any]:
    """The runtime every record's engine_compatible was checked against, stated once.

    One fact about the scan, so it belongs at the top of the document rather than repeated on every
    update entry - where it had already drifted, reporting "detected" on actionable entries and
    "none" on the rest of the same scan.
    """
    return {
        "engine_versions": dict(scan.engine_context.versions),
        "engine_context_source": scan.engine_context.source.value,
        "npm_cli_version": scan.npm_cli_version,
        "project_declares_esm": scan.declares_esm,
    }


def build_update_decide(scan: ScanResult, update_strategy: str | None = None) -> AgentDecision:
    """Decision for updating a project's direct dependencies."""
    direct_records = scan.production_packages + scan.optional_packages
    entries = [build_update_entry(record, scan.engine_context) for record in direct_records]
    result: AgentDecision = {
        "operation": "update",
        "registry": scan.packages_registry.lower(),
        "next_action": headline_next_action(entries),
        "updates": entries,
        "data_completeness": data_completeness_summary(scan.data_completeness),
        "runtime_context": runtime_context_summary(scan),
    }
    if update_strategy is not None:
        result["update_strategy"] = update_strategy
    # Same reasoning as data_completeness: an agent reading this JSON never sees a console
    # warning, so anything worth warning a human about belongs inside the document too.
    if scan.source_warnings:
        result["warnings"] = list(scan.source_warnings)
    return result


def build_update_context(
    detail: PackageDetailResult,
    target_version: str | None,
    releases: list[PackageVersion],
    registry: AbstractPackageRegistryApi,
    engine_context: EngineContext,
    project_declares_esm: bool,
    npm_cli_version: str | None = None,
) -> dict[str, Any]:
    """Diff installed_version -> target_version for a single package.

    Reuses the same pure helpers (module_system_label, engine_compatibility) that the
    recommendation pipeline uses for `recommended_version`, against an arbitrary target an agent is
    evaluating that may not be OSS IQ's own recommendation (e.g. "what changes if I go to 6.0.0").
    """
    record = detail.records[0] if (not detail.is_prospective and detail.records) else None
    package_name = record.package_name if record else (detail.prospective_name or "")
    installed_version = record.installed_version if record else None
    recommended = record.recommended_version if record else None

    to_version = target_version or recommended
    if to_version is None:
        return {"package": package_name, "error": "no recommendation available; pass target_version explicitly"}

    registry_enum = registry.package_registry
    module_system, breaking_change = module_system_label(
        package_name,
        installed_version or "0.0.0",
        to_version,
        releases,
        registry_enum,
        project_declares_esm,
    )
    target_release = next((pv for pv in releases if pv.version == to_version), None)
    engine_requirement = target_release.runtime_requirements if target_release else None

    latest_compatible_major = (
        record.compatibility.latest_compatible_major
        if record is not None
        else compute_latest_compatible_major(package_name, releases, "0.0.0", registry, registry_enum)
    )

    rejected = record.rejected_candidates if record else []
    rejected_up_to_target = [rc for rc in rejected if registry.compare_versions(rc.version, to_version) <= 0]

    engine_key = ENGINE_CONTEXT_KEY_BY_REGISTRY.get(registry_enum)
    context_version = engine_context.versions.get(engine_key) if engine_key else None

    return {
        "package": package_name,
        "registry": registry_enum.value.lower(),
        "from_version": installed_version,
        "to_version": to_version,
        "module_system": {
            "from": record.compatibility.module_system.value if record and record.compatibility.module_system else None,
            "to": module_system.value if module_system else None,
            "project_declares_esm": project_declares_esm,
        },
        "breaking_change": breaking_change,
        "latest_compatible_major": latest_compatible_major,
        "engine": {
            "requirement": engine_requirement,
            "context_version": context_version,
            "context_source": engine_context.source.value,
            "compatible": engine_compatibility(engine_requirement, engine_context.versions),
        },
        "npm_cli_version": npm_cli_version,
        "rejected_candidates": [{"version": rc.version, "reason": rc.reason} for rc in rejected_up_to_target],
    }
