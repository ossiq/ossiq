"""
Tests for the agent decision builder (service.agent).

Covers the next-action branches for both the add and update flows, driven
entirely from existing scan/package result fields.
"""

from ossiq.domain.common import (
    ConstraintType,
    CveDatabase,
    DataCompleteness,
    DataSourceStatus,
    EngineContextSource,
    ModuleSystem,
    ProjectPackagesRegistry,
    RecommendationRung,
    RejectedCandidate,
)
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VERSION_DIFF_MAJOR, VERSION_DIFF_MINOR, VERSION_LATEST, VersionsDifference
from ossiq.risk.maintenance import MaintenanceAssessment, MaintenanceState
from ossiq.service.agent import build_add_decide, build_update_decide
from ossiq.service.package import (
    RULE_SINGLE_MAINTAINER,
    RULE_SINGLE_VERSION,
    PackageDetailResult,
    PackageInsight,
    PackageWarning,
)
from ossiq.service.project.models import ScanRecord, ScanResult


def make_cve(version: str = "1.0.0", severity: Severity = Severity.HIGH) -> CVE:
    return CVE(
        id="CVE-2023-0001",
        cve_ids=("CVE-2023-0001",),
        source=CveDatabase.OSV,
        package_name="victim",
        package_registry=ProjectPackagesRegistry.PYPI,
        summary="bad things",
        severity=severity,
        affected_versions=(version,),
        published=None,
        link="https://example.test/advisory",
    )


def make_insight(latest: str = "2.0.0", recommended: str | None = "2.0.0", maintainers: int = 5) -> PackageInsight:
    return PackageInsight(
        versions_count=10,
        maintainers_count=maintainers,
        downloads_recent=1000,
        latest_version=latest,
        latest_version_age_days=400,
        recommended_version=recommended,
        recommended_version_age_days=400,
        cooldown_days_remaining=None,
    )


def make_detail(insight: PackageInsight, warnings: list[PackageWarning], cves: list[CVE]) -> PackageDetailResult:
    return PackageDetailResult(
        records=[],
        transitive_cve_groups=[],
        project_name="proj",
        packages_registry="PYPI",
        insight=insight,
        warnings=warnings,
        is_prospective=True,
        prospective_name="somepkg",
        prospective_cves=cves,
    )


def abandoned_assessment() -> MaintenanceAssessment:
    return MaintenanceAssessment(
        posterior={s.value: 0.0 for s in MaintenanceState},
        state=MaintenanceState.ABANDONED.value,
        p_not_maintained=1.0,
        observations={},
    )


def make_record(
    name: str = "pkg",
    installed: str = "1.0.0",
    latest: str = "1.0.0",
    diff_index: int = VERSION_LATEST,
    cves: list[CVE] | None = None,
    recommended: str | None = None,
    **flags,
) -> ScanRecord:
    return ScanRecord(
        package_name=name,
        dependency_name=None,
        is_optional_dependency=False,
        installed_version=installed,
        latest_version=latest,
        versions_diff_index=VersionsDifference(installed, latest, diff_index, "diff"),
        time_lag_days=None,
        releases_lag=None,
        cve=cves or [],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
        recommended_version=recommended,
        **flags,
    )


# --- add decision --------------------------------------------------------------


def test_add_install_when_clean_and_at_latest():
    detail = make_detail(make_insight(latest="2.0.0", recommended="2.0.0"), warnings=[], cves=[])
    decision = build_add_decide(detail)
    assert decision["next_action"] == "install"
    assert decision["recommended_version"] == "2.0.0"
    assert decision["operation"] == "add"
    assert decision["registry"] == "pypi"


def test_add_caution_on_single_maintainer():
    warning = PackageWarning(RULE_SINGLE_MAINTAINER, "Single maintainer — bus factor risk", "warning")
    detail = make_detail(make_insight(maintainers=1), warnings=[warning], cves=[])
    decision = build_add_decide(detail, requested_version="2.0.0")
    assert decision["next_action"] == "install with caution"
    assert RULE_SINGLE_MAINTAINER in decision["warnings"]
    assert decision["requested_version"] == "2.0.0"


def test_add_do_not_install_on_critical_warning():
    warning = PackageWarning(RULE_SINGLE_VERSION, "Only one version — typosquat risk", "critical")
    detail = make_detail(make_insight(), warnings=[warning], cves=[])
    assert build_add_decide(detail)["next_action"] == "do not install"


def test_add_caution_when_cve_present():
    detail = make_detail(make_insight(), warnings=[], cves=[make_cve()])
    decision = build_add_decide(detail)
    assert decision["next_action"] == "install with caution"
    assert decision["cves"][0]["id"] == "CVE-2023-0001"


# --- update decision ----------------------------------------------------------


def make_scan(records: list[ScanRecord], data_completeness: DataCompleteness | None = None) -> ScanResult:
    return ScanResult(
        project_name="proj",
        packages_registry="PYPI",
        project_path=".",
        production_packages=records,
        optional_packages=[],
        data_completeness=data_completeness or DataCompleteness(),
    )


def test_update_no_action_when_nothing_actionable():
    """B7: a genuinely fine package still gets an entry - explicit 'no action needed', not an
    omission. An agent can't tell "fine" from "not analysed" when a package is simply missing.
    """
    decision = build_update_decide(make_scan([make_record()]))
    assert decision["next_action"] == "no action needed"
    assert len(decision["updates"]) == 1
    entry = decision["updates"][0]
    assert entry["next_action"] == "no action needed"
    assert entry["to"] == entry["from"]
    assert entry["reasons"] == []
    assert entry["cves"] == []
    assert "verdict" not in decision


def test_update_no_action_entry_still_carries_the_full_version_picture():
    """B7: even a no-action entry carries latest_version/latest_in_range/latest_in_major - an
    agent shouldn't have to guess whether a package was actually checked.
    """
    record = make_record(installed="1.0.0", latest="1.0.0")
    decision = build_update_decide(make_scan([record]))
    entry = decision["updates"][0]
    assert entry["latest_version"] == "1.0.0"
    assert entry["latest_in_range"] == record.latest_in_range
    assert entry["latest_in_major"] == record.latest_in_major


def test_update_no_action_entry_still_carries_module_system_fields():
    """module_system/recommended_module_system/breaking_change/latest_compatible_major are part
    of the "full version picture" B7 guarantees, present even when nothing is actionable."""
    record = make_record(
        installed="1.0.0",
        latest="1.0.0",
        latest_compatible_major="1.0.0",
        module_system=ModuleSystem.CJS,
    )
    decision = build_update_decide(make_scan([record]))
    entry = decision["updates"][0]
    assert entry["latest_compatible_major"] == "1.0.0"
    assert entry["module_system"] == "cjs"
    assert entry["recommended_module_system"] is None
    assert entry["breaking_change"] is None


def test_update_entry_emits_breaking_change_and_recommended_module_system():
    record = make_record(
        installed="4.1.2",
        latest="5.0.0",
        diff_index=VERSION_DIFF_MAJOR,
        recommended="5.0.0",
        latest_compatible_major="4.1.2",
        module_system=ModuleSystem.CJS,
        recommended_module_system=ModuleSystem.ESM_ONLY,
        breaking_change="ESM-only from 5.0.0",
    )
    decision = build_update_decide(make_scan([record]))
    entry = decision["updates"][0]
    assert entry["module_system"] == "cjs"
    assert entry["recommended_module_system"] == "esm-only"
    assert entry["breaking_change"] == "ESM-only from 5.0.0"
    assert "ESM-only from 5.0.0" in entry["reasons"]


def test_update_entry_emits_engine_fields():
    record = make_record(
        installed="1.0.0",
        latest="1.1.0",
        diff_index=VERSION_DIFF_MINOR,
        recommended="1.1.0",
        engine_requirement={"node": ">=22.0.0"},
        engine_compatible=False,
        engine_context_source=EngineContextSource.DETECTED,
    )
    decision = build_update_decide(make_scan([record]))
    entry = decision["updates"][0]
    assert entry["engine_requirement"] == {"node": ">=22.0.0"}
    assert entry["engine_compatible"] is False
    assert entry["engine_context_source"] == "detected"
    assert "requires {'node': '>=22.0.0'} (detected)" in entry["reasons"]


def test_update_no_action_entry_still_carries_engine_fields_default_none():
    record = make_record(installed="1.0.0", latest="1.0.0")
    decision = build_update_decide(make_scan([record]))
    entry = decision["updates"][0]
    assert entry["engine_requirement"] is None
    assert entry["engine_compatible"] is None
    assert entry["engine_context_source"] == "none"


def test_update_release_notes_for_major_bump():
    record = make_record(installed="1.0.0", latest="2.0.0", diff_index=VERSION_DIFF_MAJOR, recommended="2.0.0")
    decision = build_update_decide(make_scan([record]))
    assert decision["next_action"] == "Check Release Notes"
    assert decision["updates"][0]["next_action"] == "Check Release Notes"
    assert decision["updates"][0]["to"] == "2.0.0"
    assert "verdict" not in decision["updates"][0]


def test_update_check_for_the_fix_when_cve_has_no_fix():
    record = make_record(installed="1.0.0", cves=[make_cve()], recommended="1.0.0")
    decision = build_update_decide(make_scan([record]))
    assert decision["next_action"] == "Check for the Fix"
    assert decision["updates"][0]["next_action"] == "Check for the Fix"


def test_update_reasons_include_rejected_candidate_line():
    record = make_record(
        installed="1.0.0",
        cves=[make_cve()],
        recommended="1.0.0",
        rejected_candidates=[RejectedCandidate(version="1.2.0", reason="dep-x requires >=2.0.0")],
    )
    decision = build_update_decide(make_scan([record]))
    assert "1.2.0 rejected: dep-x requires >=2.0.0" in decision["updates"][0]["reasons"]


def test_update_find_alternative_on_yanked():
    record = make_record(is_installed_yanked=True)
    decision = build_update_decide(make_scan([record]))
    assert decision["next_action"] == "Find alternative"


def test_update_abandoned_at_latest_becomes_an_entry():
    record = make_record(maintenance=abandoned_assessment())
    decision = build_update_decide(make_scan([record]))
    assert decision["updates"][0]["next_action"] == "Find alternative"
    assert "refactor_candidates" not in decision


# --- version ladder fields ------------------------------------------------------


def test_update_entry_exposes_ladder_fields():
    record = make_record(
        installed="1.0.0",
        latest="2.0.0",
        diff_index=VERSION_DIFF_MAJOR,
        recommended="2.0.0",
        latest_in_range="1.0.0",
        latest_in_major="1.5.0",
        recommended_from_rung=RecommendationRung.SOLVER,
    )
    decision = build_update_decide(make_scan([record]))
    entry = decision["updates"][0]
    assert entry["latest_in_range"] == "1.0.0"
    assert entry["latest_in_major"] == "1.5.0"


def test_out_of_range_recommendation_flags_constraint_widening():
    record = make_record(
        installed="1.10.13",
        latest="2.13.5",
        diff_index=VERSION_DIFF_MAJOR,
        recommended="1.10.26",
        latest_in_range="1.10.13",
        latest_in_major="1.10.26",
        recommended_from_rung=RecommendationRung.IN_MAJOR,
        version_constraint="==1.10.13",
        version_constraint_declared="==1.10.13",
    )
    decision = build_update_decide(make_scan([record]))
    entry = decision["updates"][0]
    assert entry["requires_constraint_widening"] is True
    assert any("declared range ==1.10.13 must be widened" in reason for reason in entry["reasons"])


def test_widening_reason_reads_declared_constraint_not_effective_one():
    """The reason text must read version_constraint_declared, the root manifest's own spec, not
    version_constraint — the last-writer-wins accumulator a competing transitive/peer parent can
    clobber (the pinia/vue-router bug PLAN.md item #15 fixes)."""
    record = make_record(
        installed="1.10.13",
        latest="2.13.5",
        diff_index=VERSION_DIFF_MAJOR,
        recommended="1.10.26",
        latest_in_range="1.10.13",
        latest_in_major="1.10.26",
        recommended_from_rung=RecommendationRung.IN_MAJOR,
        version_constraint="^1.10.0",  # clobbered by some other parent's spec
        version_constraint_declared="==1.10.13",  # the manifest's own declaration
    )
    decision = build_update_decide(make_scan([record]))
    entry = decision["updates"][0]
    reason_text = " ".join(entry["reasons"])
    assert "==1.10.13" in reason_text
    assert "^1.10.0" not in reason_text


def test_in_range_recommendation_does_not_flag_constraint_widening():
    record = make_record(
        installed="1.0.0",
        latest="1.5.0",
        diff_index=VERSION_DIFF_MAJOR,
        recommended="1.5.0",
        recommended_from_rung=RecommendationRung.SOLVER,
    )
    decision = build_update_decide(make_scan([record]))
    assert "requires_constraint_widening" not in decision["updates"][0]


def test_next_action_unchanged_for_widening_pick_with_minor_drift():
    """A ladder pick reachable only by widening the constraint stays "Constrained" — pinning
    build_update_entry.can_fix (via the rung-aware has_in_range_upgrade) at False."""
    record = make_record(
        installed="1.10.13",
        latest="1.10.26",
        diff_index=VERSION_DIFF_MINOR,
        recommended="1.10.26",
        recommended_from_rung=RecommendationRung.IN_MAJOR,
        version_constraint="==1.10.13",
        version_constraint_declared="==1.10.13",
    )
    decision = build_update_decide(make_scan([record]))
    entry = decision["updates"][0]
    assert entry["next_action"] == "Constrained. Check newer version"
    assert entry["requires_constraint_widening"] is True


def make_installed_detail(record: ScanRecord, insight: PackageInsight | None) -> PackageDetailResult:
    return PackageDetailResult(
        records=[record],
        transitive_cve_groups=[],
        project_name="proj",
        packages_registry="PYPI",
        insight=insight,
        warnings=[],
        is_prospective=False,
    )


def test_add_decide_includes_ladder_for_installed_package():
    record = make_record(name="pydantic", installed="1.10.13", latest_in_range="1.10.13", latest_in_major="1.10.26")
    detail = make_installed_detail(record, make_insight(latest="2.13.5", recommended="1.10.26"))
    decision = build_add_decide(detail)
    assert decision["latest_in_range"] == "1.10.13"
    assert decision["latest_in_major"] == "1.10.26"


def test_add_decide_includes_latest_compatible_major_for_installed_package():
    record = make_record(name="pydantic", installed="1.10.13", latest_compatible_major="1.10.26")
    detail = make_installed_detail(record, make_insight(latest="2.13.5", recommended="1.10.26"))
    decision = build_add_decide(detail)
    assert decision["latest_compatible_major"] == "1.10.26"


def test_add_decide_latest_compatible_major_null_for_prospective():
    detail = make_detail(make_insight(), warnings=[], cves=[])
    decision = build_add_decide(detail)
    assert decision["latest_compatible_major"] is None


def test_add_decide_ladder_null_for_prospective():
    detail = make_detail(make_insight(), warnings=[], cves=[])
    decision = build_add_decide(detail)
    assert decision["latest_in_range"] is None
    assert decision["latest_in_major"] is None


# --- B7: agent format must never omit a direct dependency ---------------------


def test_all_direct_dependencies_appear_even_when_only_one_has_a_cve():
    """The defect report's own scenario: 6 pinned direct dependencies, all outdated, only one
    (pydantic) carries a CVE. The old behaviour listed only pydantic - an agent reading the
    response would have no way to tell the other 5 were checked and found to need attention too.
    """
    records = [
        make_record(
            name="pydantic",
            installed="1.10.13",
            latest="2.13.5",
            diff_index=VERSION_DIFF_MAJOR,
            cves=[make_cve()],
            recommended="1.10.13",
        ),
        make_record(name="requests", installed="2.28.1", latest="2.34.2", diff_index=VERSION_DIFF_MINOR),
        make_record(name="click", installed="8.1.3", latest="8.1.7", diff_index=VERSION_DIFF_MINOR),
        make_record(name="jinja2", installed="3.1.2", latest="3.1.4", diff_index=VERSION_DIFF_MINOR),
        make_record(name="httpx", installed="0.24.0", latest="0.27.0", diff_index=VERSION_DIFF_MINOR),
        make_record(name="pyyaml", installed="6.0", latest="6.0.2", diff_index=VERSION_DIFF_MINOR),
    ]
    decision = build_update_decide(make_scan(records))
    listed = {entry["package"] for entry in decision["updates"]}
    assert listed == {"pydantic", "requests", "click", "jinja2", "httpx", "pyyaml"}


def test_a_package_up_to_date_and_unaffected_gets_an_explicit_entry_not_an_omission():
    fine = make_record(name="click", installed="8.1.7", latest="8.1.7")
    outdated = make_record(name="pydantic", installed="1.10.13", latest="2.13.5", diff_index=VERSION_DIFF_MAJOR)
    decision = build_update_decide(make_scan([fine, outdated]))

    assert len(decision["updates"]) == 2
    entries_by_name = {e["package"]: e for e in decision["updates"]}
    assert entries_by_name["click"]["next_action"] == "no action needed"
    assert entries_by_name["click"]["to"] == entries_by_name["click"]["from"] == "8.1.7"


# --- B8: machine-readable formats must carry data-source degradation inline ----


def test_update_decide_carries_ok_completeness_by_default():
    decision = build_update_decide(make_scan([make_record()]))
    assert decision["data_completeness"] == {"overall": "ok", "sources": []}


def test_update_decide_surfaces_degraded_sources_inline():
    """B8 point 2: an agent/script consuming this JSON never sees the console warning
    (show_scan_progress is bypassed entirely for agent/MCP callers) - the only way it can know
    a data source was degraded is if the document says so itself.
    """
    completeness = DataCompleteness(
        by_step={"vulnerabilities": DataSourceStatus.UNREACHABLE, "repositories": DataSourceStatus.OK}
    )
    decision = build_update_decide(make_scan([make_record()], data_completeness=completeness))
    assert decision["data_completeness"]["overall"] == "unreachable"
    assert {"step": "vulnerabilities", "status": "unreachable"} in decision["data_completeness"]["sources"]
    assert {"step": "repositories", "status": "ok"} in decision["data_completeness"]["sources"]
