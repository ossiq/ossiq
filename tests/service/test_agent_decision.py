"""
Tests for the agent decision builder (service.agent).

Covers the next-action branches for both the add and update flows, driven
entirely from existing scan/package result fields.
"""

import dataclasses

import pytest

from ossiq.domain.common import (
    ConstraintType,
    CveDatabase,
    DataCompleteness,
    DataSourceStatus,
    DegradeReason,
    EngineContext,
    EngineContextSource,
    FetchDiagnostics,
    ModuleSystem,
    ProjectPackagesRegistry,
    RateLimitBudget,
    RecommendationRung,
    RejectedCandidate,
    ScanStep,
    SignalCoverage,
)
from ossiq.domain.compatibility import CompatibilityFacts
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VERSION_DIFF_MAJOR, VERSION_DIFF_MINOR, VERSION_LATEST, VersionsDifference
from ossiq.risk.maintenance import MaintenanceAssessment, MaintenanceState
from ossiq.risk.triage import ACTION_REFACTOR, ACTION_RETAIN, TriageResult
from ossiq.service.agent import build_add_decide, build_update_decide
from ossiq.service.package import (
    RULE_SINGLE_MAINTAINER,
    RULE_SINGLE_VERSION,
    PackageDetailResult,
    PackageInsight,
    PackageWarning,
)
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.strategy.pyramid import UpdateStrategy
from ossiq.strategy.targeting import StrategySelection


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


# The ladder/module-system/engine cluster now lives in a nested value object; keeping the call
# sites' flat kwargs means this split happens once here rather than in every test.
COMPATIBILITY_FIELDS = {f.name for f in dataclasses.fields(CompatibilityFacts)}


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
        compatibility=CompatibilityFacts(**{k: flags.pop(k) for k in list(flags) if k in COMPATIBILITY_FIELDS}),
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


def make_scan(
    records: list[ScanRecord],
    data_completeness: DataCompleteness | None = None,
    engine_context: EngineContext | None = None,
) -> ScanResult:
    return ScanResult(
        project_name="proj",
        packages_registry="PYPI",
        project_path=".",
        production_packages=records,
        optional_packages=[],
        data_completeness=data_completeness or DataCompleteness(),
        engine_context=engine_context or EngineContext(),
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
    assert entry["latest_in_range"] == record.compatibility.latest_in_range
    assert entry["latest_in_major"] == record.compatibility.latest_in_major


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
    )
    scan = make_scan([record], engine_context=EngineContext({"node": "20.11.0"}, EngineContextSource.DETECTED))
    decision = build_update_decide(scan)
    entry = decision["updates"][0]
    assert entry["engine_requirement"] == {"node": ">=22.0.0"}
    assert entry["engine_compatible"] is False
    # Provenance is stated once for the scan, not repeated per entry - it used to be, and reported
    # "detected" on actionable entries and "none" on the rest of the same scan.
    assert "engine_context_source" not in entry
    assert decision["runtime_context"] == {
        "engine_versions": {"node": "20.11.0"},
        "engine_context_source": "detected",
        "npm_cli_version": None,
        "project_declares_esm": False,
    }
    # engine_mismatch_reason's sentence, not a raw dict repr: the same string the console prints
    # and the structural gate wrote into rejected_candidates.
    assert "requires node >=22.0.0, checked against 20.11.0 (detected)" in entry["reasons"]


def test_update_entry_omits_engine_reason_without_an_engine_context():
    """No engine_context means no evidence either way — nothing to name, so no reason line."""
    record = make_record(
        installed="1.0.0",
        latest="1.1.0",
        diff_index=VERSION_DIFF_MINOR,
        recommended="1.1.0",
        engine_requirement={"node": ">=22.0.0"},
        engine_compatible=False,
    )
    entry = build_update_decide(make_scan([record]))["updates"][0]

    assert not any("requires node" in reason for reason in entry["reasons"])


def test_update_no_action_entry_still_carries_engine_fields_default_none():
    record = make_record(installed="1.0.0", latest="1.0.0")
    decision = build_update_decide(make_scan([record]))
    entry = decision["updates"][0]
    assert entry["engine_requirement"] is None
    assert entry["engine_compatible"] is None
    assert decision["runtime_context"]["engine_context_source"] == "none"


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


def test_widening_reason_omits_the_constraint_when_nothing_is_declared():
    # A transitive-only dep has no declaration of its own, and interpolating it produced
    # "declared range None must be widened" in user-facing agent output.
    record = make_record(
        installed="1.10.13",
        latest="2.13.5",
        diff_index=VERSION_DIFF_MAJOR,
        recommended="1.10.26",
        latest_in_range="1.10.13",
        latest_in_major="1.10.26",
        recommended_from_rung=RecommendationRung.IN_MAJOR,
        version_constraint=None,
        version_constraint_declared=None,
    )
    decision = build_update_decide(make_scan([record]))
    entry = decision["updates"][0]
    assert entry["requires_constraint_widening"] is True
    assert not any("None" in reason for reason in entry["reasons"])
    assert any("1.10.26 is outside the declared range" in reason for reason in entry["reasons"])


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


def test_aliased_entry_carries_its_manifest_key():
    """Two npm aliases of one package produce two entries sharing "package" — the manifest key is
    the only thing that tells a consumer which declaration each one answers for."""
    record = make_record(name="uuid", installed="13.0.0", latest="14.0.2", recommended="14.0.2")
    record.dependency_name = "uuid-v11"

    entry = build_update_decide(make_scan([record]))["updates"][0]

    assert entry["package"] == "uuid"
    assert entry["dependency_name"] == "uuid-v11"


def test_unaliased_entry_omits_the_manifest_key():
    record = make_record(name="requests", installed="2.28.0", latest="2.32.0", recommended="2.32.0")
    record.dependency_name = "requests"

    entry = build_update_decide(make_scan([record]))["updates"][0]

    assert "dependency_name" not in entry


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


@pytest.mark.parametrize(
    "record_kwargs,is_prospective,expected",
    [
        (
            {"name": "pydantic", "installed": "1.10.13", "latest_in_range": "1.10.13", "latest_in_major": "1.10.26"},
            False,
            {"latest_in_range": "1.10.13", "latest_in_major": "1.10.26"},
        ),
        (
            {"name": "pydantic", "installed": "1.10.13", "latest_compatible_major": "1.10.26"},
            False,
            {"latest_compatible_major": "1.10.26"},
        ),
        (None, True, {"latest_in_range": None, "latest_in_major": None}),
        (None, True, {"latest_compatible_major": None}),
    ],
    ids=[
        "installed_package_includes_ladder",
        "installed_package_includes_latest_compatible_major",
        "prospective_package_ladder_is_null",
        "prospective_package_latest_compatible_major_is_null",
    ],
)
def test_add_decide_ladder_and_latest_compatible_major(
    record_kwargs: dict | None, is_prospective: bool, expected: dict
):
    if is_prospective:
        detail = make_detail(make_insight(), warnings=[], cves=[])
    else:
        assert record_kwargs is not None
        record = make_record(**record_kwargs)
        detail = make_installed_detail(record, make_insight(latest="2.13.5", recommended="1.10.26"))
    decision = build_add_decide(detail)
    for key, value in expected.items():
        assert decision[key] == value


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
    assert decision["data_completeness"] == {"overall": "ok", "sources": [], "api_budgets": []}


def test_update_decide_surfaces_degraded_sources_inline():
    """B8 point 2: an agent/script consuming this JSON never sees the console warning
    (show_scan_progress is bypassed entirely for agent/MCP callers) - the only way it can know
    a data source was degraded is if the document says so itself.
    """
    completeness = DataCompleteness(
        by_step={ScanStep.VULNERABILITIES: DataSourceStatus.UNREACHABLE, ScanStep.REPOSITORIES: DataSourceStatus.OK}
    )
    decision = build_update_decide(make_scan([make_record()], data_completeness=completeness))
    assert decision["data_completeness"]["overall"] == "unreachable"
    assert {"step": "vulnerabilities", "status": "unreachable"} in decision["data_completeness"]["sources"]
    assert {"step": "repositories", "status": "ok"} in decision["data_completeness"]["sources"]


def test_update_decide_names_the_cause_and_the_quota_behind_a_degraded_source():
    """An agent that reads "3 repositories not found" retries nothing; one that reads a bare
    `partial` may re-run the whole scan straight into an exhausted quota."""
    completeness = DataCompleteness(
        by_step={ScanStep.REPOSITORIES: DataSourceStatus.PARTIAL},
        diagnostics={
            ScanStep.REPOSITORIES: FetchDiagnostics(
                failures=((DegradeReason.NOT_FOUND, 3),),
                budgets=(RateLimitBudget(resource="core", limit=5000, remaining=120, needed=400),),
            )
        },
    )
    decision = build_update_decide(make_scan([make_record()], data_completeness=completeness))

    assert decision["data_completeness"]["sources"] == [
        {"step": "repositories", "status": "partial", "failures": [{"reason": "not_found", "count": 3}]}
    ]
    assert decision["data_completeness"]["api_budgets"] == [
        {"resource": "core", "limit": 5000, "remaining": 120, "reset_at": None, "needed": 400}
    ]


def test_one_scan_reports_one_engine_context_source_for_every_entry():
    """Regression: the provenance used to be copied onto every ScanRecord, and one real scan
    reported "detected" on actionable entries and "none" on the non-actionable ones. With it on
    ScanResult only, there is exactly one value and nothing to disagree with.
    """
    actionable = make_record(
        installed="1.0.0",
        latest="1.1.0",
        diff_index=VERSION_DIFF_MINOR,
        recommended="1.1.0",
    )
    at_latest = make_record(installed="1.0.0", latest="1.0.0")
    scan = make_scan(
        [actionable, at_latest],
        engine_context=EngineContext({"node": "20.11.0"}, EngineContextSource.DETECTED),
    )

    decision = build_update_decide(scan)

    assert [e["next_action"] for e in decision["updates"]] == ["Update Immediately", "no action needed"]
    assert not any("engine_context_source" in entry for entry in decision["updates"])
    assert decision["runtime_context"]["engine_context_source"] == "detected"


def test_update_entry_flags_a_known_break_the_widening_gate_would_miss():
    """An agent needs the same second look the CLI asks a human for. A pick whose major line is a
    known break can sit inside the declared range, so requires_constraint_widening does not fire.
    """
    record = make_record(
        installed="11.1.0",
        latest="14.0.2",
        diff_index=VERSION_DIFF_MAJOR,
        recommended="14.0.2",
        recommended_from_rung=RecommendationRung.IN_RANGE,
        breaking_change="ESM-only from 12.0.0",
    )
    entry = build_update_decide(make_scan([record]))["updates"][0]

    assert entry["carries_known_break"] is True
    assert "requires_constraint_widening" not in entry
    assert "ESM-only from 12.0.0" in entry["reasons"]


def test_update_entry_omits_the_break_flag_for_a_clean_pick():
    record = make_record(
        installed="1.0.0",
        latest="1.1.0",
        diff_index=VERSION_DIFF_MINOR,
        recommended="1.1.0",
        recommended_from_rung=RecommendationRung.IN_RANGE,
    )
    entry = build_update_decide(make_scan([record]))["updates"][0]

    assert "carries_known_break" not in entry


def test_withheld_package_does_not_blame_the_declared_range():
    """The agent payload used to carry a reason contradicting its own strategy_withheld_reason:
    `declared range <2.0.0 caps this below 1.9.1` next to `no motive admitted at security`, in the
    same entry, when <2.0.0 admits 1.9.1 perfectly well."""
    record = make_record(
        name="scikit-learn",
        installed="1.8.0",
        latest="1.9.1",
        diff_index=VERSION_DIFF_MINOR,
        version_constraint="<2.0.0",
        version_constraint_declared="<2.0.0",
        latest_in_range="1.9.1",
    )
    record.strategy_selection = StrategySelection(
        strategy=UpdateStrategy.SECURITY,
        target_version=None,
        rung=None,
        motives=frozenset(),
        requires_widening=False,
        withheld_reason="no motive admitted at security; available under --update-strategy standard",
        available_at=UpdateStrategy.STANDARD,
        escalation=None,
    )

    entry = build_update_decide(make_scan([record]))["updates"][0]

    assert entry["next_action"] == "Withheld by strategy"
    assert entry["strategy_withheld_reason"].startswith("no motive admitted at security")
    assert not any("caps this below" in reason for reason in entry["reasons"])


def test_a_genuinely_capping_range_is_still_reported():
    record = make_record(
        name="fuse.js",
        installed="7.3.0",
        latest="7.5.0",
        diff_index=VERSION_DIFF_MINOR,
        version_constraint="~7.3.0",
        version_constraint_declared="~7.3.0",
        latest_in_range="7.3.0",
    )

    entry = build_update_decide(make_scan([record]))["updates"][0]

    assert any("declared range ~7.3.0 caps this below 7.5.0" == reason for reason in entry["reasons"])


# --- N1: agent format must surface cve_data_unavailable, not just fix the wording -------------


def test_triage_summary_surfaces_cve_data_unavailable_to_the_agent():
    """The point of N1 is not just an honest reason string - a consuming agent needs a field it
    can branch on without parsing prose. build_update_entry feeds both --format agent and MCP.
    """
    triage = TriageResult(
        action=ACTION_RETAIN,
        reason="CVE data could not be retrieved for this scan; exploit signal unknown, not confirmed clean.",
        max_epss=None,
        suppressed_cves=0,
        cve_data_unavailable=True,
    )
    record = make_record(installed="1.0.0", latest="1.1.0", diff_index=VERSION_DIFF_MINOR, triage=triage)
    decision = build_update_decide(make_scan([record]))
    entry = decision["updates"][0]

    assert entry["dependency_health"]["cve_data_unavailable"] is True
    assert "could not be retrieved" in entry["dependency_health"]["reason"]


def test_triage_summary_omits_cve_data_unavailable_when_false():
    """Matches the sparse-field convention already used for suppressed_cves/deprecation_signals -
    a confirmed-clean scan should not carry a redundant `cve_data_unavailable: false` on every
    single entry.
    """
    triage = TriageResult(
        action=ACTION_RETAIN, reason="No significant exploit or stability signal.", max_epss=None, suppressed_cves=0
    )
    record = make_record(installed="1.0.0", latest="1.1.0", diff_index=VERSION_DIFF_MINOR, triage=triage)
    decision = build_update_decide(make_scan([record]))
    entry = decision["updates"][0]

    assert "cve_data_unavailable" not in entry["dependency_health"]


# --- maintenance verdicts at low signal coverage must say so -----------------------------------


def make_maintenance(state: str, p_not_maintained: float, observations: dict | None = None) -> MaintenanceAssessment:
    posterior: dict[str, float] = {s: 0.0 for s in MaintenanceState}
    posterior[state] = 1.0
    return MaintenanceAssessment(posterior, state, p_not_maintained, observations or {})


def test_maintenance_verdict_surfaces_degraded_signal_coverage():
    """The reported scenario: a strong verdict (abandoned) issued from partial data. An agent
    reading this one record over MCP had no way to know the underlying signals were incomplete -
    the SignalCoverage field already existed and was already correct, just never exposed here.
    """
    maintenance = make_maintenance(MaintenanceState.ABANDONED, 0.9, {"push_age": "stale"})
    triage = TriageResult(action=ACTION_REFACTOR, reason="stale", max_epss=None, suppressed_cves=0)
    record = make_record(
        installed="1.0.0",
        latest="1.1.0",
        diff_index=VERSION_DIFF_MINOR,
        maintenance=maintenance,
        triage=triage,
        signal_coverage=SignalCoverage.ACTIVITY_UNAVAILABLE,
    )
    decision = build_update_decide(make_scan([record]))
    entry = decision["updates"][0]

    assert entry["dependency_health"]["maintenance_state"] == "abandoned"
    assert entry["dependency_health"]["maintenance_signal_coverage"] == "activity_unavailable"


def test_maintenance_verdict_omits_coverage_field_when_full():
    """Matches the sparse-field convention already used elsewhere in this summary - a fully
    covered assessment should not carry a redundant 'coverage: full' on every single entry.
    """
    maintenance = make_maintenance(MaintenanceState.MAINTAINED, 0.05)
    triage = TriageResult(action=ACTION_RETAIN, reason="fine", max_epss=None, suppressed_cves=0)
    record = make_record(
        installed="1.0.0",
        latest="1.1.0",
        diff_index=VERSION_DIFF_MINOR,
        maintenance=maintenance,
        triage=triage,
        signal_coverage=SignalCoverage.FULL,
    )
    decision = build_update_decide(make_scan([record]))
    entry = decision["updates"][0]

    assert "maintenance_signal_coverage" not in entry["dependency_health"]


def test_maintenance_verdict_surfaces_coverage_gap_even_for_a_healthy_state():
    """The honesty principle applies uniformly, not only to alarming verdicts - a 'maintained'
    state assessed from partial data deserves the same transparency as an 'abandoned' one.
    """
    maintenance = make_maintenance(MaintenanceState.MAINTAINED, 0.05)
    triage = TriageResult(action=ACTION_RETAIN, reason="fine", max_epss=None, suppressed_cves=0)
    record = make_record(
        installed="1.0.0",
        latest="1.1.0",
        diff_index=VERSION_DIFF_MINOR,
        maintenance=maintenance,
        triage=triage,
        signal_coverage=SignalCoverage.REPOSITORY_UNAVAILABLE,
    )
    decision = build_update_decide(make_scan([record]))
    entry = decision["updates"][0]

    assert entry["dependency_health"]["maintenance_signal_coverage"] == "repository_unavailable"


def test_update_next_action_agrees_with_a_recommendation_that_clears_the_cve():
    """D4 reproduction: the uuid record from the benchmark said `to: 11.1.1/14.0.2` (a fix) and
    `next_action: Check for the Fix` (no fix) at the same time, next to `triage.action: retain`."""
    advisory = dataclasses.replace(make_cve("8.3.2"), id="GHSA-w5hq-g745-h8pq", epss=0.0001)
    record = make_record(
        name="uuid",
        installed="8.3.2",
        latest="14.0.2",
        diff_index=VERSION_DIFF_MAJOR,
        cves=[advisory],
        recommended="11.1.1",
        recommended_from_rung=RecommendationRung.LATEST,
        triage=TriageResult(ACTION_RETAIN, "No significant exploit or stability signal.", None, 1, False),
    )

    entry = build_update_decide(make_scan([record]))["updates"][0]

    assert entry["to"] == "11.1.1"
    assert entry["next_action"] != "Check for the Fix"


def test_update_next_action_checks_for_the_fix_when_the_recommendation_is_still_affected():
    """select_target's rule 7: every reachable version still carries the CVE, so `to` is no fix."""
    advisory = dataclasses.replace(make_cve("1.0.0"), affected_versions=("1.0.0", "1.1.0"), epss=0.2)
    record = make_record(
        installed="1.0.0",
        latest="1.1.0",
        diff_index=VERSION_DIFF_MINOR,
        cves=[advisory],
        recommended="1.1.0",
        recommended_from_rung=RecommendationRung.IN_RANGE,
    )

    assert build_update_decide(make_scan([record]))["updates"][0]["next_action"] == "Check for the Fix"


def test_update_next_action_is_constrained_when_the_cve_fix_needs_widening():
    advisory = dataclasses.replace(make_cve("1.0.0"), epss=0.001)
    record = make_record(
        installed="1.0.0",
        latest="1.1.0",
        diff_index=VERSION_DIFF_MINOR,
        cves=[advisory],
        recommended="1.1.0",
        recommended_from_rung=RecommendationRung.LATEST,
        version_constraint="1.0.0",
    )

    entry = build_update_decide(make_scan([record]))["updates"][0]

    assert entry["next_action"] == "Constrained. Check newer version"
    assert entry["requires_constraint_widening"] is True


def test_cve_summary_carries_the_epss_score_behind_suppression():
    advisory = dataclasses.replace(make_cve("8.3.2"), epss=0.00012)
    record = make_record(installed="8.3.2", latest="11.1.1", diff_index=VERSION_DIFF_MAJOR, cves=[advisory])

    (cve,) = build_update_decide(make_scan([record]))["updates"][0]["cves"]

    assert cve["epss"] == 0.0001
