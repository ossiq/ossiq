"""
Tests for the agent decision builder (service.agent).

Covers the next-action branches for both the add and update flows, driven
entirely from existing scan/package result fields.
"""

from ossiq.domain.common import ConstraintType, CveDatabase, ProjectPackagesRegistry, RecommendationRung
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


def make_scan(records: list[ScanRecord]) -> ScanResult:
    return ScanResult(
        project_name="proj",
        packages_registry="PYPI",
        project_path=".",
        production_packages=records,
        optional_packages=[],
    )


def test_update_no_action_when_nothing_actionable():
    decision = build_update_decide(make_scan([make_record()]))
    assert decision["next_action"] == "no action needed"
    assert decision["updates"] == []
    assert "verdict" not in decision


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
    )
    decision = build_update_decide(make_scan([record]))
    entry = decision["updates"][0]
    assert entry["requires_constraint_widening"] is True
    assert any("must be widened" in reason for reason in entry["reasons"])


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


def test_add_decide_ladder_null_for_prospective():
    detail = make_detail(make_insight(), warnings=[], cves=[])
    decision = build_add_decide(detail)
    assert decision["latest_in_range"] is None
    assert decision["latest_in_major"] is None
