"""
Tests for the agent verdict builder (service.agent).

Covers the ok/warn/block branches for both the add and update flows, driven
entirely from existing scan/package result fields.
"""

from ossiq.domain.common import ConstraintType, CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VERSION_DIFF_MAJOR, VERSION_LATEST, VersionsDifference
from ossiq.service.agent import build_add_verdict, build_update_verdict
from ossiq.service.package import (
    RULE_SINGLE_MAINTAINER,
    RULE_SINGLE_VERSION,
    PackageDetailResult,
    PackageInsight,
    PackageWarning,
)
from ossiq.service.project import ScanRecord, ScanResult


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


# --- add verdict -----------------------------------------------------------


def test_add_ok_when_clean_and_at_latest():
    detail = make_detail(make_insight(latest="2.0.0", recommended="2.0.0"), warnings=[], cves=[])
    verdict = build_add_verdict(detail)
    assert verdict["verdict"] == "ok"
    assert verdict["recommended_version"] == "2.0.0"
    assert verdict["operation"] == "add"
    assert verdict["registry"] == "pypi"


def test_add_warn_on_single_maintainer():
    warning = PackageWarning(RULE_SINGLE_MAINTAINER, "Single maintainer — bus factor risk", "warning")
    detail = make_detail(make_insight(maintainers=1), warnings=[warning], cves=[])
    verdict = build_add_verdict(detail, requested_version="2.0.0")
    assert verdict["verdict"] == "warn"
    assert RULE_SINGLE_MAINTAINER in verdict["warnings"]
    assert verdict["requested_version"] == "2.0.0"


def test_add_block_on_critical_warning():
    warning = PackageWarning(RULE_SINGLE_VERSION, "Only one version — typosquat risk", "critical")
    detail = make_detail(make_insight(), warnings=[warning], cves=[])
    verdict = build_add_verdict(detail)
    assert verdict["verdict"] == "block"


def test_add_warn_when_cve_present():
    detail = make_detail(make_insight(), warnings=[], cves=[make_cve()])
    verdict = build_add_verdict(detail)
    assert verdict["verdict"] == "warn"
    assert verdict["cves"][0]["id"] == "CVE-2023-0001"


# --- update verdict --------------------------------------------------------


def make_scan(records: list[ScanRecord]) -> ScanResult:
    return ScanResult(
        project_name="proj",
        packages_registry="PYPI",
        project_path=".",
        production_packages=records,
        optional_packages=[],
    )


def test_update_ok_when_nothing_actionable():
    scan = make_scan([make_record()])
    verdict = build_update_verdict(scan)
    assert verdict["verdict"] == "ok"
    assert verdict["updates"] == []


def test_update_warn_on_recommended_bump():
    record = make_record(installed="1.0.0", latest="2.0.0", diff_index=VERSION_DIFF_MAJOR, recommended="2.0.0")
    verdict = build_update_verdict(make_scan([record]))
    assert verdict["verdict"] == "warn"
    assert verdict["updates"][0]["to"] == "2.0.0"


def test_update_block_when_cve_has_no_fix():
    # CVE present, recommended == installed (no safe escape) -> block.
    record = make_record(installed="1.0.0", cves=[make_cve()], recommended="1.0.0")
    verdict = build_update_verdict(make_scan([record]))
    assert verdict["verdict"] == "block"
    assert verdict["updates"][0]["verdict"] == "block"


def test_update_block_on_yanked():
    record = make_record(is_installed_yanked=True)
    verdict = build_update_verdict(make_scan([record]))
    assert verdict["verdict"] == "block"
