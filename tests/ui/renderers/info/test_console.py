"""Tests for the info console renderer — block order, dedupe helpers and both render paths."""

from __future__ import annotations

from rich.console import Console

from ossiq.domain.common import ConstraintType, CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.package import Package
from ossiq.domain.project import ConstraintSource, PeerRequirement
from ossiq.domain.version import VERSION_DIFF_MAJOR, VersionsDifference
from ossiq.service.package import PackageDetailResult, PackageInsight, PackageWarning, TransitiveCVEGroup
from ossiq.service.project.models import ScanRecord
from ossiq.settings import Settings
from ossiq.solver.reason import RecommendationReason, VersionRejection
from ossiq.ui.renderers.impact_utils import format_status_badge
from ossiq.ui.renderers.info.blocks import collect_licenses, unique_cves
from ossiq.ui.renderers.info.console import ConsoleInfoRenderer


def make_cve(cve_id: str, severity: Severity = Severity.MEDIUM, summary: str = "boom") -> CVE:
    return CVE(
        id=cve_id,
        cve_ids=(cve_id,),
        source=CveDatabase.OSV,
        package_name="left-pad",
        package_registry=ProjectPackagesRegistry.NPM,
        summary=summary,
        severity=severity,
        affected_versions=("1.0.0",),
        published=None,
        link=f"https://example.test/{cve_id}",
    )


def make_reason(version: str = "1.2.0", is_latest: bool = False) -> RecommendationReason:
    return RecommendationReason(
        selected_version=version,
        constraint="^1.0.0",
        hard_rejections=[
            VersionRejection(version="3.0.0", cause="constraint_mismatch", detail="outside ^1.0.0"),
            VersionRejection(version="2.0.0", cause="constraint_mismatch", detail="outside ^1.0.0"),
        ],
        soft_rejections=[VersionRejection(version="1.3.0", cause="very_fresh", detail="too fresh")],
        lower_semver_alternatives=[],
        age_days=42,
        is_latest=is_latest,
    )


def make_record(
    *,
    installed: str = "1.0.0",
    dependency_path: list[str] | None = None,
    license: list[str] | None = None,
    cve: list[CVE] | None = None,
    recommended: str | None = None,
    peer_requirements: list[PeerRequirement] | None = None,
    is_installed_yanked: bool = False,
) -> ScanRecord:
    return ScanRecord(
        package_name="left-pad",
        dependency_name="left-pad",
        is_optional_dependency=False,
        installed_version=installed,
        latest_version="3.0.0",
        versions_diff_index=VersionsDifference(installed, "3.0.0", VERSION_DIFF_MAJOR, "major"),
        time_lag_days=400,
        releases_lag=6,
        cve=cve or [],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
        version_constraint="^1.0.0",
        dependency_path=dependency_path,
        license=license,
        package_url="https://example.test/left-pad",
        recommended_version=recommended,
        recommended_version_reason=make_reason(recommended) if recommended else None,
        peer_requirements=peer_requirements or [],
        is_installed_yanked=is_installed_yanked,
        fitness=55,
        impact=1.0,
        p_vuln=0.15,
        p_supplychain=0.0,
        expected_exposure=0.1514,
        exposure_window_days=120.0,
    )


def make_insight(recommended: str | None = "1.2.0") -> PackageInsight:
    return PackageInsight(
        versions_count=19,
        maintainers_count=6,
        downloads_recent=2_114_066,
        latest_version="3.0.0",
        latest_version_age_days=30,
        recommended_version=recommended,
        recommended_version_age_days=42,
        cooldown_days_remaining=None,
    )


def render(data: PackageDetailResult) -> str:
    renderer = ConsoleInfoRenderer(Settings())
    renderer.console = Console(record=True, width=120)
    renderer.render(data=data)
    return renderer.console.export_text()


def test_installed_render_covers_every_occurrence_block() -> None:
    records = [
        make_record(license=["MIT"], cve=[make_cve("GHSA-aaa")], recommended="1.2.0"),
        make_record(installed="1.1.0", dependency_path=["parent"], license=["Apache-2.0"]),
    ]
    data = PackageDetailResult(
        records=records,
        transitive_cve_groups=[TransitiveCVEGroup(name="dep", version="2.0.0", cves=[make_cve("GHSA-bbb")])],
        project_name="demo",
        packages_registry="npm",
        insight=make_insight(),
    )

    output = render(data)

    assert "OSS IQ — left-pad  1.0.0" in output
    assert "DIRECT" in output and "TRANSITIVE" in output
    # Both occurrences render, each with its own drift/tree/policy block.
    assert "Occurrence 1 of 2" in output and "Occurrence 2 of 2" in output
    assert output.count("Drift Status") == 2
    assert output.count("Dependency Tree") == 2
    assert output.count("Policy Compliance") == 2
    # The transitive occurrence's ancestor shows up in its trace.
    assert "└─ parent" in output
    assert "← you are here" in output
    # Risk rows are marked as belonging to the first occurrence only.
    assert "* for occurrence 1 of 2 (1.0.0); others may differ" in output
    # Rationale renders once, for the occurrence that has a recommendation.
    assert output.count("Recommendation Rationale") == 1
    assert "Eliminated (hard constraints):" in output
    assert "3.0.0, 2.0.0  — outside ^1.0.0" in output
    assert "Penalised (soft constraints):" in output
    assert "1.2.0 selected: best stable candidate (42 days old)" in output
    # Direct and transitive advisories are separate sections.
    assert "Security Advisories (1 found)" in output
    assert "GHSA-aaa" in output
    assert "Transitive CVEs (1 affected)" in output
    assert "GHSA-bbb" in output
    # Two distinct licenses across occurrences trigger the licenses block.
    assert "Licenses" in output
    assert "Apache-2.0" in output


def test_installed_render_without_findings_reports_all_clear() -> None:
    data = PackageDetailResult(
        records=[make_record(license=["MIT"])],
        transitive_cve_groups=[],
        project_name="demo",
        packages_registry="npm",
    )

    output = render(data)

    assert "✓ No known vulnerabilities" in output
    assert "Occurrence" not in output
    assert "Transitive CVEs" not in output
    # A single license is already shown in the header, so the block is skipped.
    assert "Licenses" not in output


def test_prospective_render_uses_insight_for_version_and_age() -> None:
    package = Package(
        registry=ProjectPackagesRegistry.NPM,
        name="left-pad",
        latest_version="3.0.0",
        next_version=None,
        repo_url=None,
        description="pads on the left",
        package_url="https://example.test/left-pad",
        license="MIT",
    )
    data = PackageDetailResult(
        records=[],
        transitive_cve_groups=[],
        project_name="demo",
        packages_registry="npm",
        insight=make_insight(),
        is_prospective=True,
        prospective_name="left-pad",
        prospective_cves=[make_cve("GHSA-ccc", severity=Severity.CRITICAL)],
        prospective_package=package,
        prospective_reason=make_reason("1.2.0"),
    )

    output = render(data)

    assert "PROSPECTIVE" in output
    assert "pads on the left" in output
    # Header age comes from the insight, the selected-line age from the reason.
    assert "Recommended : 1.2.0  (42 days old)" in output
    assert "1.2.0 selected: best stable candidate (42 days old)" in output
    # The constraint line is shared with the installed path.
    assert "Constraint  : ^1.0.0" in output
    assert "Security Advisories (1 found)" in output
    assert "CRITICAL" in output
    # Nothing occurrence-scoped leaks into the prospective path.
    assert "Drift Status" not in output
    assert "Policy Compliance" not in output


def test_warnings_panel_renders_before_the_body() -> None:
    data = PackageDetailResult(
        records=[make_record()],
        transitive_cve_groups=[],
        project_name="demo",
        packages_registry="npm",
        warnings=[PackageWarning(rule_id="unmaintained", message="no releases in 3 years", severity="critical")],
    )

    output = render(data)

    assert "WARNINGS" in output
    assert "no releases in 3 years" in output
    assert output.index("no releases in 3 years") < output.index("Drift Status")


def test_peer_requirements_flag_violations() -> None:
    requirement = PeerRequirement(requirer_name="consumer", spec=">=2.0.0")
    record = make_record(peer_requirements=[requirement])
    record.peer_violations = [requirement]
    data = PackageDetailResult(
        records=[record],
        transitive_cve_groups=[],
        project_name="demo",
        packages_registry="npm",
    )

    output = render(data)

    assert "Peer Requirements" in output
    assert "✗ consumer  requires  >=2.0.0  (installed: 1.0.0)" in output


def test_collect_licenses_dedupes_preserving_first_seen_order() -> None:
    records = [
        make_record(license=["MIT", "Apache-2.0"]),
        make_record(license=["Apache-2.0", "BSD-3-Clause"]),
        make_record(license=None),
    ]

    assert collect_licenses(records) == ["MIT", "Apache-2.0", "BSD-3-Clause"]


def test_unique_cves_dedupes_by_id_preserving_first_seen_order() -> None:
    records = [
        make_record(cve=[make_cve("GHSA-aaa"), make_cve("GHSA-bbb")]),
        make_record(cve=[make_cve("GHSA-bbb"), make_cve("GHSA-ccc")]),
    ]

    assert [cve.id for cve in unique_cves(records)] == ["GHSA-aaa", "GHSA-bbb", "GHSA-ccc"]


def test_status_badge_precedence_is_unpublished_first() -> None:
    record = make_record()
    assert format_status_badge(record) == ""

    record.is_installed_prerelease = True
    assert format_status_badge(record) == " [yellow][pre][/]"

    record.is_installed_deprecated = True
    assert format_status_badge(record) == " [bold yellow][DEPRECATED][/]"

    record.is_installed_yanked = True
    assert format_status_badge(record) == " [bold red][YANKED][/]"

    record.is_installed_package_unpublished = True
    assert format_status_badge(record) == " [bold red][UNPUBLISHED][/]"


def test_yanked_badge_reaches_header_and_drift_status() -> None:
    data = PackageDetailResult(
        records=[make_record(is_installed_yanked=True)],
        transitive_cve_groups=[],
        project_name="demo",
        packages_registry="npm",
    )

    output = render(data)

    assert output.count("[YANKED]") == 2
