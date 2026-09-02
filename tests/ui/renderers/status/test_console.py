"""Tests for the status console renderer: view modes, column sets, and the What's Next column."""

from __future__ import annotations

from rich.console import Console

from ossiq.domain.common import ConstraintType, CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VersionsDifference
from ossiq.risk.maintenance import MaintenanceAssessment, MaintenanceState
from ossiq.service.project.models import ScanRecord
from ossiq.settings import Settings
from ossiq.ui.renderers.impact_utils import whats_next
from ossiq.ui.renderers.status.console import ConsoleStatusRenderer

LATEST = VersionsDifference("1.0.0", "1.0.0", 0, "LATEST")
MINOR = VersionsDifference("1.0.0", "1.1.0", 4, "DIFF_MINOR")
MAJOR = VersionsDifference("1.0.0", "2.0.0", 5, "DIFF_MAJOR")
PATCH = VersionsDifference("1.0.0", "1.0.1", 3, "DIFF_PATCH")


def assessment(state: MaintenanceState) -> MaintenanceAssessment:
    not_maintained = state in (MaintenanceState.ABANDONED, MaintenanceState.DEPRECATED)
    return MaintenanceAssessment(
        posterior={s.value: 0.0 for s in MaintenanceState},
        state=state.value,
        p_not_maintained=1.0 if not_maintained else 0.0,
        observations={},
    )


def fake_cve(name: str = "left-pad", epss: float | None = None) -> CVE:
    return CVE(
        id="CVE-2020-0001",
        cve_ids=("CVE-2020-0001",),
        source=CveDatabase.OSV,
        package_name=name,
        package_registry=ProjectPackagesRegistry.NPM,
        summary="",
        severity=Severity.HIGH,
        affected_versions=("1.0.0",),
        published=None,
        link="",
        epss=epss,
    )


def make_record(
    name: str = "left-pad",
    *,
    versions_diff_index: VersionsDifference = LATEST,
    latest_version: str = "1.0.0",
    cve: list[CVE] | None = None,
    epss: float | None = None,
    maintenance: MaintenanceAssessment | None = None,
    recommended_version: str | None = None,
) -> ScanRecord:
    return ScanRecord(
        package_name=name,
        dependency_name=name,
        is_optional_dependency=False,
        installed_version="1.0.0",
        latest_version=latest_version,
        versions_diff_index=versions_diff_index,
        time_lag_days=0,
        releases_lag=0,
        cve=cve or [],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
        epss=epss,
        maintenance=maintenance,
        recommended_version=recommended_version,
    )


def render_table(prod: list[ScanRecord], dev: list[ScanRecord] | None = None, *, full: bool = False) -> str:
    renderer = ConsoleStatusRenderer(Settings())
    table = renderer.build_main_table(prod, dev or [], lag_threshold_days=180, full=full)
    assert table is not None
    console = Console(record=True, width=200)
    console.print(table)
    return console.export_text()


# --- column sets ------------------------------------------------------------------------------


def test_default_mode_shows_minimal_columns():
    output = render_table([make_record(versions_diff_index=MINOR, recommended_version="1.1.0")])
    assert "What's Next" in output
    assert "Recommended" in output
    for hidden in ("Update Mode", "Installed", "EPSS", "Latest", "State", "Lag"):
        assert hidden not in output


def test_full_mode_shows_detail_columns():
    output = render_table(
        [make_record(versions_diff_index=MINOR, recommended_version="1.1.0")],
        full=True,
    )
    for shown in ("EPSS", "Update Mode", "Installed", "Recommended", "Lag", "State", "What's Next"):
        assert shown in output
    assert "Latest" not in output
    assert "Action" not in output


# --- default-mode filtering ------------------------------------------------------------------


def test_default_mode_hides_up_to_date_maintained_package():
    output = render_table(
        [
            make_record("keep-me", versions_diff_index=MINOR, recommended_version="1.1.0"),
            make_record("drop-me", maintenance=assessment(MaintenanceState.MAINTAINED)),
        ]
    )
    assert "keep-me" in output
    assert "drop-me" not in output


def test_default_mode_keeps_abandoned_package_at_latest():
    output = render_table([make_record("dead-lib", maintenance=assessment(MaintenanceState.ABANDONED))])
    assert "dead-lib" in output
    assert "Find alternative" in output


def test_default_mode_hides_winding_down_package_at_latest():
    output = render_table(
        [
            make_record("keep-me", versions_diff_index=MINOR, recommended_version="1.1.0"),
            make_record("quiet-lib", maintenance=assessment(MaintenanceState.WINDING_DOWN)),
        ]
    )
    assert "quiet-lib" not in output


# --- transitive table ----------------------------------------------------------------------------


def test_transitive_table_default_columns():
    renderer = ConsoleStatusRenderer(Settings())
    table = renderer.transitive_table([make_record(versions_diff_index=MINOR, recommended_version="1.1.0")])
    console = Console(record=True, width=200)
    console.print(table)
    output = console.export_text()
    assert "What's Next" in output
    assert "EPSS" not in output
    assert "Age" not in output


def test_transitive_table_full_adds_epss():
    renderer = ConsoleStatusRenderer(Settings())
    table = renderer.transitive_table([make_record(epss=0.4, recommended_version="1.1.0")], full=True)
    console = Console(record=True, width=200)
    console.print(table)
    assert "EPSS" in console.export_text()


# --- whats_next column ------------------------------------------------------------------------


def test_whats_next_active_cve_outranks_drift():
    record = make_record(versions_diff_index=MINOR, cve=[fake_cve(epss=0.2)], epss=0.2)
    cell = whats_next(record)
    assert "Check for the Fix" in cell
    assert "[bold red]" in cell


def test_whats_next_low_epss_cve_falls_through_to_drift():
    record = make_record(versions_diff_index=MINOR, cve=[fake_cve(epss=0.05)], epss=0.05)
    assert "Update Immediately" in whats_next(record)


def test_whats_next_deprecated_at_latest_is_find_alternative():
    record = make_record(maintenance=assessment(MaintenanceState.DEPRECATED))
    cell = whats_next(record)
    assert "Find alternative" in cell
    assert "[bold red]" in cell


def test_whats_next_winding_down_is_consider_alternative():
    record = make_record(versions_diff_index=MINOR, maintenance=assessment(MaintenanceState.WINDING_DOWN))
    cell = whats_next(record)
    assert "Consider alternative" in cell
    assert "[bold yellow]" in cell


def test_whats_next_major_drift_is_check_release_notes():
    assert "Check Release Notes" in whats_next(make_record(versions_diff_index=MAJOR))


def test_whats_next_patch_drift_is_update_immediately():
    assert "Update Immediately" in whats_next(make_record(versions_diff_index=PATCH))


def test_whats_next_clean_package_is_empty():
    record = make_record(maintenance=assessment(MaintenanceState.MAINTAINED))
    assert whats_next(record) == ""
