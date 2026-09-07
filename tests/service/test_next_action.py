"""Tests for the shared next-action ladder (service.project.next_action)."""

from ossiq.domain.common import ConstraintType, CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VERSION_DIFF_MAJOR, VERSION_DIFF_MINOR, VERSION_LATEST, VersionsDifference
from ossiq.risk.maintenance import MaintenanceAssessment, MaintenanceState
from ossiq.service.project.models import ScanRecord
from ossiq.service.project.next_action import (
    CHECK_FOR_THE_FIX,
    CHECK_RELEASE_NOTES,
    CONSIDER_ALTERNATIVE,
    CONSTRAINED_CHECK_NEWER,
    FIND_ALTERNATIVE,
    UPDATE_IMMEDIATELY,
    next_action_label,
)

MINOR = VersionsDifference("1.0.0", "1.1.0", VERSION_DIFF_MINOR, "DIFF_MINOR")
MAJOR = VersionsDifference("1.0.0", "2.0.0", VERSION_DIFF_MAJOR, "DIFF_MAJOR")
LATEST = VersionsDifference("1.0.0", "1.0.0", VERSION_LATEST, "LATEST")


def assessment(state: MaintenanceState) -> MaintenanceAssessment:
    not_maintained = state in (MaintenanceState.ABANDONED, MaintenanceState.DEPRECATED)
    return MaintenanceAssessment(
        posterior={s.value: 0.0 for s in MaintenanceState},
        state=state.value,
        p_not_maintained=1.0 if not_maintained else 0.0,
        observations={},
    )


def fake_cve(epss: float | None = None) -> CVE:
    return CVE(
        id="CVE-2024-0001",
        cve_ids=("CVE-2024-0001",),
        source=CveDatabase.OSV,
        package_name="demo",
        package_registry=ProjectPackagesRegistry.NPM,
        summary="",
        severity=Severity.HIGH,
        affected_versions=("1.0.0",),
        published=None,
        link="",
        epss=epss,
    )


def make_record(
    *,
    versions_diff_index: VersionsDifference = LATEST,
    cve: list[CVE] | None = None,
    epss: float | None = None,
    maintenance: MaintenanceAssessment | None = None,
    recommended_version: str | None = None,
    version_constraint: str | None = None,
) -> ScanRecord:
    return ScanRecord(
        package_name="demo",
        dependency_name=None,
        is_optional_dependency=False,
        installed_version="1.0.0",
        latest_version="1.0.0",
        versions_diff_index=versions_diff_index,
        time_lag_days=None,
        releases_lag=None,
        cve=cve or [],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
        epss=epss,
        maintenance=maintenance,
        recommended_version=recommended_version,
        version_constraint=version_constraint,
    )


def test_active_cve_outranks_drift():
    record = make_record(versions_diff_index=MINOR, cve=[fake_cve(0.2)], epss=0.2)
    assert next_action_label(record) == CHECK_FOR_THE_FIX


def test_low_epss_cve_falls_through_to_drift():
    record = make_record(versions_diff_index=MINOR, cve=[fake_cve(0.05)], epss=0.05)
    assert next_action_label(record) == UPDATE_IMMEDIATELY


def test_abandoned_at_latest_is_find_alternative():
    assert next_action_label(make_record(maintenance=assessment(MaintenanceState.ABANDONED))) == FIND_ALTERNATIVE


def test_winding_down_is_consider_alternative():
    record = make_record(versions_diff_index=MINOR, maintenance=assessment(MaintenanceState.WINDING_DOWN))
    assert next_action_label(record) == CONSIDER_ALTERNATIVE


def test_major_drift_is_check_release_notes():
    assert next_action_label(make_record(versions_diff_index=MAJOR)) == CHECK_RELEASE_NOTES


def test_clean_current_package_has_no_action():
    assert next_action_label(make_record(maintenance=assessment(MaintenanceState.MAINTAINED))) is None


# --- drift the declared range will not let you act on -----------------------------------------


def test_in_range_bump_available_is_update_immediately():
    record = make_record(versions_diff_index=MINOR, recommended_version="1.0.7", version_constraint="~1.0.0")
    assert next_action_label(record) == UPDATE_IMMEDIATELY


def test_recommendation_pinned_to_installed_is_constrained():
    """`~1.0.0` with nothing newer inside it: "Update Immediately" would name no target."""
    record = make_record(versions_diff_index=MINOR, recommended_version="1.0.0", version_constraint="~1.0.0")
    assert next_action_label(record) == CONSTRAINED_CHECK_NEWER


def test_no_recommendation_under_a_constraint_is_constrained():
    record = make_record(versions_diff_index=MINOR, recommended_version=None, version_constraint="~1.0.0")
    assert next_action_label(record) == CONSTRAINED_CHECK_NEWER


def test_no_recommendation_and_no_constraint_stays_update_immediately():
    """Nothing is holding it back — the solver simply had no opinion."""
    record = make_record(versions_diff_index=MINOR, recommended_version=None, version_constraint=None)
    assert next_action_label(record) == UPDATE_IMMEDIATELY


def test_major_drift_under_a_constraint_still_reads_release_notes():
    record = make_record(versions_diff_index=MAJOR, recommended_version="1.0.0", version_constraint="~1.0.0")
    assert next_action_label(record) == CHECK_RELEASE_NOTES


def test_active_cve_outranks_a_constrained_package():
    record = make_record(
        versions_diff_index=MINOR,
        cve=[fake_cve(0.2)],
        epss=0.2,
        recommended_version="1.0.0",
        version_constraint="~1.0.0",
    )
    assert next_action_label(record) == CHECK_FOR_THE_FIX
