"""Tests for the status console renderer: view modes, column sets, and the What's Next column."""

from __future__ import annotations

from rich.console import Console

from ossiq.domain.common import ConstraintType, CveDatabase, ProjectPackagesRegistry, RejectedCandidate
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
    latest_version: str | None = "1.0.0",
    cve: list[CVE] | None = None,
    epss: float | None = None,
    maintenance: MaintenanceAssessment | None = None,
    recommended_version: str | None = None,
    version_constraint: str | None = None,
    version_constraint_declared: str | None = None,
    latest_in_major: str | None = None,
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
        version_constraint=version_constraint,
        version_constraint_declared=version_constraint_declared,
        latest_in_major=latest_in_major,
    )


def render_table(
    prod: list[ScanRecord], dev: list[ScanRecord] | None = None, *, full: bool = False, width: int = 200
) -> str:
    renderer = ConsoleStatusRenderer(Settings())
    table = renderer.build_main_table(prod, dev or [], lag_threshold_days=180, full=full)
    assert table is not None
    console = Console(record=True, width=width)
    console.print(table)
    return console.export_text()


# --- column sets ------------------------------------------------------------------------------


def header_of(output: str) -> str:
    """The table's header row alone — "Latest" is also an Update Mode *value*, so a
    whole-output substring check cannot tell a column name from a cell."""
    return output.splitlines()[0]


def test_default_mode_shows_minimal_columns():
    header = header_of(render_table([make_record(versions_diff_index=MINOR, recommended_version="1.1.0")]))
    for shown in ("Package", "CVEs", "Installed", "Latest", "Recommended", "What's Next"):
        assert shown in header
    for hidden in ("Update Mode", "EPSS", "State", "Lag"):
        assert hidden not in header


def test_narrow_terminal_keeps_fixed_format_columns_intact():
    """At a narrow width, Rich may wrap Package/What's Next, but no_wrap columns holding short
    fixed-format content (versions, badges, counts) must never be split mid-token."""
    output = render_table(
        [
            make_record(
                name="a-very-long-package-name-that-forces-the-table-to-shrink-columns",
                versions_diff_index=MINOR,
                latest_version="9.9.9",
                recommended_version="9.9.9",
            )
        ],
        full=True,
        width=80,
    )
    assert "1.0.0" in output  # Installed
    assert "9.9.9" in output  # Latest / Recommended


def test_full_mode_shows_detail_columns():
    header = header_of(render_table([make_record(versions_diff_index=MINOR, recommended_version="1.1.0")], full=True))
    for shown in ("EPSS", "Update Mode", "Installed", "Latest", "Recommended", "Lag", "State", "What's Next"):
        assert shown in header
    assert "Action" not in header


# --- Latest column and the constrained sub-row ------------------------------------------------


def test_latest_column_shows_the_registry_latest_not_the_recommendation():
    """The whole point: Recommended is clamped to the declared range, Latest is not."""
    output = render_table(
        [
            make_record(
                versions_diff_index=MINOR,
                latest_version="1.5.0",
                recommended_version="1.0.0",
                version_constraint="~1.0.0",
            )
        ],
        full=True,
    )
    assert "1.5.0" in output


def test_latest_column_is_a_dash_when_unknown():
    output = render_table([make_record(versions_diff_index=MINOR, latest_version=None)], full=True)
    assert "—" in output


def test_constrained_package_names_the_range_holding_it_back():
    output = render_table(
        [
            make_record(
                versions_diff_index=MINOR,
                latest_version="1.5.0",
                recommended_version="1.0.0",
                version_constraint="~1.0.0",
                version_constraint_declared="~1.0.0",
            )
        ],
        full=True,
    )
    assert "Constrained. Check newer version" in output
    assert "~1.0.0 caps this below 1.5.0" in output


def test_constrained_sub_row_shows_declared_not_effective_constraint():
    """The sub-row must read version_constraint_declared, not version_constraint — the latter is
    a last-writer-wins accumulator a competing transitive/peer parent can clobber."""
    output = render_table(
        [
            make_record(
                versions_diff_index=MINOR,
                latest_version="1.5.0",
                recommended_version="1.0.0",
                version_constraint="^1.2.0",  # clobbered by some other parent's spec
                version_constraint_declared="~1.0.0",  # the manifest's own declaration
            )
        ],
        full=True,
    )
    assert "~1.0.0 caps this below 1.5.0" in output
    assert "^1.2.0" not in output


def test_constrained_sub_row_is_full_mode_only():
    output = render_table(
        [
            make_record(
                versions_diff_index=MINOR,
                latest_version="1.5.0",
                recommended_version="1.0.0",
                version_constraint="~1.0.0",
                version_constraint_declared="~1.0.0",
            )
        ]
    )
    assert "Constrained. Check newer version" in output
    assert "caps this below" not in output


def test_constrained_sub_row_names_latest_in_major_when_it_differs_from_latest():
    output = render_table(
        [
            make_record(
                versions_diff_index=MINOR,
                latest_version="2.5.0",
                recommended_version="1.0.0",
                version_constraint="~1.0.0",
                version_constraint_declared="~1.0.0",
                latest_in_major="1.9.0",
            )
        ],
        full=True,
        width=260,
    )
    assert "~1.0.0 caps this below 2.5.0; 1.9.0 is the newest in the current major line" in output


def test_constrained_sub_row_omits_latest_in_major_clause_when_equal_to_latest():
    output = render_table(
        [
            make_record(
                versions_diff_index=MINOR,
                latest_version="1.5.0",
                recommended_version="1.0.0",
                version_constraint="~1.0.0",
                version_constraint_declared="~1.0.0",
                latest_in_major="1.5.0",
            )
        ],
        full=True,
    )
    assert "~1.0.0 caps this below 1.5.0" in output
    assert "newest in the current major line" not in output


def test_rejected_candidate_sub_row_shown_in_full_mode():
    record = make_record(versions_diff_index=MINOR, recommended_version="1.0.0")
    record.rejected_candidates = [RejectedCandidate(version="1.2.0", reason="dep-x requires >=2.0.0")]
    output = render_table([record], full=True)
    assert "1.2.0 rejected: dep-x requires >=2.0.0" in output


def test_rejected_candidate_sub_row_absent_without_full():
    record = make_record(versions_diff_index=MINOR, recommended_version="1.0.0")
    record.rejected_candidates = [RejectedCandidate(version="1.2.0", reason="dep-x requires >=2.0.0")]
    output = render_table([record])
    assert "rejected:" not in output


def test_breaking_change_sub_row_shown_in_full_mode():
    record = make_record(versions_diff_index=MINOR, recommended_version="5.0.0")
    record.breaking_change = "ESM-only from 5.0.0"
    output = render_table([record], full=True)
    assert "ESM-only from 5.0.0" in output


def test_breaking_change_sub_row_absent_without_full():
    record = make_record(versions_diff_index=MINOR, recommended_version="5.0.0")
    record.breaking_change = "ESM-only from 5.0.0"
    output = render_table([record])
    assert "ESM-only from 5.0.0" not in output


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


def test_transitive_table_rejected_candidate_sub_row_shown_in_full_mode():
    record = make_record(recommended_version=None)
    record.rejected_candidates = [RejectedCandidate(version="2.0.0", reason="dep-y requires >=3.0.0")]
    renderer = ConsoleStatusRenderer(Settings())
    table = renderer.transitive_table([record], full=True)
    console = Console(record=True, width=200)
    console.print(table)
    assert "2.0.0 rejected: dep-y requires >=3.0.0" in console.export_text()


def test_transitive_table_rejected_candidate_sub_row_absent_without_full():
    record = make_record(recommended_version=None)
    record.rejected_candidates = [RejectedCandidate(version="2.0.0", reason="dep-y requires >=3.0.0")]
    renderer = ConsoleStatusRenderer(Settings())
    table = renderer.transitive_table([record], full=False)
    console = Console(record=True, width=200)
    console.print(table)
    assert "rejected:" not in console.export_text()


def test_transitive_table_breaking_change_sub_row_shown_in_full_mode():
    record = make_record(recommended_version="5.0.0")
    record.breaking_change = "ESM-only from 5.0.0"
    renderer = ConsoleStatusRenderer(Settings())
    table = renderer.transitive_table([record], full=True)
    console = Console(record=True, width=200)
    console.print(table)
    assert "ESM-only from 5.0.0" in console.export_text()


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
