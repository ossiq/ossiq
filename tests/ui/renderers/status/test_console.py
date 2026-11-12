"""Tests for the status console renderer: view modes, column sets, and the What's Next column."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest
from rich.console import Console

from ossiq.domain.common import (
    ConstraintType,
    CooldownHold,
    CveDatabase,
    EngineContext,
    EngineContextSource,
    ProjectPackagesRegistry,
    RecommendationRung,
    RejectedCandidate,
    RejectionDetail,
    SignalCoverage,
)
from ossiq.domain.compatibility import CompatibilityFacts
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.project import (
    ConstraintSource,
    IncomingEdge,
    InstalledCopy,
    PeerRequirement,
    UnresolvedPeer,
)
from ossiq.domain.provenance import ProvenanceFacts, SourceLevel, TrustTier
from ossiq.domain.version import VersionsDifference
from ossiq.risk.maintenance import MaintenanceAssessment, MaintenanceState
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.settings import Settings
from ossiq.strategy.pyramid import UpdateStrategy
from ossiq.strategy.targeting import StrategySelection
from ossiq.ui.renderers.impact_utils import (
    REJECTION_DETAIL_LIMIT,
    WHATS_NEXT_SHORT,
    WHATS_NEXT_STYLE,
    format_build_provenance,
    format_source_level,
    provenance_legend,
    whats_next,
)
from ossiq.ui.renderers.status.console import (
    COVERAGE_NAME_LIMIT,
    FULL_MIN_WIDTH,
    FULL_NARROW,
    FULL_WIDE,
    MIN_WIDTH_DEFAULT,
    ConsoleStatusRenderer,
    copy_sub_row_texts,
    installed_cell,
    middle_ellipsis,
)

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
        affected_ranges=(),
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
    breaking_change: str | None = None,
    engine_requirement: dict[str, str] | None = None,
    engine_compatible: bool | None = None,
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
        compatibility=CompatibilityFacts(
            latest_in_major=latest_in_major,
            breaking_change=breaking_change,
            engine_requirement=engine_requirement,
            engine_compatible=engine_compatible,
        ),
    )


FULL_TABLE_WIDTH = 240
"""Roomy enough that no line of a `--full` table wraps."""


def render_table(
    prod: list[ScanRecord],
    dev: list[ScanRecord] | None = None,
    *,
    full: bool = False,
    width: int = 200,
    engine_context: EngineContext | None = None,
) -> str:
    renderer = ConsoleStatusRenderer(Settings())
    renderer.console = Console(record=True, width=width)
    if full:
        renderer.print_full_table([*prod, *(dev or [])], 180, engine_context or EngineContext())
    else:
        table = renderer.build_main_table(prod, dev or [], width=width)
        assert table is not None
        renderer.console.print(table)
    return renderer.console.export_text()


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
        width=80,
    )
    assert "1.0.0" in output  # Installed
    assert "9.9.9" in output  # Latest / Recommended


# --- the --full listing -----------------------------------------------------------------------


@pytest.mark.parametrize("width", [80, FULL_MIN_WIDTH - 1, FULL_MIN_WIDTH, 200])
def test_full_rows_fit_their_console_width(width):
    """Why `--full` has two layouts: the worst-case package is one line, notes included, from 80 columns up."""
    record = with_provenance(
        constrained_record("@typescript-eslint/eslint-plugin"),
        build_tier=TrustTier.NONE,
        source_level=SourceLevel.VERSION_CONTROLLED,
    )
    lines = render_table([record], full=True, width=width).splitlines()
    header, row = lines[0], lines[1]

    assert max(len(line) for line in lines) <= width
    assert "Constrained" in row
    assert "~1.0.0 caps this below 1.5.0" in "\n".join(lines)
    # Only the Package column is ever cut, and from the middle.
    assert row.count("…") == 1 and row.startswith("@type") and row.split()[0].endswith("lugin")
    merged = width < FULL_MIN_WIDTH
    assert ("Src/Bld" in header) is merged
    assert ("Mode Lag" in header) is merged
    assert ("CVE EPSS" in header) is merged
    assert ("CVEs" in header.split()) is not merged


def test_the_two_layouts_swap_at_the_threshold_width():
    assert "Src/Bld" in header_of(render_table([make_record()], full=True, width=FULL_MIN_WIDTH - 1))
    assert "Src/Bld" not in header_of(render_table([make_record()], full=True, width=FULL_MIN_WIDTH))


@pytest.mark.parametrize("layout", [FULL_WIDE, FULL_NARROW])
def test_every_whats_next_code_fits_its_column(layout):
    """A new label without a code, or with a long one, would be cut mid-word in `--full`."""
    width = layout.widths(FULL_MIN_WIDTH)["What's Next"]
    assert set(WHATS_NEXT_SHORT) == set(WHATS_NEXT_STYLE)
    assert max(len(code) for code in WHATS_NEXT_SHORT.values()) <= width


@pytest.mark.parametrize(
    ("text", "width", "expected"),
    [
        ("short", 10, "short"),
        ("exactly-10", 10, "exactly-10"),
        ("@typescript-eslint/eslint-plugin", 11, "@type…lugin"),
        ("1.0.30001600", 9, "1.0.…1600"),
        ("abcdefgh", 4, "ab…h"),
    ],
)
def test_middle_ellipsis_keeps_the_head_and_the_tail(text, width, expected):
    assert middle_ellipsis(text, width) == expected
    assert len(middle_ellipsis(text, width)) <= width


def test_a_wrapped_note_continues_under_its_arrow():
    reason = "trust downgrade: no provenance, but earlier releases had provenance"
    record = with_provenance(make_record(), build_tier=TrustTier.NONE, violations=(reason,))
    lines = render_table([record], full=True, width=60).splitlines()

    first = next(i for i, line in enumerate(lines) if "↳ policy:" in line)
    assert len(lines[first + 1]) - len(lines[first + 1].lstrip()) == lines[first].index("↳")


def test_full_mode_lists_transitive_recommendations_as_rows():
    record = make_record("minimatch", recommended_version="5.0.0")
    record.compatibility.breaking_change = "ESM-only from 5.0.0"

    section = render_report([make_record()], transitive=[record], full=True).split("Transitive Recommendations")[1]

    assert "minimatch" in section
    assert "1.0.0 ➔ 5.0.0" in section
    assert "ESM-only from 5.0.0" in section


def test_full_mode_lists_a_transitive_package_held_back_with_its_reason():
    """No recommendation, but a reason: the row is shown, so the hold is not silent."""
    record = make_record("urllib3", recommended_version=None)
    record.rejected_candidates = [
        RejectedCandidate(version="1.26.20", reason="every release under its constraints still carries a CVE")
    ]

    section = render_report([make_record()], transitive=[record], full=True).split("Transitive Recommendations")[1]

    assert "urllib3" in section
    assert "1.26.20 rejected: every release under its constraints still carries a CVE" in section


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
    assert "Constrained" in output
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


# --- narrow terminals ---------------------------------------------------------------------------


def constrained_record(name: str = "left-pad") -> ScanRecord:
    """A record whose What's Next is the widest label in the set."""
    return make_record(
        name,
        versions_diff_index=MINOR,
        latest_version="1.5.0",
        recommended_version="1.0.0",
        version_constraint="~1.0.0",
        version_constraint_declared="~1.0.0",
    )


def test_whats_next_abbreviated_below_the_narrow_threshold():
    output = render_table([constrained_record()], width=MIN_WIDTH_DEFAULT - 1)
    assert "Constrained" in output
    assert "Check newer version" not in output


def test_whats_next_keeps_the_full_label_at_the_threshold():
    output = render_table([constrained_record()], width=MIN_WIDTH_DEFAULT)
    assert "Constrained. Check newer version" in output


def test_compact_row_fits_at_the_threshold_width():
    """What pins MIN_WIDTH_DEFAULT: at the threshold a representative worst-case row still renders
    on one line with nothing ellipsized. Adding a column means re-measuring the constant, not
    nudging it."""
    output = render_table([constrained_record("vite-plugin-vue-devtools")], width=MIN_WIDTH_DEFAULT)
    assert "Constrained. Check newer version" in output
    assert "…" not in output


def test_abbreviation_is_console_only():
    """whats_next without `short` returns the canonical label, so info / agent / export are
    untouched by the console's width handling."""
    assert whats_next(constrained_record()) == "[yellow]Constrained. Check newer version[/]"


def widening_pick_record(*, authorized: bool) -> ScanRecord:
    """A minor-behind package whose pick, 1.5.0, sits past its `~1.0.0` range."""
    record = make_record(
        versions_diff_index=MINOR,
        latest_version="1.5.0",
        recommended_version="1.5.0",
        version_constraint="~1.0.0",
        version_constraint_declared="~1.0.0",
    )
    record.recommended_from_rung = RecommendationRung.LATEST
    record.strategy_selection = StrategySelection(
        strategy=UpdateStrategy.SECURITY,
        target_version="1.5.0",
        rung=RecommendationRung.LATEST,
        motives=frozenset(),
        requires_widening=True,
        withheld_reason=None,
        available_at=None,
        escalation=None,
        widening_authorized=authorized,
    )
    return record


def test_an_escalated_pick_past_the_range_reads_as_an_update():
    """`plan` writes an authorized widening pick, so the range is not what is holding it back."""
    output = render_table([widening_pick_record(authorized=True)], full=True)
    assert "Update" in output
    assert "Constrained" not in output
    assert "caps this below" not in output


def test_an_unauthorized_pick_past_the_range_stays_constrained():
    output = render_table([widening_pick_record(authorized=False)], full=True)
    assert "Constrained" in output
    assert "~1.0.0 caps this below 1.5.0" in output


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


def test_an_unresolved_peer_puts_an_otherwise_quiet_package_on_the_table():
    """Nothing to update, but the tree is broken for it: status must not filter it out."""
    record = make_record("@vue/test-utils")
    record.unresolved_peers = [
        UnresolvedPeer("@vue/server-renderer", "3.x", optional=True, installed_elsewhere=("3.5.43",))
    ]

    output = render_table([record])

    assert "@vue/test-utils" in output
    assert "optional peer @vue/server-renderer 3.x is installed only out of reach (3.5.43)" in output


def test_a_missing_required_peer_is_named():
    record = make_record("plugin")
    record.unresolved_peers = [UnresolvedPeer("host", "^1")]

    assert "missing peer host ^1" in render_table([record])


def test_a_required_peer_installed_out_of_reach_is_not_called_optional():
    record = make_record("plugin")
    record.unresolved_peers = [UnresolvedPeer("host", "^1", installed_elsewhere=("1.2.0",))]

    output = render_table([record])

    assert "peer host ^1 is installed only out of reach (1.2.0)" in output
    assert "optional" not in output


def nested_record(*copies: InstalledCopy) -> ScanRecord:
    record = make_record("minimatch", versions_diff_index=MINOR, recommended_version="1.0.1")
    record.installed_version = copies[0].version
    record.installed_copies = list(copies)
    return record


def plain_copy(version: str, *edges: IncomingEdge) -> InstalledCopy:
    return InstalledCopy(version, tuple(edges), ConstraintSource(type=ConstraintType.DECLARED, source_file=None))


def forced_copy(version: str, value: str, *, ossiq: bool = False) -> InstalledCopy:
    info = ConstraintSource(
        type=ConstraintType.OVERRIDE, source_file="package.json", override_value=value, is_ossiq_authored=ossiq
    )
    return InstalledCopy(version, (), info)


def test_installed_cell_is_the_plain_version_for_a_package_installed_once():
    assert installed_cell(nested_record(plain_copy("10.2.5"))) == "10.2.5"
    assert installed_cell(make_record()) == "1.0.0"


def test_installed_cell_lists_the_other_copies():
    record = nested_record(plain_copy("10.2.5"), plain_copy("9.0.9"), plain_copy("8.0.1"))
    assert installed_cell(record) == "10.2.5 [dim](+9.0.9, 8.0.1)[/]"


def test_installed_cell_marks_an_override_that_forces_a_copy():
    assert installed_cell(nested_record(forced_copy("3.5.42", "3.5.42"))) == "3.5.42 [yellow]⚑ override[/]"


def test_installed_cell_does_not_flag_an_override_ossiq_wrote():
    assert installed_cell(nested_record(forced_copy("3.5.42", "3.5.42", ossiq=True))) == "3.5.42"


def test_status_table_shows_every_installed_copy():
    record = nested_record(plain_copy("10.2.5"), plain_copy("9.0.9"))
    assert "10.2.5 (+9.0.9)" in render_table([record])


def test_copy_sub_rows_name_who_requires_each_copy():
    record = nested_record(
        plain_copy("10.2.5", IncomingEdge("eslint", "10.2.0", "^10.2.4")),
        plain_copy("9.0.9", IncomingEdge("editorconfig", "1.0.7", "^9.0.1"), IncomingEdge("glob", "10.5.0", "^9.0.4")),
    )
    assert copy_sub_row_texts(record) == [
        "  [dim]↳ 10.2.5 ← eslint ^10.2.4[/]",
        "  [dim]↳ 9.0.9 ← editorconfig ^9.0.1, glob ^9.0.4[/]",
    ]


def test_copy_sub_rows_count_requirers_past_the_limit():
    edges = [IncomingEdge(f"p{i}", "1.0.0", "^9") for i in range(5)]
    rows = copy_sub_row_texts(nested_record(plain_copy("10.2.5"), plain_copy("9.0.9", *edges)))
    assert rows[1] == "  [dim]↳ 9.0.9 ← p0 ^9, p1 ^9 (+3 more)[/]"


def test_copy_sub_rows_say_when_an_override_forces_a_copy():
    rows = copy_sub_row_texts(nested_record(plain_copy("10.2.5"), forced_copy("9.0.9", "9.0.9")))
    assert rows[1] == "  [dim]↳ 9.0.9 ← no requirer[/] [yellow]⚑ forced to 9.0.9[/]"


def test_copy_sub_rows_do_not_flag_an_override_ossiq_wrote():
    rows = copy_sub_row_texts(nested_record(plain_copy("10.2.5"), forced_copy("9.0.9", "9.0.9", ossiq=True)))
    assert rows[1] == "  [dim]↳ 9.0.9 ← no requirer[/]"


def peer_table_text(override_authored_by_ossiq: bool) -> str:
    record = make_record("typescript")
    record.peer_requirements = [PeerRequirement(requirer_name="plugin", spec="^5")]
    record.constraint_info = ConstraintSource(
        type=ConstraintType.OVERRIDE, source_file="package.json", is_ossiq_authored=override_authored_by_ossiq
    )
    table = ConsoleStatusRenderer(Settings()).peer_status_table([record], full=True)
    assert table is not None
    console = Console(record=True, width=200)
    console.print(table)
    return console.export_text()


def test_peer_table_says_via_override_for_an_override_the_user_wrote():
    assert "via override" in peer_table_text(override_authored_by_ossiq=False)


def test_peer_table_reads_an_override_ossiq_wrote_as_satisfied():
    output = peer_table_text(override_authored_by_ossiq=True)
    assert "via override" not in output
    assert "✓ satisfied" in output


def test_copy_sub_rows_are_empty_for_a_package_installed_once():
    assert copy_sub_row_texts(nested_record(plain_copy("10.2.5"))) == []


def test_copy_sub_rows_are_full_mode_only():
    record = nested_record(plain_copy("10.2.5", IncomingEdge("eslint", "10.2.0", "^10.2.4")), plain_copy("9.0.9"))
    assert "↳ 10.2.5 ← eslint ^10.2.4" in render_table([record], full=True)
    assert "↳ 10.2.5 ←" not in render_table([record])


def test_rejection_detail_moves_to_its_own_indented_row():
    record = make_record(versions_diff_index=MINOR, recommended_version="1.0.0")
    record.rejected_candidates = [
        RejectedCandidate(
            version="3.5.43",
            reason="@vue/shared requires 3.5.43",
            detail=RejectionDetail("no version satisfies", ("^3.5.18", "3.5.42")),
        )
    ]
    lines = render_table([record], full=True).splitlines()

    headline = next(i for i, line in enumerate(lines) if "3.5.43 rejected: @vue/shared requires 3.5.43" in line)
    # The spec list is not on the headline - joined there, one row widened the whole table.
    assert "no version satisfies" not in lines[headline]
    assert "no version satisfies: ^3.5.18, 3.5.42" in lines[headline + 1]


def test_rejection_detail_list_is_capped():
    record = make_record(versions_diff_index=MINOR, recommended_version="1.0.0")
    specs = tuple(f">={n}.0.0" for n in range(REJECTION_DETAIL_LIMIT + 3))
    record.rejected_candidates = [
        RejectedCandidate(version="3.5.43", reason="dep-x requires 3.5.43", detail=RejectionDetail("blocked by", specs))
    ]
    output = render_table([record], full=True)

    assert f">={REJECTION_DETAIL_LIMIT - 1}.0.0" in output
    assert f">={REJECTION_DETAIL_LIMIT}.0.0" not in output
    assert "(+3 more)" in output


def test_rejection_detail_row_absent_without_full():
    record = make_record(versions_diff_index=MINOR, recommended_version="1.0.0")
    record.rejected_candidates = [
        RejectedCandidate(
            version="1.2.0",
            reason="dep-x requires >=2.0.0",
            detail=RejectionDetail("no version satisfies", (">=2.0.0",)),
        )
    ]
    assert "no version satisfies" not in render_table([record])


def test_breaking_change_sub_row_shown_in_full_mode():
    record = make_record(versions_diff_index=MINOR, recommended_version="5.0.0")
    record.compatibility.breaking_change = "ESM-only from 5.0.0"
    output = render_table([record], full=True)
    assert "ESM-only from 5.0.0" in output


def test_breaking_change_sub_row_absent_without_full():
    record = make_record(versions_diff_index=MINOR, recommended_version="5.0.0")
    record.compatibility.breaking_change = "ESM-only from 5.0.0"
    output = render_table([record])
    assert "ESM-only from 5.0.0" not in output


def test_engine_mismatch_sub_row_shown_in_full_mode():
    record = make_record(versions_diff_index=MINOR, recommended_version="2.0.0")
    record.compatibility.engine_requirement = {"node": ">=22.0.0"}
    record.compatibility.engine_compatible = False
    output = render_table(
        [record], full=True, engine_context=EngineContext({"node": "18.0.0"}, EngineContextSource.DETECTED)
    )
    assert "requires node >=22.0.0, checked against 18.0.0" in output


def test_engine_mismatch_sub_row_names_only_the_mismatching_engine():
    # A line was printed for every engine_requirement key, mismatching or not - so a package
    # declaring both node and npm reported the npm requirement too, against a "?" placeholder.
    # The text now derives from engine_mismatch_reason, the same check the solver's gate applies.
    record = make_record(versions_diff_index=MINOR, recommended_version="2.0.0")
    record.compatibility.engine_requirement = {"node": ">=22.0.0", "npm": ">=9.0.0"}
    record.compatibility.engine_compatible = False
    output = render_table(
        [record], full=True, engine_context=EngineContext({"node": "18.0.0"}, EngineContextSource.DETECTED)
    )
    assert "requires node >=22.0.0, checked against 18.0.0" in output
    assert "npm" not in output


def test_engine_mismatch_sub_row_omitted_when_nothing_actually_mismatches():
    # engine_compatible is denormalized onto the record and can outlive the pick it was computed
    # for; rather than print a bare arrow, render nothing when the check finds no conflict.
    record = make_record(versions_diff_index=MINOR, recommended_version="2.0.0")
    record.compatibility.engine_requirement = {"node": ">=16.0.0"}
    record.compatibility.engine_compatible = False
    output = render_table(
        [record], full=True, engine_context=EngineContext({"node": "18.0.0"}, EngineContextSource.DETECTED)
    )
    assert "↳" not in output


def test_engine_mismatch_sub_row_absent_without_full():
    record = make_record(versions_diff_index=MINOR, recommended_version="2.0.0")
    record.compatibility.engine_requirement = {"node": ">=22.0.0"}
    record.compatibility.engine_compatible = False
    output = render_table([record], engine_context=EngineContext({"node": "18.0.0"}, EngineContextSource.DETECTED))
    assert "requires node" not in output


def test_engine_mismatch_sub_row_absent_when_compatible():
    record = make_record(versions_diff_index=MINOR, recommended_version="2.0.0")
    record.compatibility.engine_requirement = {"node": ">=16.0.0"}
    record.compatibility.engine_compatible = True
    output = render_table(
        [record], full=True, engine_context=EngineContext({"node": "18.0.0"}, EngineContextSource.DETECTED)
    )
    assert "requires node" not in output


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


def test_transitive_table_rejected_candidate_sub_row_absent_without_full():
    record = make_record(recommended_version=None)
    record.rejected_candidates = [RejectedCandidate(version="2.0.0", reason="dep-y requires >=3.0.0")]
    renderer = ConsoleStatusRenderer(Settings())
    table = renderer.transitive_table([record])
    console = Console(record=True, width=200)
    console.print(table)
    assert "rejected:" not in console.export_text()


def test_transitive_table_engine_mismatch_sub_row_absent_without_full():
    record = make_record(recommended_version="2.0.0")
    record.compatibility.engine_requirement = {"node": ">=22.0.0"}
    record.compatibility.engine_compatible = False
    renderer = ConsoleStatusRenderer(Settings())
    table = renderer.transitive_table([record])
    console = Console(record=True, width=200)
    console.print(table)
    assert "requires node" not in console.export_text()


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


class TestWithheldByStrategySubRow:
    """The tier, not the declared range, gets named when the tier is what withheld the package."""

    def withheld_record(self) -> ScanRecord:
        record = make_record(
            name="scikit-learn",
            versions_diff_index=MINOR,
            latest_version="1.9.1",
            version_constraint="<2.0.0",
            version_constraint_declared="<2.0.0",
        )
        record.compatibility.latest_in_range = "1.9.1"
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
        return record

    def test_withheld_package_names_the_tier_not_the_range(self):
        output = render_table([self.withheld_record()], full=True, width=FULL_TABLE_WIDTH)

        assert "Withheld" in output
        assert "available under --update-strategy standard" in output
        # The bug this replaced: <2.0.0 admits 1.9.1, so it caps nothing.
        assert "caps this below" not in output

    def test_range_that_admits_a_newer_version_is_never_blamed(self):
        """Without a strategy selection the label stays Constrained, but the range still has to
        actually exclude something before the sub-row names it."""
        record = self.withheld_record()
        record.strategy_selection = None

        output = render_table([record], full=True)

        assert "Constrained" in output
        assert "caps this below" not in output

    def test_a_genuinely_capping_range_is_still_named(self):
        record = self.withheld_record()
        record.strategy_selection = None
        record.compatibility.latest_in_range = "1.0.0"  # equals installed: nothing in range

        output = render_table([record], full=True)

        assert "<2.0.0 caps this below 1.9.1" in output


class TestCooldownHoldSubRow:
    """A blank Recommended cell next to a newer Latest reads as a bug unless the cooldown is named."""

    def held_record(self) -> ScanRecord:
        record = make_record(
            name="common-expression-language",
            versions_diff_index=MINOR,
            latest_version="0.10.0",
        )
        record.recommended_version = None
        record.strategy_selection = StrategySelection(
            strategy=UpdateStrategy.STANDARD,
            target_version=None,
            rung=None,
            motives=frozenset(),
            requires_widening=False,
            withheld_reason=None,
            available_at=None,
            escalation=None,
            cooldown_hold=CooldownHold(version="0.10.0", age_days=5, cooldown_period=7),
        )
        return record

    def test_held_package_says_wait_and_names_the_version_and_the_wait(self):
        output = render_table([self.held_record()], full=True, width=FULL_TABLE_WIDTH)

        assert "Cooldown" in output
        assert "0.10.0 is 5 days old" in output
        assert "7-day cooldown" in output
        # The reported defect, in one assertion: the label must not promise an update that
        # `apply` will refuse.
        assert "Update" not in output

    def test_the_declared_range_is_not_blamed_for_a_cooldown_hold(self):
        record = self.held_record()
        record.version_constraint = "<1.0.0"
        record.version_constraint_declared = "<1.0.0"
        record.compatibility.latest_in_range = record.installed_version

        output = render_table([record], full=True)

        assert "caps this below" not in output

    def test_package_manager_hold_names_the_setting_not_the_cooldown(self):
        record = self.held_record()
        assert record.strategy_selection is not None
        record.strategy_selection = dataclasses.replace(
            record.strategy_selection,
            cooldown_hold=CooldownHold(
                version="0.10.0",
                age_days=12,
                cooldown_period=7,
                enforced_by="uv exclude-newer",
                cutoff=datetime(2024, 5, 18, 6, 30, tzinfo=UTC),
            ),
        )

        output = render_table([record], full=True, width=FULL_TABLE_WIDTH)

        assert "Cooldown" in output
        assert "uv exclude-newer cutoff (2024-05-18 06:30 UTC)" in output
        assert "7-day cooldown" not in output


# --- upstream signal coverage panel -----------------------------------------------------------


def render_report(
    prod: list[ScanRecord],
    dev: list[ScanRecord] | None = None,
    *,
    transitive: list[ScanRecord] | None = None,
    full: bool = False,
    width: int = 200,
) -> str:
    """Drive the whole renderer, not just the main table — the panel is a `render()` section."""
    renderer = ConsoleStatusRenderer(Settings())
    renderer.console = Console(record=True, width=width)
    renderer.render(
        ScanResult(
            project_name="demo",
            packages_registry=ProjectPackagesRegistry.NPM,
            project_path="/tmp/demo",
            production_packages=prod,
            optional_packages=dev or [],
            transitive_packages=transitive or [],
        ),
        full=full,
    )
    return renderer.console.export_text()


def uncovered(name: str, coverage: SignalCoverage) -> ScanRecord:
    record = make_record(name)
    record.signal_coverage = coverage
    return record


class TestSignalCoveragePanel:
    def test_panel_names_each_package_under_its_reason(self):
        output = render_report(
            [
                uncovered("gitlab-pkg", SignalCoverage.UNSUPPORTED_HOST),
                uncovered("orphan-pkg", SignalCoverage.NO_REPOSITORY),
                uncovered("private-pkg", SignalCoverage.REPOSITORY_UNAVAILABLE),
                make_record("covered-pkg"),
            ],
            full=True,
        )

        assert "Upstream Signal Coverage" in output
        assert "3 of 4 packages (including transitive) gave up less than the full signal set" in output
        for label, name in (
            ("Not on GitHub (1)", "gitlab-pkg"),
            ("No repository declared (1)", "orphan-pkg"),
            ("Repository unreachable (1)", "private-pkg"),
        ):
            line = next(line for line in output.splitlines() if label in line)
            assert name in line
        # The panel exists to name what was missed; a covered package is not a gap.
        assert "covered-pkg" not in output.split("Upstream Signal Coverage")[1]

    def test_panel_absent_when_every_package_is_covered(self):
        output = render_report([make_record("a"), make_record("b")], full=True)

        assert "Upstream Signal Coverage" not in output

    def test_panel_absent_without_full(self):
        output = render_report([uncovered("gitlab-pkg", SignalCoverage.UNSUPPORTED_HOST)])

        assert "Upstream Signal Coverage" not in output

    def test_development_packages_are_counted_too(self):
        output = render_report(
            [make_record("prod-pkg")],
            [uncovered("dev-pkg", SignalCoverage.UNSUPPORTED_HOST)],
            full=True,
        )

        assert "1 of 2 packages (including transitive) gave up less than the full signal set" in output
        assert "dev-pkg" in output

    def test_transitive_packages_are_counted_too(self):
        # The /repos fetch covers the whole graph, so a transitive package's failed fetch is in
        # the scan's degraded count. Leaving it out of the panel left that count unattributable.
        output = render_report(
            [make_record("prod-pkg")],
            transitive=[uncovered("deep-pkg", SignalCoverage.REPOSITORY_UNAVAILABLE)],
            full=True,
        )

        assert "1 of 2 packages" in output
        assert "deep-pkg" in output

    def test_commit_history_gap_is_reported_separately_from_the_repository(self):
        # A package whose repo answered but whose commits did not has metadata and no maintenance
        # assessment — two failed fetches for one package, and only one of them named here.
        output = render_report([uncovered("half-pkg", SignalCoverage.ACTIVITY_UNAVAILABLE)], full=True)

        line = next(line for line in output.splitlines() if "Commit history unreachable (1)" in line)
        assert "half-pkg" in line

    def test_long_name_lists_are_capped(self):
        records = [uncovered(f"pkg-{n:02d}", SignalCoverage.UNSUPPORTED_HOST) for n in range(COVERAGE_NAME_LIMIT + 4)]

        # Scoped to the panel: every name is also a row in the main table above it.
        panel = render_report(records, full=True).split("Upstream Signal Coverage")[1]

        assert "pkg-00" in panel
        assert f"pkg-{COVERAGE_NAME_LIMIT:02d}" not in panel
        assert "(+4 more)" in panel


# --- supply-chain provenance ------------------------------------------------------------------


def with_provenance(record: ScanRecord, **facts) -> ScanRecord:
    record.provenance = ProvenanceFacts(**facts)
    return record


def test_default_mode_leaves_the_provenance_columns_to_full():
    header = header_of(render_table([make_record(versions_diff_index=MINOR, recommended_version="1.1.0")]))
    assert "Build" not in header
    assert "Source" not in header


@pytest.mark.parametrize(
    ("tier", "badge"),
    [(TrustTier.TRUSTED_PUBLISHER, "L2"), (TrustTier.PROVENANCE, "L1"), (TrustTier.NONE, "L0")],
)
def test_the_build_column_badges_the_installed_releases_tier(tier, badge):
    output = render_table([with_provenance(make_record(), build_tier=tier)], full=True, width=FULL_TABLE_WIDTH)
    assert badge in output.splitlines()[1].split()


def test_a_package_whose_tier_was_not_read_shows_a_dash_not_none():
    output = render_table([with_provenance(make_record(), build_tier=None)], full=True, width=FULL_TABLE_WIDTH)
    assert "L0" not in output


def test_a_violation_is_written_under_the_package_in_every_mode():
    record = with_provenance(
        make_record(versions_diff_index=MINOR, recommended_version="1.1.0"),
        build_tier=TrustTier.NONE,
        violations=("trust downgrade: no provenance, but earlier releases had provenance",),
    )
    for full in (False, True):
        output = render_table([record], full=full, width=FULL_TABLE_WIDTH)
        assert "↳ policy: trust downgrade" in output


def test_a_package_at_latest_with_a_violation_is_not_hidden_in_the_compact_table():
    record = with_provenance(make_record(), build_tier=TrustTier.NONE, violations=("below the required provenance",))
    assert "below the required provenance" in render_table([record])


def test_a_quiet_package_with_no_violation_stays_out_of_the_compact_table():
    renderer = ConsoleStatusRenderer(Settings())
    clean = with_provenance(make_record(), build_tier=TrustTier.NONE)
    assert renderer.build_main_table([clean], []) is None


@pytest.mark.parametrize(
    ("level", "badge"),
    [(SourceLevel.VERSION_CONTROLLED, "L1"), (SourceLevel.PROTECTED_HISTORY, "L2"), (SourceLevel.REVIEWED, "L3")],
)
def test_the_source_column_badges_the_repositorys_level(level, badge):
    record = with_provenance(make_record(), source_level=level)
    assert badge in render_table([record], full=True, width=FULL_TABLE_WIDTH).splitlines()[1].split()


class TestRedCellsFollowTheRuleThatFailed:
    """One policy can fail on the build and pass on the source (or the reverse): only the failing cell is red."""

    BUILD = "no provenance, below the required provenance"
    SOURCE = "source repository is version-controlled, below the required protected-history"

    def record(self, *violations: str) -> ScanRecord:
        return with_provenance(
            make_record(),
            build_tier=TrustTier.NONE,
            source_level=SourceLevel.PROTECTED_HISTORY,
            violations=violations,
        )

    def test_a_build_failure_reddens_the_build_cell_only(self):
        record = self.record(self.BUILD)

        assert "✗L0" in format_build_provenance(record)
        assert "✗" not in format_source_level(record)

    def test_a_source_failure_reddens_the_source_cell_only(self):
        record = self.record(self.SOURCE)

        assert "✗" not in format_build_provenance(record)
        assert "✗L2" in format_source_level(record)

    def test_both_failing_reddens_both(self):
        record = self.record(self.BUILD, self.SOURCE)

        assert "✗" in format_build_provenance(record) and "✗" in format_source_level(record)

    def test_neither_failing_reddens_neither(self):
        record = self.record()

        assert "✗" not in format_build_provenance(record) + format_source_level(record)


# --- the Versions cell and its notes ----------------------------------------------------------


def test_an_off_latest_recommendation_notes_the_latest():
    output = render_table(
        [make_record(versions_diff_index=MINOR, latest_version="1.5.0", recommended_version="1.2.0")], full=True
    )
    assert "1.0.0 ➔ 1.2.0" in output
    assert "↳ latest 1.5.0" in output


def test_a_recommendation_at_the_latest_adds_no_latest_note():
    output = render_table(
        [make_record(versions_diff_index=MINOR, latest_version="1.2.0", recommended_version="1.2.0")], full=True
    )
    assert "1.0.0 ➔ 1.2.0" in output
    assert "↳ latest" not in output


@pytest.mark.parametrize(
    "record",
    [
        make_record(),
        make_record(recommended_version="1.0.0"),
        make_record(versions_diff_index=MINOR, latest_version="1.5.0"),
        make_record(versions_diff_index=MINOR, latest_version="1.5.0", recommended_version="1.0.0"),
    ],
    ids=["at latest", "recommends itself", "nothing to recommend", "held on the installed version"],
)
def test_no_arrow_without_a_newer_version_to_move_to(record):
    row = render_table([record], full=True).splitlines()[1]
    assert "➔" not in row and "—" not in row.split("  ")[1]
    assert row.split()[1] == "1.0.0"


def test_a_package_held_behind_the_latest_still_names_the_latest():
    output = render_table([make_record(versions_diff_index=MINOR, latest_version="1.5.0")], full=True)
    assert "↳ latest 1.5.0" in output


def test_a_conflict_prints_no_target():
    record = make_record(versions_diff_index=MINOR, latest_version="1.5.0", recommended_version="1.5.0")
    record.constraint_conflict = ["a ^1.0.0", "b ^2.0.0"]
    output = render_table([record], full=True)
    assert "➔" not in output.splitlines()[1]
    assert "no version satisfies: a ^1.0.0 + b ^2.0.0" in output
    assert "↳ latest 1.5.0" in output


def test_a_long_version_is_cut_from_the_middle():
    record = make_record(versions_diff_index=MINOR, latest_version="1.0.30001600", recommended_version="1.0.30001600")
    record.installed_version = "1.0.30001599-beta.12"
    row = render_table([record], full=True, width=80).splitlines()[1]
    assert "…" in row
    assert "1.0.30001599-beta.12" not in row


def test_extra_installed_copies_move_to_a_note():
    output = render_table([nested_record(plain_copy("10.2.5"), plain_copy("9.0.9"))], full=True)
    assert "↳ installed 10.2.5 (+9.0.9)" in output


# --- the footer legend ------------------------------------------------------------------------


def test_the_legend_spells_out_every_badge_in_the_console_words():
    source, build = provenance_legend()
    assert source == "L1 vcs · L2 protected · L3 reviewed"
    assert build.startswith("L0 none · L1 attested · L2 trusted")


def test_the_legend_follows_the_full_listing_only():
    assert "Src  L1 vcs" in render_report([make_record()], full=True)
    assert "Src  L1 vcs" not in render_report([make_record(versions_diff_index=MINOR, recommended_version="1.1.0")])
