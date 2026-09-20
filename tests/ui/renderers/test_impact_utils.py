"""Tests for ui/renderers/impact_utils.py."""

from rich.console import Console
from rich.table import Table

from ossiq.domain.common import RejectionDetail
from ossiq.service.update_impact import TransitiveImpact
from ossiq.ui.renderers.impact_utils import (
    REJECTION_DETAIL_LIMIT,
    format_probability,
    format_rejection_detail,
    impact_sub_row_texts,
    is_fresh_new_dep,
    new_transitive_deps_table,
)


def make_impact(
    package_name: str,
    *,
    current_version: str | None = "1.0.0",
    projected_version: str | None = "2.0.0",
    new_constraint: str = ">=2.0",
    driven_by: str = "requests",
    has_conflict: bool = False,
    conflict: RejectionDetail | None = None,
    projected_age_days: int | None = None,
) -> TransitiveImpact:
    return TransitiveImpact(
        package_name=package_name,
        current_version=current_version,
        projected_version=projected_version,
        new_constraint=new_constraint,
        driven_by=driven_by,
        has_conflict=has_conflict,
        conflict=conflict,
        projected_age_days=projected_age_days,
    )


def render_table(table: Table) -> str:
    recording = Console(record=True, width=120)
    recording.print(table)
    return recording.export_text()


# ============================================================================
# new_transitive_deps_table
# ============================================================================


def test_new_transitive_deps_table_empty_list_returns_none():
    assert new_transitive_deps_table([]) is None


def test_new_transitive_deps_table_no_new_deps_returns_none():
    impacts = [make_impact("urllib3"), make_impact("certifi")]
    assert new_transitive_deps_table(impacts) is None


def test_new_transitive_deps_table_with_new_dep_returns_table():
    impacts = [make_impact("h2", current_version=None, projected_version=None, new_constraint=">=4.0")]
    result = new_transitive_deps_table(impacts)
    assert isinstance(result, Table)


def test_new_transitive_deps_table_skips_existing_deps():
    impacts = [
        make_impact("urllib3"),
        make_impact("h2", current_version=None, new_constraint=">=4.0"),
    ]
    result = new_transitive_deps_table(impacts)
    assert isinstance(result, Table)
    assert result.row_count == 1


def test_new_transitive_deps_table_multiple_new_deps():
    impacts = [
        make_impact("h2", current_version=None, new_constraint=">=4.0", driven_by="requests"),
        make_impact("sniffio", current_version=None, new_constraint=">=1.1", driven_by="anyio"),
    ]
    result = new_transitive_deps_table(impacts)
    assert isinstance(result, Table)
    assert result.row_count == 2


def test_new_transitive_deps_table_shows_age_and_version():
    impacts = [make_impact("h2", current_version=None, projected_version="4.1.0", projected_age_days=30)]
    result = new_transitive_deps_table(impacts, cooldown_period=7)
    assert isinstance(result, Table)
    output = render_table(result)
    assert "4.1.0" in output
    assert "30d" in output


def test_new_transitive_deps_table_marks_fresh_dep():
    impacts = [make_impact("h2", current_version=None, projected_version="4.1.0", projected_age_days=2)]
    result = new_transitive_deps_table(impacts, cooldown_period=7)
    assert isinstance(result, Table)
    output = render_table(result)
    assert "⚠" in output


def test_new_transitive_deps_table_unknown_age_renders_dash():
    impacts = [make_impact("h2", current_version=None, projected_version=None, projected_age_days=None)]
    result = new_transitive_deps_table(impacts, cooldown_period=7)
    assert isinstance(result, Table)
    output = render_table(result)
    assert "⚠" not in output
    assert "—" in output


def test_is_fresh_new_dep_thresholds():
    fresh = make_impact("h2", current_version=None, projected_age_days=2)
    mature = make_impact("h2", current_version=None, projected_age_days=30)
    unknown = make_impact("h2", current_version=None, projected_age_days=None)
    assert is_fresh_new_dep(fresh, cooldown_period=7) is True
    assert is_fresh_new_dep(mature, cooldown_period=7) is False
    assert is_fresh_new_dep(unknown, cooldown_period=7) is False
    assert is_fresh_new_dep(fresh, cooldown_period=0) is False


# ============================================================================
# impact_sub_row_texts
# ============================================================================


def test_impact_sub_row_texts_new_dep_shows_constraint_not_none():
    impacts = [make_impact("h2", current_version=None, projected_version=None, new_constraint=">=4.0")]
    rows = impact_sub_row_texts(impacts)
    assert any("None" not in r for r in rows)
    assert any(">=4.0" in r for r in rows)


def test_impact_sub_row_texts_new_dep_shows_projected_version_when_available():
    impacts = [make_impact("h2", current_version=None, projected_version="4.1.0", new_constraint=">=4.0")]
    rows = impact_sub_row_texts(impacts)
    assert any("4.1.0" in r for r in rows)


def test_impact_sub_row_texts_conflict_shows_warning():
    impacts = [
        make_impact(
            "urllib3",
            has_conflict=True,
            conflict=RejectionDetail("no version satisfies", (">=2.0", "<1.5")),
        )
    ]
    rows = impact_sub_row_texts(impacts)
    assert any("✗ no actionable update found" in r for r in rows)
    assert any("⚠" in r for r in rows)


def test_impact_sub_row_texts_normal_dep_shows_version_transition():
    impacts = [make_impact("certifi", current_version="2022.1.1", projected_version="2024.1.1")]
    rows = impact_sub_row_texts(impacts)
    assert any("2022.1.1" in r and "2024.1.1" in r for r in rows)


def test_impact_sub_row_texts_count_mode_for_many_deps():
    impacts = [make_impact(f"pkg{i}") for i in range(5)]
    rows = impact_sub_row_texts(impacts)
    assert any("transitive dep(s) also updated" in r for r in rows)


def test_format_probability():
    assert format_probability(0.1234) == "12.3%"
    assert format_probability(0.0) == "0.0%"
    assert format_probability(None) == "[dim]—[/dim]"


def test_format_rejection_detail_under_the_limit_shows_everything():
    detail = RejectionDetail("no version satisfies", (">=2.0", "<1.5"))

    assert format_rejection_detail(detail) == "no version satisfies: >=2.0, <1.5"
    assert "more" not in format_rejection_detail(detail)


def test_format_rejection_detail_at_the_limit_does_not_count():
    items = tuple(f">={n}.0" for n in range(REJECTION_DETAIL_LIMIT))
    detail = RejectionDetail("blocked by", items)

    assert format_rejection_detail(detail) == "blocked by: " + ", ".join(items)


def test_format_rejection_detail_over_the_limit_counts_the_remainder():
    items = tuple(f">={n}.0" for n in range(REJECTION_DETAIL_LIMIT + 7))

    rendered = format_rejection_detail(RejectionDetail("blocked by", items))

    assert rendered.endswith("(+7 more)")
    assert f">={REJECTION_DETAIL_LIMIT}.0" not in rendered


def test_impact_conflict_row_elides_a_long_spec_list():
    items = tuple(f">={n}.0" for n in range(REJECTION_DETAIL_LIMIT + 2))
    impacts = [make_impact("urllib3", has_conflict=True, conflict=RejectionDetail("no version satisfies", items))]

    rows = impact_sub_row_texts(impacts)

    assert any("(+2 more)" in row for row in rows)
