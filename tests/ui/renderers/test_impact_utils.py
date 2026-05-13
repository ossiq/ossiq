"""Tests for ui/renderers/impact_utils.py."""

from rich.table import Table

from ossiq.service.update_impact import TransitiveImpact
from ossiq.ui.renderers.impact_utils import impact_sub_row_texts, new_transitive_deps_table


def make_impact(
    package_name: str,
    *,
    current_version: str | None = "1.0.0",
    projected_version: str | None = "2.0.0",
    new_constraint: str = ">=2.0",
    driven_by: str = "requests",
    has_conflict: bool = False,
    conflict_detail: str | None = None,
) -> TransitiveImpact:
    return TransitiveImpact(
        package_name=package_name,
        current_version=current_version,
        projected_version=projected_version,
        new_constraint=new_constraint,
        driven_by=driven_by,
        has_conflict=has_conflict,
        conflict_detail=conflict_detail,
    )


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
    impacts = [make_impact("urllib3", has_conflict=True, conflict_detail="no version satisfies: >=2.0,<1.5")]
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
