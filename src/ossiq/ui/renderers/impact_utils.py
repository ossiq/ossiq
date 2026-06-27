"""Shared Rich-rendering utilities for transitive impact display."""

from rich.table import Table

from ossiq.domain.version import (
    VERSION_DIFF_BUILD,
    VERSION_DIFF_MAJOR,
    VERSION_DIFF_MINOR,
    VERSION_DIFF_PATCH,
    VERSION_DIFF_PRERELEASE,
    VERSION_LATEST,
    VersionsDifference,
)
from ossiq.service.update_impact import TransitiveImpact
from ossiq.timeutil import format_time_days


def format_time_delta(days: int | None, lag_threshold_days: int) -> str:
    """Format time delta with color highlighting."""
    if days is None:
        return "N/A"
    formatted_string = format_time_days(days)
    return f"[bold red]{formatted_string}" if days >= lag_threshold_days else formatted_string


def format_lag_status(vdiff: VersionsDifference) -> str:
    """Format version lag status with color coding."""
    if vdiff.diff_index == VERSION_DIFF_MAJOR:
        return "[red][bold]Major"
    elif vdiff.diff_index == VERSION_DIFF_MINOR:
        return "[yellow][bold]Minor"
    elif vdiff.diff_index == VERSION_DIFF_PATCH:
        return "[bold blue]Patch"
    elif vdiff.diff_index == VERSION_DIFF_PRERELEASE:
        return "[yellow][bold]Prerelease"
    elif vdiff.diff_index == VERSION_DIFF_BUILD:
        return "[bold blue]Build"
    elif vdiff.diff_index == VERSION_LATEST:
        return "[green][bold]Latest"
    else:
        return "[bold]N/A"


def impact_sub_row_texts(impacts: list[TransitiveImpact]) -> list[str]:
    """Return Rich-markup strings for each transitive impact, one per sub-row."""
    is_actionable = all(not i.has_conflict for i in impacts if i.current_version is not None)
    rows: list[str] = []
    if not is_actionable:
        rows.append("[red]  ✗ no actionable update found[/red]")

    conflicts = [i for i in impacts if i.has_conflict]
    normal = [i for i in impacts if not i.has_conflict and i.current_version is not None]
    new_deps = [i for i in impacts if i.current_version is None]

    show_detail = (len(impacts) - len(new_deps)) <= 3

    for impact in conflicts:
        rows.append(f"[yellow]  ↳ ⚠ {impact.package_name}: {impact.conflict_detail or 'conflict'}[/yellow]")

    if show_detail:
        for impact in normal:
            rows.append(f"[dim]  ↳ {impact.package_name} {impact.current_version} → {impact.projected_version}[/dim]")
    elif normal:
        rows.append(f"[dim]  ↳ {len(normal)} transitive dep(s) also updated[/dim]")

    for impact in new_deps:
        version_info = impact.projected_version or impact.new_constraint
        rows.append(f"[dim blue]  + {impact.package_name} {version_info} (new dep)[/dim blue]")

    return rows


def is_fresh_new_dep(impact: TransitiveImpact, cooldown_period: int) -> bool:
    """True when a new dep's projected version is younger than the cooldown period."""
    if cooldown_period <= 0 or impact.projected_age_days is None:
        return False
    return impact.projected_age_days < cooldown_period


def new_transitive_deps_table(impacts: list[TransitiveImpact], cooldown_period: int = 0) -> Table | None:
    """Build a Rich table of brand-new transitive deps introduced by recommended updates.

    New deps are resolved by the package manager outside the cooldown hold, so versions
    younger than cooldown_period are flagged with a ⚠ marker instead of being withheld.
    Returns None when there are no new deps, so the caller can skip printing.
    """
    new_deps = [i for i in impacts if i.current_version is None]
    if not new_deps:
        return None

    table = Table(
        title="New transitive dependencies introduced by recommended updates",
        title_style="bold",
        box=None,
        padding=(0, 2),
    )
    table.add_column("Package", justify="left", style="bold")
    table.add_column("Version", justify="left")
    table.add_column("Constraint", justify="left")
    table.add_column("Age", justify="left", style="dim")
    table.add_column("Required By", justify="left", style="dim")

    for impact in new_deps:
        pkg_cell = impact.package_name
        if is_fresh_new_dep(impact, cooldown_period):
            pkg_cell = f"[yellow]⚠ {impact.package_name}[/yellow]"
        age = f"{impact.projected_age_days}d" if impact.projected_age_days is not None else "—"
        version = impact.projected_version or "—"
        table.add_row(pkg_cell, version, impact.new_constraint, age, impact.driven_by)

    return table
