"""Tests for the status console renderer's main table — the EPSS column."""

from __future__ import annotations

from rich.console import Console

from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VersionsDifference
from ossiq.service.project.models import ScanRecord
from ossiq.settings import Settings
from ossiq.ui.renderers.status.console import ConsoleStatusRenderer


def make_record(
    name: str = "left-pad",
    *,
    epss: float | None = None,
) -> ScanRecord:
    return ScanRecord(
        package_name=name,
        dependency_name=name,
        is_optional_dependency=False,
        installed_version="1.0.0",
        latest_version="1.0.0",
        versions_diff_index=VersionsDifference("1.0.0", "1.0.0", 0, "LATEST"),
        time_lag_days=0,
        releases_lag=0,
        cve=[],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
        epss=epss,
    )


def render_table(prod: list[ScanRecord], dev: list[ScanRecord] | None = None) -> str:
    renderer = ConsoleStatusRenderer(Settings())
    table = renderer.build_main_table(prod, dev or [], lag_threshold_days=180)
    assert table is not None
    console = Console(record=True, width=200)
    console.print(table)
    return console.export_text()


def test_epss_column_shown_when_any_record_has_epss():
    records = [make_record("left-pad", epss=0.853), make_record("right-pad", epss=None)]
    output = render_table(records)
    assert "EPSS" in output
    assert "85.3%" in output


def test_epss_column_hidden_when_every_record_epss_is_none():
    records = [make_record("left-pad", epss=None), make_record("right-pad", epss=None)]
    output = render_table(records)
    assert "EPSS" not in output
