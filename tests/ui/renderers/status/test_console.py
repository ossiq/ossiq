"""Tests for the status console renderer's main table — gate badges and the Fitness column."""

from __future__ import annotations

from rich.console import Console

from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VersionsDifference
from ossiq.risk.gate import GateDecision
from ossiq.service.project.models import ScanRecord
from ossiq.settings import Settings
from ossiq.ui.renderers.status.console import ConsoleStatusRenderer


def make_record(
    name: str = "left-pad",
    *,
    gate_decision: GateDecision | None = None,
    fitness: int | None = None,
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
        gate_decision=gate_decision,
        fitness=fitness,
    )


def render_table(prod: list[ScanRecord], dev: list[ScanRecord] | None = None) -> str:
    renderer = ConsoleStatusRenderer(Settings())
    table = renderer.build_main_table(prod, dev or [], lag_threshold_days=180)
    assert table is not None
    console = Console(record=True, width=200)
    console.print(table)
    return console.export_text()


def test_gate_badge_shown_for_blocked_package():
    record = make_record(gate_decision=("block", "known critical CVE"))
    output = render_table([record])
    assert "[BLOCK]" in output
    assert "↳ gate: known critical CVE" in output


def test_gate_badge_shown_for_quarantined_package():
    record = make_record(gate_decision=("quarantine", "released 2 days ago"))
    output = render_table([record])
    assert "[QUARANTINE]" in output
    assert "↳ gate: released 2 days ago" in output


def test_gate_badge_absent_for_passing_package():
    record = make_record(gate_decision=("pass", "ok"))
    output = render_table([record])
    assert "[BLOCK]" not in output
    assert "[QUARANTINE]" not in output
    assert "↳ gate:" not in output


def test_gate_badge_absent_when_no_gate_decision():
    record = make_record(gate_decision=None)
    output = render_table([record])
    assert "[BLOCK]" not in output
    assert "[QUARANTINE]" not in output
    assert "↳ gate:" not in output


def test_fitness_column_shown_when_any_record_has_fitness():
    records = [make_record("left-pad", fitness=85), make_record("right-pad", fitness=None)]
    output = render_table(records)
    assert "Fitness" in output
    assert "85" in output


def test_fitness_column_hidden_when_every_record_fitness_is_none():
    records = [make_record("left-pad", fitness=None), make_record("right-pad", fitness=None)]
    output = render_table(records)
    assert "Fitness" not in output
