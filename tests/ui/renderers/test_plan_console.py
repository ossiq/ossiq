"""Tests for the plan console renderer — convergence notice and held-for-cooldown section."""

from __future__ import annotations

from rich.console import Console

from ossiq.domain.common import ConstraintType
from ossiq.service.update import UpdateEntry, UpdatePlan
from ossiq.settings import Settings
from ossiq.ui.renderers.plan import console as plan_console
from ossiq.ui.renderers.plan.console import ConsolePlanRenderer
from ossiq.unit_of_work.solver.reason import RecommendationReason


def reason_with_age(version: str, age_days: int) -> RecommendationReason:
    return RecommendationReason(
        selected_version=version,
        constraint=None,
        hard_rejections=[],
        soft_rejections=[],
        lower_semver_alternatives=[],
        age_days=age_days,
        is_latest=False,
    )


def make_entry(name: str, current: str, recommended: str, age_days: int, is_direct: bool) -> UpdateEntry:
    return UpdateEntry(
        package_name=name,
        current_version=current,
        recommended_version=recommended,
        is_direct=is_direct,
        reason=reason_with_age(recommended, age_days),
        constraint_type=ConstraintType.DECLARED,
    )


def render(plan: UpdatePlan, monkeypatch) -> str:
    recording = Console(record=True, width=120)
    monkeypatch.setattr(plan_console, "console", recording)
    ConsolePlanRenderer(Settings()).render(data=plan, script="")
    return recording.export_text()


def make_plan(
    direct_entries: list[UpdateEntry] | None = None,
    transitive_entries: list[UpdateEntry] | None = None,
    held_for_cooldown: list[UpdateEntry] | None = None,
    cooldown_period: int = 7,
) -> UpdatePlan:
    return UpdatePlan(
        project_name="frontend",
        project_path="/tmp/frontend",
        registry_type="NPM",
        package_manager_name="npm",
        direct_entries=direct_entries or [],
        transitive_entries=transitive_entries or [],
        held_for_cooldown=held_for_cooldown or [],
        cooldown_period=cooldown_period,
    )


def test_convergence_notice_shown_with_transitive_entries(monkeypatch):
    plan = make_plan(transitive_entries=[make_entry("open", "10.2.0", "11.0.0", 208, is_direct=False)])
    output = render(plan, monkeypatch)
    assert "Re-run `ossiq plan`" in output


def test_no_convergence_notice_without_tree_changes(monkeypatch):
    plan = make_plan(direct_entries=[make_entry("requests", "2.28.0", "2.32.0", 90, is_direct=True)])
    output = render(plan, monkeypatch)
    assert "Re-run `ossiq plan`" not in output


def test_held_for_cooldown_section_lists_package(monkeypatch):
    plan = make_plan(
        held_for_cooldown=[make_entry("@vue/reactivity", "3.5.35", "3.5.38", 0, is_direct=False)],
        cooldown_period=7,
    )
    output = render(plan, monkeypatch)
    assert "Held for cooldown" in output
    assert "7-day" in output
    assert "@vue/reactivity" in output
    assert "3.5.38" in output


def make_forced_entry(name: str, current: str, recommended: str, is_direct: bool) -> UpdateEntry:
    return UpdateEntry(
        package_name=name,
        current_version=current,
        recommended_version=recommended,
        is_direct=is_direct,
        reason=None,
        constraint_type=ConstraintType.OVERRIDE,
        is_forced=True,
    )


def test_forced_entry_rendered_with_forced_type_and_warning(monkeypatch):
    plan = make_plan(transitive_entries=[make_forced_entry("urllib3", "1.26.0", "1.26.19", is_direct=False)])
    output = render(plan, monkeypatch)
    assert "forced" in output
    assert "bypass solver compatibility checks" in output


def test_no_forced_warning_without_forced_entries(monkeypatch):
    plan = make_plan(direct_entries=[make_entry("requests", "2.28.0", "2.32.0", 90, is_direct=True)])
    output = render(plan, monkeypatch)
    assert "bypass solver compatibility checks" not in output


def make_security_entry(name: str, current: str, recommended: str, age_days: int, is_direct: bool) -> UpdateEntry:
    return UpdateEntry(
        package_name=name,
        current_version=current,
        recommended_version=recommended,
        is_direct=is_direct,
        reason=reason_with_age(recommended, age_days),
        constraint_type=ConstraintType.DECLARED,
        is_security=True,
    )


def test_security_entry_rendered_with_cve_tag(monkeypatch):
    plan = make_plan(direct_entries=[make_security_entry("urllib3", "1.26.0", "1.26.19", 90, is_direct=True)])
    output = render(plan, monkeypatch)
    assert "CVE" in output


def test_fresh_security_entry_shows_cooldown_bypass_note(monkeypatch):
    plan = make_plan(
        direct_entries=[make_security_entry("urllib3", "1.26.0", "1.26.19", 2, is_direct=True)],
        cooldown_period=7,
    )
    output = render(plan, monkeypatch)
    assert "cooldown bypassed" in output


def test_mature_security_entry_has_no_bypass_note(monkeypatch):
    plan = make_plan(
        direct_entries=[make_security_entry("urllib3", "1.26.0", "1.26.19", 90, is_direct=True)],
        cooldown_period=7,
    )
    output = render(plan, monkeypatch)
    assert "cooldown bypassed" not in output


def test_non_security_entry_has_no_cve_tag(monkeypatch):
    plan = make_plan(direct_entries=[make_entry("requests", "2.28.0", "2.32.0", 90, is_direct=True)])
    output = render(plan, monkeypatch)
    assert "CVE" not in output
