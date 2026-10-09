"""Tests for the plan console renderer — convergence notice and held-for-cooldown section."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

from rich.console import Console

from ossiq.domain.common import ConstraintType, OverrideHold, PeerHold, RecommendationRung
from ossiq.service.project.models import PeerRepair
from ossiq.service.update import UpdateEntry, UpdatePlan
from ossiq.service.update_impact import ImpactKind, TransitiveImpact
from ossiq.settings import Settings
from ossiq.solver.reason import RecommendationReason
from ossiq.ui.renderers.plan import console as plan_console
from ossiq.ui.renderers.plan.console import ConsolePlanRenderer


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


def make_entry(
    name: str,
    current: str,
    recommended: str,
    age_days: int,
    is_direct: bool,
    carries_known_break: bool = False,
    dependency_name: str | None = None,
) -> UpdateEntry:
    return UpdateEntry(
        package_name=name,
        dependency_name=dependency_name,
        current_version=current,
        recommended_version=recommended,
        is_direct=is_direct,
        reason=reason_with_age(recommended, age_days),
        constraint_type=ConstraintType.DECLARED,
        carries_known_break=carries_known_break,
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
    held_for_widening: list[UpdateEntry] | None = None,
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
        held_for_widening=held_for_widening or [],
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


def test_package_manager_holds_get_their_own_section(monkeypatch):
    by_uv = dataclasses.replace(
        make_entry("idna", "3.7", "3.10", 3, is_direct=True),
        held_by="uv exclude-newer",
        held_cutoff=datetime(2026, 9, 24, 12, 0, tzinfo=UTC),
    )
    by_cooldown = make_entry("@vue/reactivity", "3.5.35", "3.5.38", 0, is_direct=False)
    plan = make_plan(held_for_cooldown=[by_uv, by_cooldown], cooldown_period=7)

    output = render(plan, monkeypatch)

    cooldown_section, uv_section = output.split("Held by uv exclude-newer")
    assert "@vue/reactivity" in cooldown_section and "idna" not in cooldown_section
    assert "idna" in uv_section and "@vue/reactivity" not in uv_section
    assert "2026-09-24 12:00 UTC" in uv_section


def test_only_package_manager_holds_print_no_cooldown_header(monkeypatch):
    by_uv = dataclasses.replace(
        make_entry("idna", "3.7", "3.10", 3, is_direct=True),
        held_by="uv exclude-newer",
        held_cutoff=datetime(2026, 9, 24, 12, 0, tzinfo=UTC),
    )
    output = render(make_plan(held_for_cooldown=[by_uv], cooldown_period=7), monkeypatch)
    assert "Held by uv exclude-newer" in output
    assert "7-day cooldown" not in output


def test_held_for_widening_section_lists_package_and_declared_range(monkeypatch):
    entry = UpdateEntry(
        package_name="pydantic",
        current_version="1.10.13",
        recommended_version="1.10.26",
        is_direct=True,
        reason=reason_with_age("1.10.26", 200),
        version_defined="==1.10.13",
        constraint_type=ConstraintType.PINNED,
        from_rung=RecommendationRung.IN_MAJOR,
    )
    plan = make_plan(held_for_widening=[entry])
    output = render(plan, monkeypatch)
    assert "constraint widening" in output
    assert "pydantic" in output
    assert "1.10.13" in output
    assert "==1.10.13" in output
    assert "1.10.26" in output
    assert "same major" in output


def test_user_override_holds_get_their_own_section(monkeypatch):
    plan = dataclasses.replace(
        make_plan(),
        held_by_user_overrides=[
            OverrideHold(
                package="@vue/shared",
                value="3.5.42",
                source_file="package.json",
                blocked=("vue@3.5.43", "vue-router@5.0.5"),
            ),
            OverrideHold(package="minimatch", key="^9.0.0", value="9.0.9", blocked=("minimatch@9.0.10",)),
        ],
    )

    output = render(plan, monkeypatch)

    assert "Held by overrides you wrote" in output
    assert "@vue/shared" in output and "3.5.42" in output
    assert "vue@3.5.43, vue-router@5.0.5" in output
    assert "minimatch@^9.0.0" in output


def test_no_user_override_section_without_holds(monkeypatch):
    output = render(make_plan(direct_entries=[make_entry("vue", "3.5.42", "3.5.43", 20, is_direct=True)]), monkeypatch)

    assert "Held by overrides you wrote" not in output


def test_peer_holds_get_their_own_section(monkeypatch):
    plan = dataclasses.replace(
        make_plan(),
        held_by_peers=[
            PeerHold("typescript", "7.0.2", "@typescript-eslint/utils", ">=4.8.4 <6.1.0", others=7),
            PeerHold("vue", "3.5.44", "@vue/server-renderer", "3.5.43"),
        ],
    )

    output = render(plan, monkeypatch)

    assert "Held by peer dependencies" in output
    assert "typescript" in output and "7.0.2" in output
    assert "@typescript-eslint/utils (+7" in output and ">=4.8.4 <6.1.0" in output
    assert "@vue/server-renderer" in output and "(+0 more)" not in output


def test_no_peer_section_without_holds(monkeypatch):
    output = render(make_plan(direct_entries=[make_entry("vue", "3.5.42", "3.5.43", 20, is_direct=True)]), monkeypatch)

    assert "Held by peer dependencies" not in output


def test_peer_repairs_get_their_own_section(monkeypatch):
    move = TransitiveImpact(
        package_name="@vue/shared",
        current_version="3.5.42",
        projected_version="3.5.43",
        new_constraint="3.5.43",
        driven_by="@vue/server-renderer",
        has_conflict=False,
        kind=ImpactKind.OVERRIDE_BUMP,
    )
    plan = dataclasses.replace(
        make_plan(),
        peer_repairs=[PeerRepair("@vue/server-renderer", "~3.5.43", True, ("@vue/test-utils",), (move,))],
    )

    output = render(plan, monkeypatch)

    assert "Repairs unresolved peers" in output
    assert "@vue/server-renderer ~3.5.43" in output
    assert "devDependency" in output and "@vue/test-utils" in output and "1 stale copy" in output


def test_peer_repair_counts_stale_copies_in_the_plural(monkeypatch):
    moves = tuple(
        TransitiveImpact(
            package_name=name,
            current_version="3.5.42",
            projected_version="3.5.43",
            new_constraint="3.5.43",
            driven_by="@vue/server-renderer",
            has_conflict=False,
            kind=ImpactKind.OVERRIDE_BUMP,
        )
        for name in ("@vue/shared", "@vue/compiler-dom")
    )
    plan = dataclasses.replace(
        make_plan(),
        peer_repairs=[PeerRepair("@vue/server-renderer", "~3.5.43", True, ("@vue/test-utils",), moves)],
    )

    assert "2 stale copies" in render(plan, monkeypatch)


def test_a_peer_repair_with_no_family_moves_says_so(monkeypatch):
    plan = dataclasses.replace(make_plan(), peer_repairs=[PeerRepair("host", "~1.2.0", False, ("plugin",))])

    output = render(plan, monkeypatch)

    assert "stale cop" not in output
    assert "dependency" in output and "devDependency" not in output


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


class TestKnownBreakSubRow:
    """A pick whose major line is a known break reached the plan only because every installable
    release was gated and build_candidates' escape hatch admitted the newest anyway. It can sit
    inside the declared range, so it appears as an ordinary row - the sub-row is what says otherwise.
    """

    def test_direct_entry_gets_a_break_sub_row(self, monkeypatch) -> None:
        entry = make_entry("uuid", "13.0.0", "14.0.2", 30, is_direct=True, carries_known_break=True)

        output = render(make_plan(direct_entries=[entry]), monkeypatch)

        assert "known API/module-system break" in output

    def test_transitive_entry_gets_one_too(self, monkeypatch) -> None:
        entry = make_entry("uuid", "13.0.0", "14.0.2", 30, is_direct=False, carries_known_break=True)

        output = render(make_plan(transitive_entries=[entry]), monkeypatch)

        assert "known API/module-system break" in output

    def test_a_clean_entry_gets_no_sub_row(self, monkeypatch) -> None:
        entry = make_entry("lodash", "4.17.20", "4.17.21", 30, is_direct=True)

        output = render(make_plan(direct_entries=[entry]), monkeypatch)

        assert "known API/module-system break" not in output


class TestAliasedPackageNames:
    """Two npm aliases of one package must not render as two identical rows."""

    def test_direct_row_names_the_manifest_key(self, monkeypatch):
        plan = make_plan(
            direct_entries=[
                make_entry("uuid", "13.0.0", "14.0.2", 30, True, dependency_name="uuid-v11"),
            ]
        )

        assert "uuid-v11 (uuid)" in render(plan, monkeypatch)

    def test_widening_row_names_the_manifest_key(self, monkeypatch):
        entry = make_entry("uuid", "7.0.3", "11.1.1", 30, True, dependency_name="uuid-v7")
        plan = make_plan(held_for_widening=[entry])

        assert "uuid-v7 (uuid)" in render(plan, monkeypatch)

    def test_unaliased_row_is_unchanged(self, monkeypatch):
        plan = make_plan(direct_entries=[make_entry("requests", "2.28.0", "2.32.0", 30, True)])
        output = render(plan, monkeypatch)

        assert "requests" in output
        assert "(" not in output.split("requests")[1].split("\n")[0]
