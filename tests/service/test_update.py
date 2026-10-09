"""Tests for service/update.py — build_update_plan()."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

from ossiq.domain.common import (
    ConstraintType,
    CooldownHold,
    CveDatabase,
    OverrideHold,
    PeerHold,
    ProjectPackagesRegistry,
    RecommendationRung,
    RejectedCandidate,
    RejectionDetail,
)
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VersionsDifference
from ossiq.service.project.models import PeerRepair, ScanRecord, ScanResult
from ossiq.service.update import (
    build_update_plan,
    find_override_record,
    override_alias_siblings,
    override_bump_entry,
)
from ossiq.service.update_impact import ImpactKind, TransitiveImpact
from ossiq.solver.reason import RecommendationReason
from ossiq.strategy.overrides import StrategyPlan
from ossiq.strategy.pyramid import UpdateStrategy
from ossiq.strategy.targeting import StrategySelection

NO_DIFF = VersionsDifference("1.0.0", "1.0.0", 0, diff_name="LATEST")
CONSTRAINT_SOURCE = ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml")


def reason_with_age(selected_version: str, age_days: int) -> RecommendationReason:
    return RecommendationReason(
        selected_version=selected_version,
        constraint=None,
        hard_rejections=[],
        soft_rejections=[],
        lower_semver_alternatives=[],
        age_days=age_days,
        is_latest=False,
    )


def selection_with(
    *,
    target_version: str | None = None,
    cooldown_hold: CooldownHold | None = None,
    cooldown_bypassed: bool = False,
    widening_authorized: bool = False,
) -> StrategySelection:
    return StrategySelection(
        strategy=UpdateStrategy.STANDARD,
        target_version=target_version,
        rung=RecommendationRung.IN_RANGE if target_version else None,
        motives=frozenset(),
        requires_widening=False,
        withheld_reason=None,
        available_at=None,
        escalation=None,
        cooldown_hold=cooldown_hold,
        cooldown_bypassed=cooldown_bypassed,
        widening_authorized=widening_authorized,
    )


def make_record(name: str, installed: str, recommended: str | None = None) -> ScanRecord:
    return ScanRecord(
        package_name=name,
        dependency_name=name,
        is_optional_dependency=False,
        installed_version=installed,
        latest_version=None,
        versions_diff_index=NO_DIFF,
        time_lag_days=None,
        releases_lag=None,
        cve=[],
        constraint_info=CONSTRAINT_SOURCE,
        version_constraint=None,
        recommended_version=recommended,
    )


def make_scan_result(
    production: list[ScanRecord] | None = None,
    optional: list[ScanRecord] | None = None,
    transitive: list[ScanRecord] | None = None,
) -> ScanResult:
    return ScanResult(
        project_name="test-project",
        packages_registry="PYPI",
        project_path="/tmp/test",
        production_packages=production or [],
        optional_packages=optional or [],
        transitive_packages=transitive or [],
    )


def make_pinned_record(name: str, installed: str, recommended: str | None = None) -> ScanRecord:
    record = make_record(name, installed, recommended)
    record.constraint_info = ConstraintSource(type=ConstraintType.PINNED, source_file="pyproject.toml")
    return record


class TestBuildUpdatePlan:
    def test_pin_all_defaults_to_false(self):
        plan = build_update_plan(make_scan_result(), "uv")
        assert plan.pin_all is False

    def test_pin_all_propagated(self):
        plan = build_update_plan(make_scan_result(), "uv", pin_all=True)
        assert plan.pin_all is True

    def test_pinned_entry_included(self):
        result = make_scan_result(production=[make_pinned_record("requests", "2.28.0", "2.31.0")])
        plan = build_update_plan(result, "uv")
        assert len(plan.direct_entries) == 1
        assert plan.direct_entries[0].package_name == "requests"

    def test_installed_versions_includes_all_packages(self):
        result = make_scan_result(
            production=[make_record("requests", "2.28.0", "2.32.0")],
            optional=[make_record("pytest", "7.0.0")],
            transitive=[make_record("urllib3", "1.26.18")],
        )
        plan = build_update_plan(result, "uv")
        assert plan.installed_versions == {
            "requests": "2.28.0",
            "pytest": "7.0.0",
            "urllib3": "1.26.18",
        }

    def test_installed_versions_includes_packages_without_recommendations(self):
        result = make_scan_result(production=[make_record("stable-pkg", "1.0.0")])
        plan = build_update_plan(result, "uv")
        assert "stable-pkg" in plan.installed_versions

    def test_direct_entries_from_production_and_optional(self):
        result = make_scan_result(
            production=[make_record("requests", "2.28.0", "2.32.0")],
            optional=[make_record("pytest", "7.0.0", "8.0.0")],
        )
        plan = build_update_plan(result, "uv")
        names = {e.package_name for e in plan.direct_entries}
        assert names == {"requests", "pytest"}

    def test_no_entry_when_recommended_equals_installed(self):
        result = make_scan_result(production=[make_record("unchanged", "1.0.0", "1.0.0")])
        plan = build_update_plan(result, "uv")
        assert not plan.direct_entries

    def test_transitive_deduped_and_sorted(self):
        result = make_scan_result(
            transitive=[
                make_record("zlib", "1.2.0", "1.3.0"),
                make_record("attrs", "21.0.0", "23.0.0"),
                make_record("zlib", "1.2.0", "1.4.0"),  # duplicate, last wins
            ]
        )
        plan = build_update_plan(result, "uv")
        assert [e.package_name for e in plan.transitive_entries] == ["attrs", "zlib"]
        zlib_entry = next(e for e in plan.transitive_entries if e.package_name == "zlib")
        assert zlib_entry.recommended_version == "1.4.0"

    def test_transitive_version_overridden_by_impact(self):
        """Impact projected version beats the transitive solver's recommendation.

        Scenario: wagtail 7.4 requires modelsearch>=1.3,<1.4, but the transitive solver
        (using current-lockfile constraints) recommends modelsearch 1.2.2. The impact's
        projected_version (1.3.1) must win to avoid a uv lock conflict.
        """
        modelsearch_impact = TransitiveImpact(
            package_name="modelsearch",
            current_version="1.1.1",
            projected_version="1.3.1",
            new_constraint=">=1.3,<1.4",
            driven_by="wagtail",
            has_conflict=False,
            conflict=None,
        )
        wagtail = make_record("wagtail", "7.3.1", "7.4")
        wagtail.update_transitive_impacts = [modelsearch_impact]

        modelsearch = make_record("modelsearch", "1.1.1", "1.2.2")

        result = make_scan_result(production=[wagtail], transitive=[modelsearch])
        plan = build_update_plan(result, "uv")

        modelsearch_entry = next(e for e in plan.transitive_entries if e.package_name == "modelsearch")
        assert modelsearch_entry.recommended_version == "1.3.1"

    def test_direct_package_not_in_transitive_when_no_direct_update(self):
        """Direct dep with no pending update must not appear in transitive_entries
        even if the transitive solver recommends a higher version."""
        typer_direct = make_record("typer", "0.24.2")
        typer_transitive = make_record("typer", "0.24.2", "0.25.1")

        result = make_scan_result(production=[typer_direct], transitive=[typer_transitive])
        plan = build_update_plan(result, "uv")

        assert not plan.direct_entries
        assert not plan.transitive_entries

    def test_transitive_impact_with_conflict_not_applied(self):
        """Impact with has_conflict=True must not override the solver's recommendation."""
        conflicting_impact = TransitiveImpact(
            package_name="modelsearch",
            current_version="1.1.1",
            projected_version=None,
            new_constraint=">=1.3,<1.4",
            driven_by="wagtail",
            has_conflict=True,
            conflict=RejectionDetail("no version satisfies", ("all constraints",)),
        )
        wagtail = make_record("wagtail", "7.3.1", "7.4")
        wagtail.update_transitive_impacts = [conflicting_impact]

        modelsearch = make_record("modelsearch", "1.1.1", "1.2.2")

        result = make_scan_result(production=[wagtail], transitive=[modelsearch])
        plan = build_update_plan(result, "uv")

        modelsearch_entry = next(e for e in plan.transitive_entries if e.package_name == "modelsearch")
        assert modelsearch_entry.recommended_version == "1.2.2"


def make_cve(package_name: str) -> CVE:
    return CVE(
        id="CVE-0000-0000",
        cve_ids=("CVE-0000-0000",),
        source=CveDatabase.OSV,
        package_name=package_name,
        package_registry=ProjectPackagesRegistry.PYPI,
        summary="test",
        severity=Severity.HIGH,
        affected_versions=("1.0.0",),
        published=None,
        link="https://example.com",
    )


class TestCooldownHold:
    def fresh_record(self, name: str, installed: str, recommended: str, age_days: int) -> ScanRecord:
        record = make_record(name, installed, recommended)
        record.recommended_version_reason = reason_with_age(recommended, age_days)
        return record

    def test_fresh_transitive_held_back(self):
        result = make_scan_result(transitive=[self.fresh_record("@vue/reactivity", "3.5.35", "3.5.38", age_days=0)])
        plan = build_update_plan(result, "npm", cooldown_period=7)
        assert not plan.transitive_entries
        assert [e.package_name for e in plan.held_for_cooldown] == ["@vue/reactivity"]

    def test_fresh_direct_held_back(self):
        result = make_scan_result(production=[self.fresh_record("requests", "2.28.0", "2.32.0", age_days=2)])
        plan = build_update_plan(result, "uv", cooldown_period=7)
        assert not plan.direct_entries
        assert [e.package_name for e in plan.held_for_cooldown] == ["requests"]

    def test_mature_version_recommended_normally(self):
        result = make_scan_result(transitive=[self.fresh_record("open", "10.2.0", "11.0.0", age_days=208)])
        plan = build_update_plan(result, "npm", cooldown_period=7)
        assert [e.package_name for e in plan.transitive_entries] == ["open"]
        assert not plan.held_for_cooldown

    def test_security_fresh_not_held(self):
        record = self.fresh_record("urllib3", "1.26.0", "1.26.19", age_days=1)
        record.cve = [make_cve("urllib3")]
        result = make_scan_result(production=[record])
        plan = build_update_plan(result, "uv", cooldown_period=7)
        assert [e.package_name for e in plan.direct_entries] == ["urllib3"]
        assert plan.direct_entries[0].is_security is True
        assert not plan.held_for_cooldown

    def test_no_cooldown_when_period_zero(self):
        result = make_scan_result(transitive=[self.fresh_record("@vue/reactivity", "3.5.35", "3.5.38", age_days=0)])
        plan = build_update_plan(result, "npm", cooldown_period=0)
        assert [e.package_name for e in plan.transitive_entries] == ["@vue/reactivity"]
        assert not plan.held_for_cooldown

    def test_missing_reason_not_held(self):
        result = make_scan_result(production=[make_record("requests", "2.28.0", "2.32.0")])
        plan = build_update_plan(result, "uv", cooldown_period=7)
        assert [e.package_name for e in plan.direct_entries] == ["requests"]
        assert not plan.held_for_cooldown


class TestCooldownBlankedRecords:
    """Direct records apply_update_strategy left with no recommendation at all, because every
    reachable release was fresher than the cooldown. They can never become an UpdateEntry, so the
    plan has to name them from the record or drop them silently."""

    def blanked_record(self, name: str, installed: str, held: str, age_days: int) -> ScanRecord:
        record = make_record(name, installed, recommended=None)
        record.strategy_selection = selection_with(
            cooldown_hold=CooldownHold(version=held, age_days=age_days, cooldown_period=7)
        )
        return record

    def test_blanked_record_is_still_listed_as_held(self):
        result = make_scan_result(production=[self.blanked_record("cel", "0.8.0", "0.10.0", age_days=5)])
        plan = build_update_plan(result, "uv", cooldown_period=7)

        assert not plan.direct_entries
        assert [e.package_name for e in plan.held_for_cooldown] == ["cel"]
        entry = plan.held_for_cooldown[0]
        assert entry.recommended_version == "0.10.0"
        assert entry.current_version == "0.8.0"
        assert entry.reason is not None and entry.reason.age_days == 5
        assert entry.held_by is None

    def test_a_package_manager_hold_keeps_its_attribution(self):
        cutoff = datetime(2026, 9, 24, tzinfo=UTC)
        record = make_record("cel", "0.8.0", recommended=None)
        record.strategy_selection = selection_with(
            cooldown_hold=CooldownHold(
                version="0.10.0", age_days=12, cooldown_period=7, enforced_by="uv exclude-newer", cutoff=cutoff
            )
        )
        plan = build_update_plan(make_scan_result(production=[record]), "uv", cooldown_period=7)

        entry = plan.held_for_cooldown[0]
        assert (entry.held_by, entry.held_cutoff) == ("uv exclude-newer", cutoff)

    def test_an_override_on_a_blanked_record_wins_over_the_hold(self):
        result = make_scan_result(production=[self.blanked_record("cel", "0.8.0", "0.10.0", age_days=5)])
        plan = build_update_plan(result, "uv", cooldown_period=7, forced_overrides={"cel": "0.10.0"})

        assert [e.package_name for e in plan.direct_entries] == ["cel"]
        assert not plan.held_for_cooldown

    def test_a_bypassed_entry_is_not_re_held(self):
        # select_target took a fresh release because an end-of-life motive left nothing aged that
        # resolved it. is_security does not cover that case, so without cooldown_bypassed the hold
        # downstream would contradict the recommendation `status` just made.
        record = make_record("abandoned-pkg", "1.0.0", "2.0.0")
        record.recommended_version_reason = reason_with_age("2.0.0", age_days=2)
        record.strategy_selection = selection_with(target_version="2.0.0", cooldown_bypassed=True)
        result = make_scan_result(production=[record])

        plan = build_update_plan(result, "uv", cooldown_period=7)
        assert [e.package_name for e in plan.direct_entries] == ["abandoned-pkg"]
        assert plan.direct_entries[0].cooldown_bypassed is True
        assert not plan.held_for_cooldown


class TestSecurityFilter:
    """Which packages carry a recommendation under `security` is now decided upstream by
    service.project.strategy.apply_update_strategy (see tests/strategy/test_targeting.py and
    tests/service/test_strategy_apply.py) — build_update_plan no longer filters by CVE itself,
    it only decides cooldown/widening holds over whatever recommendation is already present."""

    def cve_record(self, name: str, installed: str, recommended: str) -> ScanRecord:
        record = make_record(name, installed, recommended)
        record.cve = [make_cve(name)]
        return record

    def test_held_for_cooldown_empty_for_security_entry(self):
        """A CVE-carrying entry bypasses the cooldown hold regardless of the run's tier."""
        record = self.cve_record("urllib3", "1.26.0", "1.26.19")
        record.recommended_version_reason = reason_with_age("1.26.19", age_days=1)
        result = make_scan_result(production=[record])
        plan = build_update_plan(result, "uv", cooldown_period=7)
        assert [e.package_name for e in plan.direct_entries] == ["urllib3"]
        assert not plan.held_for_cooldown

    def test_default_keeps_non_cve_entries(self):
        result = make_scan_result(production=[make_record("requests", "2.28.0", "2.32.0")])
        plan = build_update_plan(result, "uv")
        assert [e.package_name for e in plan.direct_entries] == ["requests"]


class TestForcedOverrides:
    def test_forced_replaces_solver_recommendation(self):
        result = make_scan_result(production=[make_record("requests", "2.28.0", "2.32.0")])
        plan = build_update_plan(result, "uv", forced_overrides={"requests": "2.30.0"})
        assert len(plan.direct_entries) == 1
        entry = plan.direct_entries[0]
        assert entry.recommended_version == "2.30.0"
        assert entry.is_forced is True
        assert entry.reason is None

    def test_forced_creates_entry_without_solver_recommendation(self):
        result = make_scan_result(production=[make_record("requests", "2.28.0")])
        plan = build_update_plan(result, "uv", forced_overrides={"requests": "2.30.0"})
        assert [e.package_name for e in plan.direct_entries] == ["requests"]
        assert plan.direct_entries[0].is_forced is True

    def test_forced_transitive_marked_override(self):
        result = make_scan_result(transitive=[make_record("urllib3", "1.26.0")])
        plan = build_update_plan(result, "uv", forced_overrides={"urllib3": "1.26.19"})
        assert [e.package_name for e in plan.transitive_entries] == ["urllib3"]
        entry = plan.transitive_entries[0]
        assert entry.is_forced is True
        assert entry.constraint_type == ConstraintType.OVERRIDE

    def test_unknown_override_collected(self):
        result = make_scan_result(production=[make_record("requests", "2.28.0")])
        plan = build_update_plan(result, "uv", forced_overrides={"no-such-pkg": "1.0.0"})
        assert plan.unknown_override_packages == ("no-such-pkg",)
        assert not plan.direct_entries

    def test_forced_equal_to_installed_skipped(self):
        result = make_scan_result(production=[make_record("requests", "2.28.0", "2.32.0")])
        plan = build_update_plan(result, "uv", forced_overrides={"requests": "2.28.0"})
        assert not plan.direct_entries

    def test_forced_never_held_for_cooldown(self):
        result = make_scan_result(production=[make_record("requests", "2.28.0")])
        plan = build_update_plan(result, "uv", cooldown_period=7, forced_overrides={"requests": "2.32.0"})
        assert [e.package_name for e in plan.direct_entries] == ["requests"]
        assert not plan.held_for_cooldown

    def test_forced_survives_under_security_tier(self):
        result = make_scan_result(production=[make_record("requests", "2.28.0", "2.32.0")])
        plan = build_update_plan(
            result,
            "uv",
            strategy=StrategyPlan(default=UpdateStrategy.SECURITY),
            forced_overrides={"requests": "2.30.0"},
        )
        assert [e.package_name for e in plan.direct_entries] == ["requests"]
        assert plan.direct_entries[0].is_forced is True


class TestVersionDefined:
    """UpdateEntry.version_defined is what api_uv.resolve_direct_specifier rewrites into
    pyproject.toml, so it must be the root manifest's own spec, not the last-writer-wins
    accumulator some transitive parent contributed to.
    """

    def test_reads_the_declaration_over_the_lww_constraint(self):
        record = make_record("pydantic", "2.12.5", "2.13.5")
        record.version_constraint = ">=2.0.0,<3.0.0"
        record.version_constraint_declared = ">=2.0.0"
        plan = build_update_plan(make_scan_result(production=[record]), "uv")
        assert plan.direct_entries[0].version_defined == ">=2.0.0"

    def test_falls_back_to_the_lww_constraint_when_nothing_is_declared(self):
        record = make_record("urllib3", "2.6.3", "2.7.0")
        record.version_constraint = ">=2.0.0"
        plan = build_update_plan(make_scan_result(transitive=[record]), "uv")
        assert plan.transitive_entries[0].version_defined == ">=2.0.0"

    def test_forced_entry_reads_the_declaration_too(self):
        record = make_record("requests", "2.31.0", None)
        record.version_constraint = ">=2.0.0,<3.0.0"
        record.version_constraint_declared = "~=2.31.0"
        plan = build_update_plan(make_scan_result(production=[record]), "uv", forced_overrides={"requests": "2.34.2"})
        assert plan.direct_entries[0].version_defined == "~=2.31.0"


class TestHeldForWidening:
    def rung_record(self, name: str, installed: str, recommended: str, rung: RecommendationRung) -> ScanRecord:
        record = make_record(name, installed, recommended)
        record.version_constraint = f"=={installed}"
        record.recommended_from_rung = rung
        return record

    def test_in_major_rung_held_for_widening(self):
        record = self.rung_record("pydantic", "1.10.13", "1.10.26", RecommendationRung.IN_MAJOR)
        plan = build_update_plan(make_scan_result(production=[record]), "uv")
        assert not plan.direct_entries
        assert [e.package_name for e in plan.held_for_widening] == ["pydantic"]

    def test_latest_rung_held_for_widening(self):
        record = self.rung_record("numpy", "1.26.4", "2.5.3", RecommendationRung.LATEST)
        plan = build_update_plan(make_scan_result(production=[record]), "uv")
        assert not plan.direct_entries
        assert [e.package_name for e in plan.held_for_widening] == ["numpy"]

    def test_in_range_rung_written(self):
        record = self.rung_record("requests", "2.28.0", "2.28.5", RecommendationRung.IN_RANGE)
        plan = build_update_plan(make_scan_result(production=[record]), "uv")
        assert [e.package_name for e in plan.direct_entries] == ["requests"]
        assert not plan.held_for_widening

    def test_solver_rung_written(self):
        record = self.rung_record("requests", "2.28.0", "2.32.0", RecommendationRung.SOLVER)
        plan = build_update_plan(make_scan_result(production=[record]), "uv")
        assert [e.package_name for e in plan.direct_entries] == ["requests"]
        assert not plan.held_for_widening

    def test_transitive_in_major_rung_held_for_widening(self):
        record = self.rung_record("urllib3", "1.26.0", "1.26.19", RecommendationRung.IN_MAJOR)
        plan = build_update_plan(make_scan_result(transitive=[record]), "uv")
        assert not plan.transitive_entries
        assert [e.package_name for e in plan.held_for_widening] == ["urllib3"]

    def test_forced_override_never_held_for_widening(self):
        record = self.rung_record("pydantic", "1.10.13", "1.10.26", RecommendationRung.IN_MAJOR)
        result = make_scan_result(production=[record])
        plan = build_update_plan(result, "uv", forced_overrides={"pydantic": "2.13.5"})
        assert [e.package_name for e in plan.direct_entries] == ["pydantic"]
        assert plan.direct_entries[0].is_forced is True
        assert not plan.held_for_widening

    def test_widening_entry_not_double_held_for_cooldown(self):
        record = self.rung_record("pydantic", "1.10.13", "1.10.26", RecommendationRung.IN_MAJOR)
        record.recommended_version_reason = reason_with_age("1.10.26", age_days=0)
        plan = build_update_plan(make_scan_result(production=[record]), "uv", cooldown_period=7)
        assert [e.package_name for e in plan.held_for_widening] == ["pydantic"]
        assert not plan.held_for_cooldown

    def test_in_major_rung_written_under_latest_tier(self):
        """Picking `latest` IS the authorization to widen — see is_held_for_widening."""
        record = self.rung_record("pydantic", "1.10.13", "1.10.26", RecommendationRung.IN_MAJOR)
        plan = build_update_plan(
            make_scan_result(production=[record]), "uv", strategy=StrategyPlan(default=UpdateStrategy.LATEST)
        )
        assert [e.package_name for e in plan.direct_entries] == ["pydantic"]
        assert plan.direct_entries[0].widens_constraint is True
        assert not plan.held_for_widening

    def test_per_package_override_authorizes_widening(self):
        record = self.rung_record("pydantic", "1.10.13", "1.10.26", RecommendationRung.IN_MAJOR)
        plan = build_update_plan(
            make_scan_result(production=[record]),
            "uv",
            strategy=StrategyPlan(default=UpdateStrategy.STANDARD, overrides={"pydantic": UpdateStrategy.LATEST}),
        )
        assert [e.package_name for e in plan.direct_entries] == ["pydantic"]
        assert not plan.held_for_widening

    def test_fresh_in_range_ladder_pick_still_held_for_cooldown(self):
        record = self.rung_record("requests", "2.28.0", "2.28.5", RecommendationRung.IN_RANGE)
        record.recommended_version_reason = reason_with_age("2.28.5", age_days=0)
        plan = build_update_plan(make_scan_result(production=[record]), "uv", cooldown_period=7)
        assert not plan.direct_entries
        assert [e.package_name for e in plan.held_for_cooldown] == ["requests"]
        assert not plan.held_for_widening

    def test_an_escalated_pick_is_written_not_held(self):
        record = self.rung_record("requests", "2.31.0", "2.32.4", RecommendationRung.IN_MAJOR)
        record.strategy_selection = selection_with(target_version="2.32.4", widening_authorized=True)
        plan = build_update_plan(make_scan_result(production=[record]), "uv")
        assert [e.package_name for e in plan.direct_entries] == ["requests"]
        assert not plan.held_for_widening
        entry = plan.direct_entries[0]
        assert entry.widening_authorized is True
        # apply's own widening confirmation reads this, so authorizing the write must not clear it.
        assert entry.widens_constraint is True

    def test_a_widening_pick_without_the_authorization_stays_held(self):
        record = self.rung_record("requests", "2.31.0", "2.32.4", RecommendationRung.IN_MAJOR)
        record.strategy_selection = selection_with(target_version="2.32.4")
        plan = build_update_plan(make_scan_result(production=[record]), "uv")
        assert not plan.direct_entries
        assert [e.package_name for e in plan.held_for_widening] == ["requests"]


class TestHeldForWideningUnderRewriteVersions:
    """--rewrite-versions exists to move `==x.y.z` pins past the range they declare.

    Holding those picks back for widening authorization made the flag a no-op: every pinned dep
    landed in held_for_widening and `Direct: 0` came out the other end.
    """

    def pinned_record(self, name: str, installed: str, recommended: str) -> ScanRecord:
        record = make_pinned_record(name, installed, recommended)
        record.version_constraint = f"=={installed}"
        record.recommended_from_rung = RecommendationRung.IN_MAJOR
        return record

    def test_pinned_entry_held_without_the_flag(self):
        record = self.pinned_record("black", "25.11.0", "26.5.1")
        plan = build_update_plan(make_scan_result(production=[record]), "uv")
        assert not plan.direct_entries
        assert [e.package_name for e in plan.held_for_widening] == ["black"]

    def test_pinned_entry_written_with_the_flag(self):
        record = self.pinned_record("black", "25.11.0", "26.5.1")
        plan = build_update_plan(make_scan_result(production=[record]), "uv", rewrite_versions=True)
        assert [e.package_name for e in plan.direct_entries] == ["black"]
        assert not plan.held_for_widening
        # Still flagged as widening so command_apply's second confirmation keeps firing.
        assert plan.direct_entries[0].widens_constraint is True

    def test_npm_alias_pin_stays_held_with_the_flag(self):
        # The inner constraint of `npm:pkg@x.y.z` can't be rewritten, so the flag can't
        # authorize it - mirrors clamp_recommendations' own alias carve-out.
        record = make_pinned_record("chalk", "4.1.2", "5.6.2")
        record.version_constraint = "npm:chalk@4.1.2"
        record.version_constraint_declared = "npm:chalk@4.1.2"
        record.recommended_from_rung = RecommendationRung.LATEST
        plan = build_update_plan(make_scan_result(production=[record]), "npm", rewrite_versions=True)
        assert not plan.direct_entries
        assert [e.package_name for e in plan.held_for_widening] == ["chalk"]

    def test_unpinned_out_of_range_entry_stays_held_with_the_flag(self):
        # The flag drops `==` pins only; a declared range is still the user's to widen.
        record = make_record("requests", "2.31.0", "2.34.2")
        record.version_constraint = "~=2.31.0"
        record.recommended_from_rung = RecommendationRung.IN_MAJOR
        plan = build_update_plan(make_scan_result(production=[record]), "uv", rewrite_versions=True)
        assert not plan.direct_entries
        assert [e.package_name for e in plan.held_for_widening] == ["requests"]


def npm_override(value: str, *, ossiq: bool, key: str | None = None) -> ConstraintSource:
    return ConstraintSource(
        type=ConstraintType.OVERRIDE,
        source_file="package.json",
        is_ossiq_authored=ossiq,
        override_key=key,
        override_value=value,
    )


def impact_of(kind: ImpactKind, name: str, current: str, projected: str) -> TransitiveImpact:
    return TransitiveImpact(
        package_name=name,
        current_version=current,
        projected_version=projected,
        new_constraint=projected,
        driven_by="vue",
        has_conflict=False,
        kind=kind,
    )


class TestNestedCopiesInThePlan:
    """What a candidate's impact on an npm tree does to the entries the writers see."""

    def test_a_new_copy_does_not_retarget_the_solvers_pick(self):
        vue = make_record("vue", "3.5.42", "3.5.43")
        vue.update_transitive_impacts = [impact_of(ImpactKind.NEW_COPY, "minimatch", "10.2.5", "11.0.0")]
        minimatch = make_record("minimatch", "10.2.5", "10.2.6")

        plan = build_update_plan(make_scan_result(production=[vue], transitive=[minimatch]), "npm")

        assert [(e.package_name, e.recommended_version) for e in plan.transitive_entries] == [("minimatch", "10.2.6")]

    def test_an_upgrade_still_retargets_the_solvers_pick(self):
        vue = make_record("vue", "3.5.42", "3.5.43")
        vue.update_transitive_impacts = [impact_of(ImpactKind.UPGRADE, "minimatch", "10.2.5", "10.3.0")]
        minimatch = make_record("minimatch", "10.2.5", "10.2.6")

        plan = build_update_plan(make_scan_result(production=[vue], transitive=[minimatch]), "npm")

        assert [(e.package_name, e.recommended_version) for e in plan.transitive_entries] == [("minimatch", "10.3.0")]

    def test_an_override_bump_becomes_a_transitive_entry_without_a_solver_pick(self):
        vue = make_record("vue", "3.5.42", "3.5.43")
        vue.update_transitive_impacts = [impact_of(ImpactKind.OVERRIDE_BUMP, "@vue/shared", "3.5.42", "3.5.43")]
        shared = make_record("@vue/shared", "3.5.42")
        shared.constraint_info = npm_override("3.5.42", ossiq=True)

        plan = build_update_plan(make_scan_result(production=[vue], transitive=[shared]), "npm")

        (entry,) = plan.transitive_entries
        assert (entry.package_name, entry.current_version, entry.recommended_version) == (
            "@vue/shared",
            "3.5.42",
            "3.5.43",
        )
        assert entry.constraint_type == ConstraintType.OVERRIDE
        assert entry.is_direct is False
        assert plan.held_by_user_overrides == []

    def test_a_transitive_pick_on_a_package_the_user_overrode_is_held_and_named(self):
        minimatch = make_record("minimatch", "9.0.9", "9.0.10")
        minimatch.constraint_info = npm_override("9.0.9", ossiq=False, key="^9.0.0")

        plan = build_update_plan(make_scan_result(transitive=[minimatch]), "npm")

        assert plan.transitive_entries == []
        assert [(h.package, h.key, h.value, h.blocked) for h in plan.held_by_user_overrides] == [
            ("minimatch", "^9.0.0", "9.0.9", ("minimatch@9.0.10",))
        ]

    def test_an_override_ossiq_wrote_is_not_a_hold(self):
        minimatch = make_record("minimatch", "9.0.9", "9.0.10")
        minimatch.constraint_info = npm_override("9.0.9", ossiq=True)

        plan = build_update_plan(make_scan_result(transitive=[minimatch]), "npm")

        assert [e.package_name for e in plan.transitive_entries] == ["minimatch"]
        assert plan.held_by_user_overrides == []

    def test_an_override_without_a_value_of_its_own_is_never_held(self):
        """uv overrides carry no value in the scan, so uv plans are unchanged."""
        urllib3 = make_record("urllib3", "1.26.18", "2.2.0")
        urllib3.constraint_info = ConstraintSource(type=ConstraintType.OVERRIDE, source_file="pyproject.toml")

        plan = build_update_plan(make_scan_result(transitive=[urllib3]), "uv")

        assert [e.package_name for e in plan.transitive_entries] == ["urllib3"]
        assert plan.held_by_user_overrides == []

    def test_rejected_candidates_name_the_user_override_that_blocked_them(self):
        vue = make_record("vue", "3.5.42")
        vue.rejected_candidates = [
            RejectedCandidate(
                "3.5.43",
                "@vue/shared is held by an override in package.json",
                held_by_override=OverrideHold(
                    package="@vue/shared", value="3.5.42", source_file="package.json", blocked=("vue@3.5.43",)
                ),
            ),
        ]
        runtime = make_record("vue-router", "5.0.4")
        runtime.rejected_candidates = [
            RejectedCandidate(
                "5.0.5",
                "@vue/shared is held by an override in package.json",
                held_by_override=OverrideHold(
                    package="@vue/shared", value="3.5.42", source_file="package.json", blocked=("vue-router@5.0.5",)
                ),
            ),
        ]

        plan = build_update_plan(make_scan_result(production=[vue, runtime]), "npm")

        (hold,) = plan.held_by_user_overrides
        assert (hold.package, hold.value) == ("@vue/shared", "3.5.42")
        assert hold.blocked == ("vue@3.5.43", "vue-router@5.0.5")

    def test_a_transitive_pick_brings_the_family_moves_it_carries(self):
        ts_eslint = make_record("typescript-eslint", "8.68.0", "8.71.0")
        ts_eslint.update_transitive_impacts = [
            impact_of(ImpactKind.OVERRIDE_BUMP, "@typescript-eslint/parser", "8.68.0", "8.71.0")
        ]
        parser = make_record("@typescript-eslint/parser", "8.68.0")

        plan = build_update_plan(make_scan_result(transitive=[ts_eslint, parser]), "npm")

        assert [(e.package_name, e.current_version, e.recommended_version) for e in plan.transitive_entries] == [
            ("@typescript-eslint/parser", "8.68.0", "8.71.0"),
            ("typescript-eslint", "8.68.0", "8.71.0"),
        ]

    def test_a_split_name_gets_one_entry_per_copy(self):
        """The solver's pick targets the primary copy; the family move targets the stale hoisted one."""
        vue = make_record("vue", "3.5.43", "3.5.44")
        vue.update_transitive_impacts = [impact_of(ImpactKind.OVERRIDE_BUMP, "@vue/shared", "3.5.42", "3.5.44")]
        shared = make_record("@vue/shared", "3.5.43", "3.5.44")

        plan = build_update_plan(make_scan_result(production=[vue], transitive=[shared]), "npm")

        assert [(e.package_name, e.current_version, e.recommended_version) for e in plan.transitive_entries] == [
            ("@vue/shared", "3.5.42", "3.5.44"),
            ("@vue/shared", "3.5.43", "3.5.44"),
        ]


class TestHeldByPeers:
    """A package whose newer release an installed peer range rules out must not just vanish."""

    @staticmethod
    def refused(version: str, requirer: str, spec: str, others: int = 0) -> RejectedCandidate:
        return RejectedCandidate(
            version,
            f"{requirer} peer-requires typescript",
            held_by_peer=PeerHold("typescript", version, requirer, spec, others),
        )

    def test_the_newest_refused_release_stands_for_the_package(self):
        """rejected_candidates run lowest rung first, so the last peer hold is the furthest reach."""
        typescript = make_record("typescript", "6.0.3")
        typescript.rejected_candidates = [
            self.refused("6.1.0", "ts-eslint", "<6.1.0"),
            self.refused("7.0.2", "ts-eslint", "<6.1.0", others=7),
        ]

        plan = build_update_plan(make_scan_result(production=[typescript]), "npm")

        assert plan.held_by_peers == [PeerHold("typescript", "7.0.2", "ts-eslint", "<6.1.0", 7)]

    def test_holds_are_listed_by_package_name(self):
        zod = make_record("zod", "3.0.0")
        zod.rejected_candidates = [
            RejectedCandidate("4.0.0", "x", held_by_peer=PeerHold("zod", "4.0.0", "form-lib", "^3")),
        ]
        typescript = make_record("typescript", "6.0.3")
        typescript.rejected_candidates = [self.refused("7.0.2", "ts-eslint", "<6.1.0")]

        plan = build_update_plan(make_scan_result(production=[zod, typescript]), "npm")

        assert [h.package for h in plan.held_by_peers] == ["typescript", "zod"]

    def test_a_rejection_that_is_not_a_peer_is_not_listed(self):
        vue = make_record("vue", "3.5.42")
        vue.rejected_candidates = [RejectedCandidate("3.5.43", "@vue/shared is held by an override")]

        plan = build_update_plan(make_scan_result(production=[vue]), "npm")

        assert plan.held_by_peers == []


class TestPeerRepairsInThePlan:
    def test_a_repair_carries_into_the_plan_with_its_family_moves_as_override_entries(self):
        move = impact_of(ImpactKind.OVERRIDE_BUMP, "@vue/shared", "3.5.42", "3.5.43")
        repair = PeerRepair("@vue/server-renderer", "~3.5.43", True, ("@vue/test-utils",), (move,))
        result = dataclasses.replace(
            make_scan_result(transitive=[make_record("@vue/shared", "3.5.43")]), peer_repairs=[repair]
        )

        plan = build_update_plan(result, "npm")

        assert plan.peer_repairs == [repair]
        assert [
            (e.package_name, e.current_version, e.recommended_version, e.constraint_type)
            for e in plan.transitive_entries
        ] == [("@vue/shared", "3.5.42", "3.5.43", ConstraintType.OVERRIDE)]


class TestOverrideBumpEntryKey:
    """A family move is keyed to the range from the old copy to the target, not the old copy alone."""

    def test_the_key_spans_old_to_new_so_the_familys_new_edges_match_it(self):
        entry = override_bump_entry(impact_of(ImpactKind.OVERRIDE_BUMP, "@vue/reactivity", "3.5.42", "3.5.43"))

        assert (entry.current_version, entry.recommended_version, entry.override_key) == (
            "3.5.42",
            "3.5.43",
            "3.5.42 - 3.5.43",
        )

    def test_the_range_is_ordered_whichever_way_the_copy_moves(self):
        entry = override_bump_entry(impact_of(ImpactKind.OVERRIDE_BUMP, "x", "2.0.0", "1.9.0"))

        assert entry.override_key == "1.9.0 - 2.0.0"


class TestCarriesKnownBreak:
    """The structural-gate escape hatch: when every installable release is gated, build_candidates
    admits the newest anyway rather than blanking the recommendation. That pick can sit inside the
    declared range - `uuid@>11.0.0` admits ESM-only 14.0.2 - so widens_constraint is False and
    nothing else would ask before writing it.
    """

    def test_a_break_carrying_pick_is_flagged(self) -> None:
        record = make_record("uuid", "11.1.0", recommended="14.0.2")
        record.compatibility.breaking_change = "ESM-only from 12.0.0"

        plan = build_update_plan(make_scan_result(production=[record]), "npm")

        entry = plan.direct_entries[0]
        assert entry.carries_known_break is True
        # In range, so the widening gate would not have caught it - that was the hole.
        assert entry.widens_constraint is False

    def test_it_is_still_applied_not_withheld(self) -> None:
        """The acknowledgement is the gate, so --yes and MCP callers keep working unchanged."""
        record = make_record("uuid", "11.1.0", recommended="14.0.2")
        record.compatibility.breaking_change = "ESM-only from 12.0.0"

        plan = build_update_plan(make_scan_result(production=[record]), "npm")

        assert [e.package_name for e in plan.direct_entries] == ["uuid"]
        assert plan.held_for_widening == []

    def test_a_clean_pick_is_not_flagged(self) -> None:
        record = make_record("lodash", "4.17.20", recommended="4.17.21")

        plan = build_update_plan(make_scan_result(production=[record]), "npm")

        assert plan.direct_entries[0].carries_known_break is False

    def test_an_override_forced_pick_is_never_flagged(self) -> None:
        """--override is explicit user intent, exempt from the acknowledgement prompt for the same
        reason it is exempt from is_held_for_widening."""
        record = make_record("uuid", "11.1.0", recommended="14.0.2")
        record.compatibility.breaking_change = "ESM-only from 12.0.0"

        plan = build_update_plan(
            make_scan_result(production=[record]),
            "npm",
            forced_overrides={"uuid": "14.0.2"},
        )

        entry = plan.direct_entries[0]
        assert entry.is_forced is True
        assert entry.carries_known_break is False

    def test_a_transitive_break_carrying_pick_is_flagged_too(self) -> None:
        record = make_record("uuid", "11.1.0", recommended="14.0.2")
        record.compatibility.breaking_change = "ESM-only from 12.0.0"

        plan = build_update_plan(make_scan_result(transitive=[record]), "npm")

        assert plan.transitive_entries[0].carries_known_break is True


class TestNpmAliasIdentity:
    """Two npm aliases of one package must stay two entries.

    `uuid-v7: "npm:uuid@^7.0.0"` and `uuid-v11: "npm:uuid@>11.0.0"` both carry
    `package_name == "uuid"`, so the widening and cooldown partitions — which subtracted by
    registry name — dropped the sibling of any held entry from the plan entirely. On
    testdata/npm/version-constrained that silently removed uuid 13.0.0 -> ESM-only 14.0.2 from
    both the plan table and the acknowledgement prompt.
    """

    def alias_record(self, alias: str, installed: str, recommended: str) -> ScanRecord:
        record = make_record("uuid", installed, recommended)
        record.dependency_name = alias
        record.version_constraint = f"npm:uuid@^{installed}"
        return record

    def test_holding_one_alias_for_widening_keeps_its_sibling(self):
        held = self.alias_record("uuid-v7", "7.0.3", "11.1.1")
        held.recommended_from_rung = RecommendationRung.LATEST
        kept = self.alias_record("uuid-v11", "13.0.0", "14.0.2")
        kept.recommended_from_rung = RecommendationRung.IN_RANGE

        plan = build_update_plan(make_scan_result(production=[held, kept]), "npm")

        assert [e.identity for e in plan.held_for_widening] == ["uuid-v7"]
        assert [e.identity for e in plan.direct_entries] == ["uuid-v11"]

    def test_holding_one_alias_for_cooldown_keeps_its_sibling(self):
        held = self.alias_record("uuid-v7", "7.0.3", "7.1.0")
        held.recommended_version_reason = reason_with_age("7.1.0", age_days=1)
        kept = self.alias_record("uuid-v11", "13.0.0", "14.0.2")
        kept.recommended_version_reason = reason_with_age("14.0.2", age_days=400)

        plan = build_update_plan(make_scan_result(production=[held, kept]), "npm", cooldown_period=7)

        assert [e.identity for e in plan.held_for_cooldown] == ["uuid-v7"]
        assert [e.identity for e in plan.direct_entries] == ["uuid-v11"]

    def test_override_by_alias_key_resolves_that_alias_only(self):
        first = self.alias_record("uuid-v7", "7.0.3", "7.1.0")
        second = self.alias_record("uuid-v11", "13.0.0", "14.0.2")

        plan = build_update_plan(
            make_scan_result(production=[first, second]),
            "npm",
            forced_overrides={"uuid-v7": "7.5.0"},
        )

        forced = [e for e in plan.direct_entries if e.is_forced]
        assert [(e.identity, e.recommended_version) for e in forced] == [("uuid-v7", "7.5.0")]
        assert [e.recommended_version for e in plan.direct_entries if not e.is_forced] == ["14.0.2"]

    def test_identity_falls_back_to_the_registry_name(self):
        record = make_record("requests", "2.28.0", "2.32.0")
        record.dependency_name = None

        entry = build_update_plan(make_scan_result(production=[record]), "uv").direct_entries[0]

        assert entry.identity == "requests"
        assert entry.display_name == "requests"

    def test_display_name_names_both_spellings_when_aliased(self):
        record = self.alias_record("uuid-v7", "7.0.3", "7.1.0")

        entry = build_update_plan(make_scan_result(production=[record]), "npm").direct_entries[0]

        assert entry.display_name == "uuid-v7 (uuid)"


class TestOverrideTargetResolution:
    """--override has to resolve a user-supplied name the same way everywhere.

    Accepting the alias key in build_update_plan while a sibling validator asked the registry for
    a package literally called `uuid-v11` produced "Unable to load package: uuid-v11" — accepted
    by one half of the command and fatal in the other.
    """

    def scan(self) -> ScanResult:
        first = make_record("uuid", "7.0.3", "11.1.1")
        first.dependency_name = "uuid-v7"
        second = make_record("uuid", "13.0.0", "14.0.2")
        second.dependency_name = "uuid-v11"
        plain = make_record("requests", "2.28.0", "2.32.0")
        return make_scan_result(production=[first, second, plain], transitive=[make_record("urllib3", "1.26.18")])

    def test_an_alias_key_resolves_to_that_alias(self):
        record = find_override_record(self.scan(), "uuid-v11")

        assert record is not None
        assert (record.package_name, record.installed_version) == ("uuid", "13.0.0")

    def test_the_registry_name_resolves_to_a_record_carrying_it(self):
        """Ambiguous by construction — the caller warns; this only has to not crash or invent."""
        record = find_override_record(self.scan(), "uuid")

        assert record is not None
        assert record.package_name == "uuid"

    def test_an_unaliased_direct_dep_resolves_by_its_own_name(self):
        record = find_override_record(self.scan(), "requests")

        assert record is not None and record.package_name == "requests"

    def test_a_transitive_resolves_too(self):
        record = find_override_record(self.scan(), "urllib3")

        assert record is not None and record.package_name == "urllib3"

    def test_an_unknown_name_resolves_to_nothing(self):
        assert find_override_record(self.scan(), "nope") is None

    def test_alias_siblings_are_reported_only_when_there_are_several(self):
        assert override_alias_siblings(self.scan(), "uuid") == ["uuid-v11", "uuid-v7"]
        assert override_alias_siblings(self.scan(), "requests") == []
        assert override_alias_siblings(self.scan(), "nope") == []

    def test_forcing_one_alias_leaves_its_sibling_on_its_own_recommendation(self):
        plan = build_update_plan(self.scan(), "npm", forced_overrides={"uuid-v11": "14.0.2"})

        by_identity = {e.identity: (e.recommended_version, e.is_forced) for e in plan.direct_entries}
        assert by_identity["uuid-v11"] == ("14.0.2", True)
        assert by_identity["uuid-v7"] == ("11.1.1", False)

    def test_forcing_the_registry_name_replaces_every_entry_carrying_it(self):
        plan = build_update_plan(self.scan(), "npm", forced_overrides={"uuid": "14.0.2"})

        uuid_entries = [e for e in plan.direct_entries if e.package_name == "uuid"]
        assert len(uuid_entries) == 1
        assert uuid_entries[0].is_forced is True
