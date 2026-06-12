"""Tests for service/update.py — build_update_plan()."""

from __future__ import annotations

from ossiq.domain.common import ConstraintType, CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VersionsDifference
from ossiq.service.project import ScanRecord, ScanResult
from ossiq.service.update import build_update_plan
from ossiq.service.update_impact import TransitiveImpact
from ossiq.unit_of_work.solver.reason import RecommendationReason

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
            conflict_detail=None,
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
            conflict_detail="no version satisfies all constraints",
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


class TestSecurityFilter:
    def cve_record(self, name: str, installed: str, recommended: str) -> ScanRecord:
        record = make_record(name, installed, recommended)
        record.cve = [make_cve(name)]
        return record

    def test_direct_cve_entry_kept(self):
        result = make_scan_result(
            production=[
                self.cve_record("urllib3", "1.26.0", "1.26.19"),
                make_record("requests", "2.28.0", "2.32.0"),
            ]
        )
        plan = build_update_plan(result, "uv", security_only=True)
        assert [e.package_name for e in plan.direct_entries] == ["urllib3"]

    def test_transitive_cve_entry_kept(self):
        result = make_scan_result(
            transitive=[
                self.cve_record("certifi", "2022.12.7", "2023.7.22"),
                make_record("idna", "3.3", "3.6"),
            ]
        )
        plan = build_update_plan(result, "uv", security_only=True)
        assert [e.package_name for e in plan.transitive_entries] == ["certifi"]

    def test_empty_plan_when_no_cve_packages(self):
        result = make_scan_result(
            production=[make_record("requests", "2.28.0", "2.32.0")],
            transitive=[make_record("idna", "3.3", "3.6")],
        )
        plan = build_update_plan(result, "uv", security_only=True)
        assert not plan.direct_entries
        assert not plan.transitive_entries
        assert not plan.held_for_cooldown

    def test_held_for_cooldown_empty_under_security(self):
        """Security entries bypass the cooldown hold, so nothing can be held in security-only mode."""
        record = self.cve_record("urllib3", "1.26.0", "1.26.19")
        record.recommended_version_reason = reason_with_age("1.26.19", age_days=1)
        result = make_scan_result(production=[record])
        plan = build_update_plan(result, "uv", cooldown_period=7, security_only=True)
        assert [e.package_name for e in plan.direct_entries] == ["urllib3"]
        assert not plan.held_for_cooldown

    def test_default_keeps_non_cve_entries(self):
        result = make_scan_result(production=[make_record("requests", "2.28.0", "2.32.0")])
        plan = build_update_plan(result, "uv", security_only=False)
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

    def test_forced_survives_security_filter(self):
        result = make_scan_result(production=[make_record("requests", "2.28.0", "2.32.0")])
        plan = build_update_plan(result, "uv", security_only=True, forced_overrides={"requests": "2.30.0"})
        assert [e.package_name for e in plan.direct_entries] == ["requests"]
        assert plan.direct_entries[0].is_forced is True
