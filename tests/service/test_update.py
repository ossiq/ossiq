"""Tests for service/update.py — build_update_plan()."""

from __future__ import annotations

from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VersionsDifference
from ossiq.service.project import ScanRecord, ScanResult
from ossiq.service.update import build_update_plan
from ossiq.service.update_impact import TransitiveImpact

NO_DIFF = VersionsDifference("1.0.0", "1.0.0", 0, diff_name="LATEST")
CONSTRAINT_SOURCE = ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml")


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

    def test_rewrite_versions_defaults_to_false(self):
        plan = build_update_plan(make_scan_result(), "uv")
        assert plan.rewrite_versions is False

    def test_rewrite_versions_propagated(self):
        plan = build_update_plan(make_scan_result(), "uv", rewrite_versions=True)
        assert plan.rewrite_versions is True

    def test_pinned_entry_excluded_by_default(self):
        result = make_scan_result(production=[make_pinned_record("requests", "2.28.0", "2.31.0")])
        plan = build_update_plan(result, "uv")
        assert not plan.direct_entries

    def test_pinned_entry_included_when_rewrite_versions(self):
        result = make_scan_result(production=[make_pinned_record("requests", "2.28.0", "2.31.0")])
        plan = build_update_plan(result, "uv", rewrite_versions=True)
        assert len(plan.direct_entries) == 1
        assert plan.direct_entries[0].package_name == "requests"

    def test_declared_entry_not_affected_by_rewrite_versions_flag(self):
        result = make_scan_result(production=[make_record("requests", "2.28.0", "2.31.0")])
        plan_without = build_update_plan(result, "uv")
        plan_with = build_update_plan(result, "uv", rewrite_versions=True)
        assert len(plan_without.direct_entries) == 1
        assert len(plan_with.direct_entries) == 1

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
