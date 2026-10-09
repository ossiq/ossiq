"""Tests for update command and NPM adapter helper methods."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
import typer

from ossiq.commands.plan import (
    CommandPlanOptions,
    check_override_ignore_conflict,
    confirm_acknowledged,
    parse_override_specs,
    warn_uninstallable_override_versions,
)
from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource
from ossiq.domain.release_cutoff import ReleaseCutoff
from ossiq.domain.version import PackageVersion, VersionsDifference
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.service.update import UpdateEntry, UpdatePlan


class TestCommandUpdatePinWiring:
    def test_pin_all_true_passed_to_options(self) -> None:
        options = CommandPlanOptions(project_path="/some/path", pin_all=True)
        assert options.pin_all is True

    def test_pin_all_false_by_default(self) -> None:
        options = CommandPlanOptions(project_path="/some/path")
        assert options.pin_all is False


class TestParseOverrideSpecs:
    def test_simple_spec_parsed(self) -> None:
        assert parse_override_specs(["lodash==4.17.21"]) == (("lodash", "4.17.21"),)

    def test_scoped_npm_name_parsed(self) -> None:
        assert parse_override_specs(["@scope/pkg==1.2.3"]) == (("@scope/pkg", "1.2.3"),)

    def test_none_returns_empty(self) -> None:
        assert parse_override_specs(None) == ()

    def test_missing_separator_rejected(self) -> None:
        with pytest.raises(typer.BadParameter):
            parse_override_specs(["lodash@4.17.21"])

    def test_empty_version_rejected(self) -> None:
        with pytest.raises(typer.BadParameter):
            parse_override_specs(["lodash=="])

    def test_empty_name_rejected(self) -> None:
        with pytest.raises(typer.BadParameter):
            parse_override_specs(["==1.2.3"])

    def test_duplicate_same_version_deduped(self) -> None:
        assert parse_override_specs(["lodash==4.17.21", "lodash==4.17.21"]) == (("lodash", "4.17.21"),)

    def test_duplicate_conflicting_versions_rejected(self) -> None:
        with pytest.raises(typer.BadParameter):
            parse_override_specs(["lodash==4.17.21", "lodash==4.17.20"])

    def test_name_is_canonicalized(self) -> None:
        """--override now normalizes names, as --strategy-override and --ignore already did.
        Without it, `--override Requests==2.32.0` silently matched no record, because
        build_update_plan looks the override up by the record's canonical package_name."""
        assert parse_override_specs(["My_Package==1.0.0"]) == (("my-package", "1.0.0"),)
        assert parse_override_specs(["Requests==2.32.0"]) == (("requests", "2.32.0"),)

    def test_scoped_npm_name_keeps_its_scope(self) -> None:
        assert parse_override_specs(["@Scope/Pkg==1.2.3"]) == (("@scope/pkg", "1.2.3"),)

    def test_duplicates_that_differ_only_in_spelling_are_deduped(self) -> None:
        assert parse_override_specs(["Lodash==4.17.21", "lodash==4.17.21"]) == (("lodash", "4.17.21"),)

    def test_duplicates_that_differ_only_in_spelling_still_detect_a_conflict(self) -> None:
        with pytest.raises(typer.BadParameter):
            parse_override_specs(["Lodash==4.17.21", "lodash==4.17.20"])


class TestCheckOverrideIgnoreConflict:
    def test_disjoint_sets_pass(self) -> None:
        check_override_ignore_conflict((("lodash", "4.17.21"),), ("express",))

    def test_conflicting_package_rejected(self) -> None:
        with pytest.raises(typer.BadParameter):
            check_override_ignore_conflict((("lodash", "4.17.21"),), ("lodash",))

    def test_conflict_detected_across_spellings(self) -> None:
        """Both sides are canonicalized, so an --ignore spelled differently from the --override
        still conflicts — ProjectSources normalizes --ignore anyway."""
        with pytest.raises(typer.BadParameter):
            check_override_ignore_conflict((("my-package", "1.0.0"),), ("My_Package",))


class TestConfirmAcknowledged:
    """The second, apt-style prompt covers two distinct reasons: a pick that rewrites the declared
    range, and a pick whose major line is a known break. The second case used to slip through
    whenever the pick happened to sit inside the declared range."""

    def entry(
        self,
        *,
        widens_constraint: bool = False,
        carries_known_break: bool = False,
        widening_authorized: bool = False,
    ) -> UpdateEntry:
        return UpdateEntry(
            package_name="uuid",
            current_version="11.1.0",
            recommended_version="14.0.2",
            is_direct=True,
            reason=None,
            version_defined=">11.0.0",
            widens_constraint=widens_constraint,
            carries_known_break=carries_known_break,
            widening_authorized=widening_authorized,
        )

    def plan_with(self, *entries: UpdateEntry) -> UpdatePlan:
        return UpdatePlan(
            project_name="proj",
            project_path=".",
            registry_type="NPM",
            package_manager_name="npm",
            direct_entries=list(entries),
            transitive_entries=[],
        )

    def test_nothing_to_acknowledge_needs_no_prompt(self, monkeypatch) -> None:
        monkeypatch.setattr(typer, "confirm", lambda *a, **k: pytest.fail("should not prompt"))

        assert confirm_acknowledged(self.plan_with(self.entry())) is True

    def test_a_known_break_inside_the_declared_range_still_prompts(self, monkeypatch, capsys) -> None:
        """`uuid@>11.0.0` admits ESM-only 14.0.2, so widens_constraint is False - this is exactly
        the pick that used to be written with no second look."""
        monkeypatch.setattr(typer, "confirm", lambda *a, **k: True)
        plan = self.plan_with(self.entry(carries_known_break=True))

        assert confirm_acknowledged(plan) is True
        out = capsys.readouterr().out
        assert "uuid" in out
        assert "known break" in out
        assert "widens" not in out

    def test_a_widening_pick_names_widening(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr(typer, "confirm", lambda *a, **k: True)
        plan = self.plan_with(self.entry(widens_constraint=True))

        assert confirm_acknowledged(plan) is True
        out = capsys.readouterr().out
        assert "widens >11.0.0" in out
        assert "known break" not in out

    def test_an_authorized_widening_still_asks_before_rewriting_the_range(self, monkeypatch, capsys) -> None:
        """A CVE or end-of-life escalation lifts the plan's hold, not this confirmation."""
        monkeypatch.setattr(typer, "confirm", lambda *a, **k: True)
        plan = self.plan_with(self.entry(widens_constraint=True, widening_authorized=True))

        assert confirm_acknowledged(plan) is True
        assert "widens >11.0.0" in capsys.readouterr().out

    def test_both_reasons_are_named_for_one_entry(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr(typer, "confirm", lambda *a, **k: True)
        plan = self.plan_with(self.entry(widens_constraint=True, carries_known_break=True))

        confirm_acknowledged(plan)
        out = capsys.readouterr().out
        assert "widens >11.0.0, known break" in out

    def test_declining_returns_false(self, monkeypatch) -> None:
        monkeypatch.setattr(typer, "confirm", lambda *a, **k: False)

        assert confirm_acknowledged(self.plan_with(self.entry(carries_known_break=True))) is False


class TestWarnUninstallableOverrideVersions:
    """A forced version `apply` cannot install is named before `apply` hits it."""

    CUTOFF = ReleaseCutoff("uv exclude-newer", default=datetime(2026, 9, 18, tzinfo=UTC))

    def sources(self, release_cutoff: ReleaseCutoff | None) -> MagicMock:
        sources = MagicMock()
        sources.release_cutoff = release_cutoff
        sources.packages_registry.package_versions.return_value = [
            PackageVersion(
                version=version,
                license=None,
                package_url=f"https://pypi.org/project/idna/{version}/",
                declared_dependencies={},
                published_date_iso=published,
            )
            for version, published in (("3.7", "2026-04-01T00:00:00Z"), ("3.10", "2026-09-25T00:00:00Z"))
        ]
        return sources

    def scan_result(self) -> ScanResult:
        record = ScanRecord(
            package_name="idna",
            dependency_name="idna",
            is_optional_dependency=False,
            installed_version="3.7",
            latest_version=None,
            versions_diff_index=VersionsDifference("3.7", "3.7", 0, diff_name="LATEST"),
            time_lag_days=None,
            releases_lag=None,
            cve=[],
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
            version_constraint=None,
        )
        return ScanResult(
            project_name="p",
            packages_registry="PYPI",
            project_path="/tmp/p",
            production_packages=[record],
            optional_packages=[],
            transitive_packages=[],
        )

    def test_override_past_the_release_cutoff_is_named(self, capsys) -> None:
        warn_uninstallable_override_versions(self.sources(self.CUTOFF), self.scan_result(), (("idna", "3.10"),))
        assert "published after the uv exclude-newer cutoff" in capsys.readouterr().err

    def test_override_inside_the_release_cutoff_is_quiet(self, capsys) -> None:
        warn_uninstallable_override_versions(self.sources(self.CUTOFF), self.scan_result(), (("idna", "3.7"),))
        assert capsys.readouterr().err == ""

    def test_without_a_release_cutoff_a_recent_override_is_quiet(self, capsys) -> None:
        warn_uninstallable_override_versions(self.sources(None), self.scan_result(), (("idna", "3.10"),))
        assert capsys.readouterr().err == ""

    def test_unknown_version_is_still_named(self, capsys) -> None:
        warn_uninstallable_override_versions(self.sources(self.CUTOFF), self.scan_result(), (("idna", "9.9"),))
        assert "version not found in the registry" in capsys.readouterr().err
