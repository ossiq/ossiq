"""Tests for unit_of_work/project_sources.py — ignore_packages normalization."""

import shutil
from datetime import date, timedelta
from pathlib import Path

import pytest

from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.exceptions import InvalidPolicyFile, UnknownProjectPackageManager
from ossiq.domain.policy import Policy
from ossiq.domain.provenance import TrustTier
from ossiq.settings import Settings
from ossiq.sources.project_sources import ProjectSources

PEP621_NO_LOCKFILE_TESTDATA = Path(__file__).parents[2] / "testdata" / "pypi" / "pep621-no-lockfile"


class TestProjectSourcesIgnorePackages:
    """ignore_packages is normalized to canonical form at construction time."""

    def make_sources(self, ignore_packages: tuple[str, ...]) -> ProjectSources:
        # A real Settings, not a mock: the API clients read cutoff_date when they are constructed.
        return ProjectSources(
            settings=Settings(),
            project_path="/tmp/fake",
            ignore_packages=ignore_packages,
        )

    def test_empty_ignore_packages_stays_empty(self):
        sources = self.make_sources(())
        assert sources.ignore_packages == ()

    def test_already_canonical_name_is_unchanged(self):
        sources = self.make_sources(("requests",))
        assert sources.ignore_packages == ("requests",)

    def test_uppercase_name_is_lowercased(self):
        sources = self.make_sources(("Requests",))
        assert sources.ignore_packages == ("requests",)

    def test_underscores_normalized_to_dashes(self):
        sources = self.make_sources(("my_package",))
        assert sources.ignore_packages == ("my-package",)

    def test_mixed_separators_normalized(self):
        sources = self.make_sources(("My_Mixed.Package",))
        assert sources.ignore_packages == ("my-mixed-package",)

    def test_multiple_packages_all_normalized(self):
        sources = self.make_sources(("Sphinx", "requests_toolbelt", "urllib3"))
        assert set(sources.ignore_packages) == {"sphinx", "requests-toolbelt", "urllib3"}


class TestProjectSourcesPep621Detection:
    """A fresh uv init-style project (pyproject.toml with [project].dependencies, no lockfile)
    used to fail with UnknownProjectPackageManager - see PLAN.md item #17 / api_pep621.py."""

    def test_enter_succeeds_instead_of_raising_unknown_package_manager(self):
        sources = ProjectSources(settings=Settings(), project_path=str(PEP621_NO_LOCKFILE_TESTDATA))
        with sources:
            assert sources.packages_manager.package_manager_type.name == "pep621"

    def test_poetry_only_manifest_still_fails_cleanly_naming_inspected_files(self, tmp_path):
        """A Poetry-only pyproject.toml (no [project] table) is explicitly out of scope for the
        PEP 621 adapter and must keep failing - but with a message naming what was inspected,
        not silently miscategorized as PEP 621."""
        (tmp_path / "pyproject.toml").write_text(
            '[tool.poetry]\nname = "demo"\nversion = "0.1.0"\n\n'
            '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "^2.31.0"\n'
        )
        sources = ProjectSources(settings=Settings(), project_path=str(tmp_path))
        with pytest.raises(UnknownProjectPackageManager) as exc_info:
            with sources:
                pass
        hint = exc_info.value.hint
        assert hint is not None
        assert "pyproject.toml" in hint
        assert "requirements.txt" in hint


MIXED_TESTDATA = Path(__file__).parents[2] / "testdata" / "mixed"


class TestProjectSourcesWarnings:
    """Architecture rule 3: lower layers return diagnostics, they never print. __enter__ used to
    call ui.system.show_warning directly, which reached stderr even for the JSON front doors."""

    def test_multiple_registries_collects_a_warning_instead_of_printing(self):
        sources = ProjectSources(settings=Settings(), project_path=str(MIXED_TESTDATA))
        with sources:
            pass

        assert len(sources.warnings) == 1
        assert "multiple registry types" in sources.warnings[0]

    def test_narrowed_registry_is_not_ambiguous(self):
        sources = ProjectSources(
            settings=Settings(),
            project_path=str(MIXED_TESTDATA),
            narrow_package_registry=ProjectPackagesRegistry.PYPI,
        )
        with sources:
            pass

        assert sources.warnings == []

    def test_single_registry_project_warns_about_nothing(self):
        sources = ProjectSources(settings=Settings(), project_path=str(PEP621_NO_LOCKFILE_TESTDATA))
        with sources:
            pass

        assert sources.warnings == []


class TestProjectSourcesPolicyFile:
    """The project's .ossiq.yaml reaches the scan through the sources, and the cooldown keeps its order."""

    @pytest.fixture
    def project(self, tmp_path) -> Path:
        path = tmp_path / "project"
        shutil.copytree(PEP621_NO_LOCKFILE_TESTDATA, path)
        return path

    def write_policy(self, project: Path, body: str) -> None:
        (project / ".ossiq.yaml").write_text(f"version: 1\npolicy:\n{body}", encoding="utf-8")

    def test_without_a_file_there_is_no_policy(self, project):
        sources = ProjectSources(settings=Settings(), project_path=str(project))
        with sources:
            assert sources.policy == Policy()
            assert sources.settings.cooldown_period == Settings().cooldown_period

    def test_the_file_sets_the_policy_and_the_cooldown(self, project):
        self.write_policy(project, "  cooldown:\n    days: 14\n  build:\n    minimum: provenance\n")

        sources = ProjectSources(settings=Settings(), project_path=str(project))
        with sources:
            assert sources.policy.min_build is TrustTier.PROVENANCE
            assert sources.settings.cooldown_period == 14

    def test_a_file_without_a_cooldown_leaves_the_machines_setting(self, project):
        self.write_policy(project, "  build:\n    minimum: provenance\n")

        sources = ProjectSources(settings=Settings(cooldown_period=3), project_path=str(project))
        with sources:
            assert sources.settings.cooldown_period == 3

    def test_a_setting_beats_the_file(self, project):
        self.write_policy(project, "  cooldown:\n    days: 14\n")

        sources = ProjectSources(settings=Settings(cooldown_period=3), project_path=str(project))
        with sources:
            assert sources.settings.cooldown_period == 3

    def test_the_environment_beats_the_file(self, project, monkeypatch):
        self.write_policy(project, "  cooldown:\n    days: 14\n")
        monkeypatch.setenv("OSSIQ_COOLDOWN_PERIOD", "5")

        sources = ProjectSources(settings=Settings(), project_path=str(project))
        with sources:
            assert sources.settings.cooldown_period == 5

    def test_a_flag_beats_the_file_even_when_it_asks_for_zero(self, project):
        self.write_policy(project, "  cooldown:\n    days: 14\n")
        settings = Settings().model_copy(update={"cooldown_period": 0})

        sources = ProjectSources(settings=settings, project_path=str(project))
        with sources:
            assert sources.settings.cooldown_period == 0

    def test_an_expired_exception_is_a_warning_on_the_sources(self, project):
        yesterday = date.today() - timedelta(days=1)
        self.write_policy(
            project, f"  exceptions:\n    - package: left-pad\n      reason: old\n      expires: {yesterday}\n"
        )

        sources = ProjectSources(settings=Settings(), project_path=str(project))
        with sources:
            assert sources.policy.exceptions == ()
            assert "left-pad" in sources.warnings[0]

    def test_a_broken_file_stops_the_scan_before_anything_is_read(self, project):
        self.write_policy(project, "  cooldwn:\n    days: 14\n")

        sources = ProjectSources(settings=Settings(), project_path=str(project))
        with pytest.raises(InvalidPolicyFile), sources:
            pass
