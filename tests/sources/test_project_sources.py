"""Tests for unit_of_work/project_sources.py — ignore_packages normalization."""

from pathlib import Path

import pytest

from ossiq.domain.exceptions import UnknownProjectPackageManager
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
