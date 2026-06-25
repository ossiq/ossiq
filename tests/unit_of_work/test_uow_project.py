"""Tests for unit_of_work/uow_project.py — ignore_packages normalization."""

from unittest.mock import MagicMock

from ossiq.unit_of_work.uow_project import ProjectSources


class TestProjectSourcesIgnorePackages:
    """ignore_packages is normalized to canonical form at construction time."""

    def make_sources(self, ignore_packages: tuple[str, ...]) -> ProjectSources:
        return ProjectSources(
            settings=MagicMock(),
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
