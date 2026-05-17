"""Tests for unit_of_work/uow_project.py — ignore_packages normalization."""

from unittest.mock import MagicMock

from ossiq.unit_of_work.uow_project import ProjectUnitOfWork


class TestProjectUnitOfWorkIgnorePackages:
    """ignore_packages is normalized to canonical form at construction time."""

    def _make_uow(self, ignore_packages: tuple[str, ...]) -> ProjectUnitOfWork:
        return ProjectUnitOfWork(
            settings=MagicMock(),
            project_path="/tmp/fake",
            ignore_packages=ignore_packages,
        )

    def test_empty_ignore_packages_stays_empty(self):
        uow = self._make_uow(())
        assert uow.ignore_packages == ()

    def test_already_canonical_name_is_unchanged(self):
        uow = self._make_uow(("requests",))
        assert uow.ignore_packages == ("requests",)

    def test_uppercase_name_is_lowercased(self):
        uow = self._make_uow(("Requests",))
        assert uow.ignore_packages == ("requests",)

    def test_underscores_normalized_to_dashes(self):
        uow = self._make_uow(("my_package",))
        assert uow.ignore_packages == ("my-package",)

    def test_mixed_separators_normalized(self):
        uow = self._make_uow(("My_Mixed.Package",))
        assert uow.ignore_packages == ("my-mixed-package",)

    def test_multiple_packages_all_normalized(self):
        uow = self._make_uow(("Sphinx", "requests_toolbelt", "urllib3"))
        assert set(uow.ignore_packages) == {"sphinx", "requests-toolbelt", "urllib3"}
