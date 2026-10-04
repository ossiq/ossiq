"""Tests for RequirementScope — the extras and Python floor a project's requirements are read under."""

from ossiq.domain.requirement_scope import RequirementScope


def test_extras_are_looked_up_by_normalised_package_name() -> None:
    scope = RequirementScope({"django-allauth": frozenset({"socialaccount"})}, python_floor="3.12")

    assert scope.extras_for("Django_Allauth") == frozenset({"socialaccount"})


def test_a_package_with_no_extras_gets_an_empty_set() -> None:
    assert RequirementScope({"django-allauth": frozenset({"socialaccount"})}).extras_for("requests") == frozenset()


def test_the_default_scope_enables_nothing_and_has_no_floor() -> None:
    scope = RequirementScope()

    assert scope.extras_for("anything") == frozenset()
    assert scope.python_floor is None
