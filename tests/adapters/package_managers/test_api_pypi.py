"""Tests for enrich_registry_constraints — what each parent's PyPI metadata asks of its children."""

from unittest.mock import MagicMock, patch

import pytest

from ossiq.adapters.package_managers.api_pypi import enrich_registry_constraints
from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource, Dependency

FETCH = "ossiq.adapters.package_managers.api_pypi.batch_fetch_requires_dist"


def dep(name: str, version: str, **fields) -> Dependency:
    return Dependency(name=name, canonical_name=name, version_installed=version, **fields)


def registry_of(*nodes: Dependency) -> dict[frozenset, Dependency]:
    return {frozenset((node.name, node.version_installed)): node for node in nodes}


def enrich(registry, requires, **options):
    with patch(FETCH, return_value=requires) as fetch:
        enrich_registry_constraints(registry, MagicMock(), **options)
    return fetch


class TestEveryParentIsRecorded:
    """A lockfile edge carries no specifier, so each parent's metadata is the only source."""

    REQUIRES = {
        ("django-oauth-toolkit", "3.4.1"): ["oauthlib>=3.3.0"],
        ("django-allauth", "65.19.4"): ['oauthlib<4,>=3.3.0; extra == "socialaccount"'],
    }

    @staticmethod
    def graph(parent_order: list[str]):
        oauthlib = dep("oauthlib", "3.3.1")
        toolkit = dep("django-oauth-toolkit", "3.4.1", dependencies={"oauthlib": oauthlib})
        allauth = dep(
            "django-allauth",
            "65.19.4",
            extras=["socialaccount"],
            optional_dependencies={"oauthlib": oauthlib},
        )
        parents = {"django-oauth-toolkit": toolkit, "django-allauth": allauth}
        return oauthlib, registry_of(oauthlib, *(parents[name] for name in parent_order))

    @pytest.mark.parametrize(
        "order", [["django-oauth-toolkit", "django-allauth"], ["django-allauth", "django-oauth-toolkit"]]
    )
    def test_the_child_ends_up_with_both_specifiers_whichever_parent_comes_first(self, order):
        oauthlib, registry = self.graph(order)

        enrich(registry, self.REQUIRES)

        assert sorted(oauthlib.parent_constraints) == ["<4,>=3.3.0", ">=3.3.0"]

    def test_the_first_parent_fills_the_single_declared_constraint(self):
        oauthlib, registry = self.graph(["django-oauth-toolkit", "django-allauth"])

        enrich(registry, self.REQUIRES)

        assert oauthlib.version_defined == ">=3.3.0"

    def test_a_spec_two_parents_share_is_kept_once_per_parent(self):
        # update_impact removes one occurrence when it swaps out the spec a single parent imposed
        child = dep("idna", "3.20")
        parents = [
            dep("requests", "2.34.2", dependencies={"idna": child}),
            dep("httpx", "0.30", dependencies={"idna": child}),
        ]
        requires = {("requests", "2.34.2"): ["idna<4,>=2.5"], ("httpx", "0.30"): ["idna<4,>=2.5"]}

        enrich(registry_of(child, *parents), requires)

        assert child.parent_constraints == ["<4,>=2.5", "<4,>=2.5"]

    def test_a_dependency_already_declared_keeps_its_declared_constraint(self):
        child = dep("oauthlib", "3.3.1", version_defined="~=3.3")
        parent = dep("django-oauth-toolkit", "3.4.1", dependencies={"oauthlib": child})

        enrich(registry_of(child, parent), {("django-oauth-toolkit", "3.4.1"): ["oauthlib>=3.3.0"]})

        assert child.version_defined == "~=3.3"
        assert child.parent_constraints == [">=3.3.0"]

    def test_an_additive_constraint_type_is_never_downgraded(self):
        child = dep(
            "oauthlib", "3.3.1", constraint_info=ConstraintSource(type=ConstraintType.ADDITIVE, source_file="x")
        )
        parent = dep("django-oauth-toolkit", "3.4.1", dependencies={"oauthlib": child})

        enrich(registry_of(child, parent), {("django-oauth-toolkit", "3.4.1"): ["oauthlib>=3.3.0"]})

        assert child.constraint_info.type == ConstraintType.ADDITIVE


class TestExtrasAndMarkers:
    def test_a_requirement_gated_on_an_extra_the_parent_enables_is_recorded(self):
        child = dep("oauthlib", "3.3.1")
        parent = dep("django-allauth", "65.19.4", extras=["socialaccount"], optional_dependencies={"oauthlib": child})

        enrich(registry_of(child, parent), {("django-allauth", "65.19.4"): ['oauthlib<4; extra == "socialaccount"']})

        assert child.version_defined == "<4"

    def test_an_extra_the_parent_does_not_enable_records_nothing(self):
        child = dep("oauthlib", "3.3.1")
        parent = dep("django-allauth", "65.19.4", optional_dependencies={"oauthlib": child})

        enrich(registry_of(child, parent), {("django-allauth", "65.19.4"): ['oauthlib<4; extra == "socialaccount"']})

        assert child.version_defined is None
        assert child.parent_constraints == []

    @pytest.mark.parametrize(("floor", "recorded"), [("3.12", False), ("3.10", True), (None, True)])
    def test_the_python_floor_decides_whether_an_older_python_requirement_counts(self, floor, recorded):
        child = dep("tomli", "2.4.1")
        parent = dep("pylint", "4.0.9", dependencies={"tomli": child})

        enrich(
            registry_of(child, parent),
            {("pylint", "4.0.9"): ['tomli>=1.1; python_version < "3.11"']},
            python_floor=floor,
        )

        assert bool(child.parent_constraints) is recorded


class TestWhatIsFetched:
    def test_the_project_root_is_never_fetched(self):
        # PyPI may hold an unrelated package of the same name as the project
        child = dep("django", "6.0.7")
        root = dep("ossiq-pro", "0.1.5", dependencies={"django": child})
        parent = dep("wagtail", "7.4.2", dependencies={"django": child})

        fetch = enrich(registry_of(child, root, parent), {("wagtail", "7.4.2"): ["django>=5.2"]}, root=root)

        assert fetch.call_args.args[0] == [("wagtail", "7.4.2")]

    def test_nothing_is_fetched_when_no_package_has_children(self):
        fetch = enrich(registry_of(dep("click", "8.5.0")), {})

        fetch.assert_not_called()

    def test_a_failed_fetch_leaves_the_graph_untouched(self):
        child = dep("oauthlib", "3.3.1")
        parent = dep("django-oauth-toolkit", "3.4.1", dependencies={"oauthlib": child})

        enrich(registry_of(child, parent), {})

        assert child.version_defined is None
        assert child.parent_constraints == []

    def test_an_unconstrained_requirement_records_no_constraint(self):
        child = dep("regex", "2026.7.19")
        parent = dep("tiktoken", "0.14.0", dependencies={"regex": child})

        enrich(registry_of(child, parent), {("tiktoken", "0.14.0"): ["regex"]})

        assert child.parent_constraints == []
        assert child.version_defined is None
