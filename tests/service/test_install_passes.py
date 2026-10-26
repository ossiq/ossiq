"""Install passes for an npm plan: which updates must land before others so npm accepts every step."""

from __future__ import annotations

from ossiq.domain.common import ConstraintType, ProjectPackagesRegistry
from ossiq.domain.version import PeerDependency
from ossiq.service.install_passes import assign_install_passes
from ossiq.service.update import UpdateEntry, UpdatePlan


def entry(name: str, current: str, recommended: str) -> UpdateEntry:
    return UpdateEntry(
        package_name=name,
        current_version=current,
        recommended_version=recommended,
        is_direct=True,
        reason=None,
        constraint_type=ConstraintType.DECLARED,
    )


def plan_of(*entries: UpdateEntry) -> UpdatePlan:
    return UpdatePlan(
        project_name="frontend",
        project_path="/tmp/frontend",
        registry_type="NPM",
        package_manager_name="npm",
        direct_entries=list(entries),
        transitive_entries=[],
    )


def peers_of(declared: dict[tuple[str, str], dict[str, str]]):
    """A registry stub: {(package, version): {peer: range}}; anything unlisted declares no peers."""

    def lookup(name: str, version: str) -> dict[str, PeerDependency]:
        return {peer: PeerDependency(spec) for peer, spec in declared.get((name, version), {}).items()}

    return lookup


def assign(plan: UpdatePlan, declared: dict[tuple[str, str], dict[str, str]]) -> UpdatePlan:
    return assign_install_passes(plan, peers_of(declared), ProjectPackagesRegistry.NPM)


def passes(plan: UpdatePlan) -> dict[str, int]:
    return {e.package_name: e.install_pass for e in plan.all_entries}


# vue-router 5.1.0 only takes pinia ^3, 5.4.0 takes ^3 || ^4, and @pinia/nuxt 1.0.3 needs pinia ^4.
PINIA_TRIO = {
    ("vue-router", "5.1.0"): {"pinia": "^3.0.4"},
    ("vue-router", "5.4.0"): {"pinia": "^3.0.4 || ^4.0.2"},
    ("@pinia/nuxt", "0.11.3"): {"pinia": "^3.0.4"},
    ("@pinia/nuxt", "1.0.3"): {"pinia": "^4.1.0"},
}


def pinia_trio() -> UpdatePlan:
    return plan_of(
        entry("pinia", "3.0.4", "4.1.0"),
        entry("@pinia/nuxt", "0.11.3", "1.0.3"),
        entry("vue-router", "5.1.0", "5.4.0"),
    )


def test_the_requirer_whose_old_range_forbids_the_new_peer_installs_first() -> None:
    assert passes(assign(pinia_trio(), PINIA_TRIO)) == {"vue-router": 1, "pinia": 2, "@pinia/nuxt": 2}


def test_the_ordering_names_who_waits_for_whom_and_why() -> None:
    (ordering,) = assign(pinia_trio(), PINIA_TRIO).pass_orderings

    assert (ordering.requirer, ordering.requirer_version) == ("vue-router", "5.1.0")
    assert (ordering.peer, ordering.peer_version, ordering.spec) == ("pinia", "4.1.0", "^3.0.4")
    assert ordering.honoured


def test_pass_count_and_through_pass_are_cumulative() -> None:
    plan = assign(pinia_trio(), PINIA_TRIO)

    assert plan.pass_count == 2
    assert [e.package_name for e in plan.through_pass(1).all_entries] == ["vue-router"]
    assert {e.package_name for e in plan.through_pass(2).all_entries} == {"pinia", "@pinia/nuxt", "vue-router"}


def test_a_plan_without_peer_ranges_between_its_entries_is_returned_as_it_was() -> None:
    plan = plan_of(entry("a", "1.0.0", "2.0.0"), entry("b", "1.0.0", "2.0.0"))

    assert assign(plan, {}) is plan


def test_a_lockstep_pair_shares_a_pass() -> None:
    plan = plan_of(entry("vue", "3.5.43", "3.5.44"), entry("renderer", "3.5.43", "3.5.44"))
    declared = {
        ("renderer", "3.5.43"): {"vue": "3.5.43"},
        ("renderer", "3.5.44"): {"vue": "3.5.44"},
    }

    assert set(passes(assign(plan, declared)).values()) == {1}


def test_a_range_the_installed_pair_already_breaks_does_not_order_anything() -> None:
    plan = plan_of(entry("host", "2.0.0", "2.1.0"), entry("plugin", "1.0.0", "1.1.0"))
    declared = {("plugin", "1.0.0"): {"host": "^1"}, ("plugin", "1.1.0"): {"host": "^2"}}

    assert passes(assign(plan, declared)) == {"host": 1, "plugin": 1}


def test_a_peer_only_one_side_moves_is_not_ordered() -> None:
    plan = plan_of(entry("plugin", "1.0.0", "1.1.0"))

    assert assign(plan, {("plugin", "1.0.0"): {"host": "^1"}}) is plan
