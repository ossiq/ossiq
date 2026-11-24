from __future__ import annotations

from ossiq.domain.common import ConstraintType, PassOrdering
from ossiq.domain.update_plan import PeerRepair, TransitiveImpact, UpdateEntry, UpdatePlan
from ossiq.service.upgrade.queue import build_queue

PATCH, MINOR, MAJOR = 3, 4, 5


def entry(name: str, current: str = "1.0.0", target: str = "2.0.0", *, direct: bool = True, **kwargs) -> UpdateEntry:
    return UpdateEntry(
        package_name=name,
        current_version=current,
        recommended_version=target,
        is_direct=direct,
        reason=None,
        constraint_type=ConstraintType.DECLARED,
        **kwargs,
    )


def plan_of(direct: list[UpdateEntry], transitive: list[UpdateEntry] | None = None, **kwargs) -> UpdatePlan:
    return UpdatePlan(
        project_name="demo",
        project_path="/p",
        registry_type="NPM",
        package_manager_name="npm",
        direct_entries=direct,
        transitive_entries=transitive or [],
        **kwargs,
    )


def bump_of(sizes: dict[str, int] | None = None):
    sizes = sizes or {}
    return lambda current, target: sizes.get(target, MAJOR)


def queue_of(plan: UpdatePlan, epss=None, sizes=None, parents=None, **kwargs):
    return build_queue(plan, epss or {}, bump_of(sizes), parents or {}, **kwargs)


def names(queue) -> list[list[str]]:
    return [[p.name for p in step] for step in queue]


def impact(name: str, current: str, projected: str) -> TransitiveImpact:
    return TransitiveImpact(
        package_name=name,
        current_version=current,
        projected_version=projected,
        new_constraint="^1",
        driven_by="a",
        has_conflict=False,
    )


def test_a_cve_fix_comes_first_then_the_higher_epss_then_the_smaller_bump_then_the_name() -> None:
    plan = plan_of(
        [
            entry("zeta", target="1.0.1"),
            entry("alpha", target="1.1.0"),
            entry("fix-low", target="2.0.0", is_security=True),
            entry("fix-high", target="2.0.0", is_security=True),
        ]
    )

    queue = queue_of(plan, {"fix-low": 0.1, "fix-high": 0.9}, {"1.0.1": PATCH, "1.1.0": MINOR})

    assert names(queue) == [["fix-high"], ["fix-low"], ["zeta"], ["alpha"]]


def test_an_earlier_install_pass_goes_before_everything_else() -> None:
    plan = plan_of([entry("late", is_security=True, install_pass=2), entry("early", install_pass=1)])

    queue = queue_of(plan)

    assert names(queue) == [["early"], ["late"]]


def test_a_transitive_copy_a_direct_package_drags_along_rides_in_its_step() -> None:
    direct = entry("app-lib", transitive_impacts=[impact("helper", "1.0.0", "1.2.0")])
    rider = entry("helper", "1.0.0", "1.2.0", direct=False)

    queue = queue_of(plan_of([direct], [rider]))

    assert names(queue) == [["app-lib", "helper"]]


def test_a_pair_that_must_install_together_is_one_step() -> None:
    plugin, host = entry("eslint-plugin-oxlint"), entry("oxlint")
    plan = plan_of([plugin, entry("other"), host], install_together=[(plugin.move_key, host.move_key)])

    queue = queue_of(plan)

    assert names(queue) == [["eslint-plugin-oxlint", "oxlint"], ["other"]]


def test_a_peer_cycle_is_one_step() -> None:
    react, dom = entry("react"), entry("react-dom")
    ordering = PassOrdering(
        requirer_key=dom.move_key,
        requirer="react-dom",
        requirer_version="1.0.0",
        peer="react",
        peer_version="2.0.0",
        spec="^1",
        honoured=False,
        peer_key=react.move_key,
    )

    queue = queue_of(plan_of([react, dom, entry("other")], pass_orderings=[ordering]))

    assert names(queue) == [["other"], ["react", "react-dom"]]


def test_transitive_moves_no_direct_package_drags_each_get_a_step_of_their_own() -> None:
    plan = plan_of([entry("a")], [entry("t1", direct=False), entry("t2", direct=False)])

    assert names(queue_of(plan)) == [["a"], ["t1"], ["t2"]]


def test_an_orphan_goes_right_after_its_parent() -> None:
    plan = plan_of([entry("a"), entry("b")], [entry("t", direct=False)])

    assert names(queue_of(plan, parents={"t": "a"})) == [["a"], ["t"], ["b"]]


def test_an_orphan_with_two_parents_goes_after_the_one_that_comes_first() -> None:
    t1, t2 = entry("t1", direct=False), entry("t2", direct=False)
    plan = plan_of([entry("a"), entry("b"), entry("c")], [t1, t2], install_together=[(t1.move_key, t2.move_key)])

    queue = queue_of(plan, parents={"t1": "b", "t2": "a"})

    assert names(queue) == [["a"], ["t1", "t2"], ["b"], ["c"]]


def test_an_orphan_whose_parent_does_not_move_keeps_the_normal_order_with_cve_fixes_first() -> None:
    plan = plan_of([entry("a"), entry("b")], [entry("t", direct=False, is_security=True)])

    assert names(queue_of(plan, parents={"t": "not-moving"})) == [["t"], ["a"], ["b"]]


def test_an_orphan_never_moves_ahead_of_a_step_from_an_earlier_pass() -> None:
    plan = plan_of([entry("a", install_pass=1), entry("c", install_pass=1)], [entry("t", direct=False, install_pass=2)])

    assert names(queue_of(plan, parents={"t": "a"})) == [["a"], ["c"], ["t"]]


def test_a_parent_from_a_later_pass_does_not_pull_an_orphan_back() -> None:
    plan = plan_of([entry("a", install_pass=1), entry("p", install_pass=2)], [entry("t", direct=False, install_pass=1)])

    assert names(queue_of(plan, parents={"t": "p"})) == [["a"], ["t"], ["p"]]


def test_package_keeps_one_step_and_leaves_the_transitive_one_and_the_repairs_out() -> None:
    repair = PeerRepair(package="peer", spec="^1", is_dev=False, requirers=("b",))
    plan = plan_of([entry("a"), entry("b")], [entry("t", direct=False)], peer_repairs=[repair])

    queue = queue_of(plan, parents={"t": "b"}, package="b")

    assert names(queue) == [["b"]]


def test_package_matches_an_npm_alias_by_either_name() -> None:
    aliased = entry("uuid", dependency_name="uuid-v7")

    assert names(queue_of(plan_of([aliased]), package="uuid-v7")) == [["uuid-v7"]]
    assert names(queue_of(plan_of([aliased]), package="uuid")) == [["uuid-v7"]]


def test_limit_keeps_the_first_steps() -> None:
    plan = plan_of([entry("a"), entry("b")], [entry("t", direct=False)])

    assert names(queue_of(plan, parents={"t": "a"}, limit=2)) == [["a"], ["t"]]


def test_a_plan_of_only_peer_repairs_yields_steps() -> None:
    repair = PeerRepair(package="peer", spec="~1.2.0", is_dev=False, requirers=("a",))

    ((step,),) = queue_of(plan_of([], peer_repairs=[repair]))

    assert (step.name, step.current, step.target, step.is_repair, step.is_direct) == ("peer", "", "~1.2.0", True, False)
    assert step.move_key == "peer-repair:peer"


def test_a_repair_goes_right_after_the_step_that_moves_its_requirer() -> None:
    repair = PeerRepair(package="peer", spec="^1", is_dev=False, requirers=("b",))

    queue = queue_of(plan_of([entry("a"), entry("b"), entry("c")], peer_repairs=[repair]))

    assert names(queue) == [["a"], ["b"], ["peer"], ["c"]]


def test_a_repair_whose_requirer_does_not_move_goes_last() -> None:
    repair = PeerRepair(package="peer", spec="^1", is_dev=False, requirers=("not-moving",))

    queue = queue_of(plan_of([entry("a"), entry("b")], peer_repairs=[repair]))

    assert names(queue) == [["a"], ["b"], ["peer"]]


def test_a_repair_carries_its_family_moves_in_its_own_step() -> None:
    repair = PeerRepair(
        package="peer", spec="^1", is_dev=False, requirers=("a",), family_moves=(impact("fam", "1.0.0", "1.2.0"),)
    )
    plan = plan_of([entry("a"), entry("b")], [entry("fam", "1.0.0", "1.2.0", direct=False)], peer_repairs=[repair])

    queue = queue_of(plan)

    assert names(queue) == [["a"], ["peer", "fam"], ["b"]]


def test_a_step_lists_its_direct_package_first() -> None:
    direct = entry("zz-direct", transitive_impacts=[impact("aa-rider", "1.0.0", "1.2.0")])
    rider = entry("aa-rider", "1.0.0", "1.2.0", direct=False, is_security=True)

    queue = queue_of(plan_of([direct], [rider]))

    assert names(queue) == [["zz-direct", "aa-rider"]]


def test_a_step_remembers_a_cve_fix_and_a_move_that_needs_acknowledging() -> None:
    plan = plan_of(
        [
            entry("fix", is_security=True),
            entry("wide", widens_constraint=True),
            entry("broken", carries_known_break=True),
            entry("plain"),
        ]
    )

    flags = {p.name: (p.is_security, p.needs_ack) for step in queue_of(plan) for p in step}

    assert flags == {"fix": (True, False), "wide": (False, True), "broken": (False, True), "plain": (False, False)}
