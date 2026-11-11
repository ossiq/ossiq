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

    queue, _ = build_queue(plan, {"fix-low": 0.1, "fix-high": 0.9}, bump_of({"1.0.1": PATCH, "1.1.0": MINOR}))

    assert names(queue) == [["fix-high"], ["fix-low"], ["zeta"], ["alpha"]]


def test_an_earlier_install_pass_goes_before_everything_else() -> None:
    plan = plan_of([entry("late", is_security=True, install_pass=2), entry("early", install_pass=1)])

    queue, _ = build_queue(plan, {}, bump_of())

    assert names(queue) == [["early"], ["late"]]


def test_a_transitive_copy_a_direct_package_drags_along_rides_in_its_step() -> None:
    direct = entry("app-lib", transitive_impacts=[impact("helper", "1.0.0", "1.2.0")])
    rider = entry("helper", "1.0.0", "1.2.0", direct=False)

    queue, _ = build_queue(plan_of([direct], [rider]), {}, bump_of())

    assert names(queue) == [["app-lib", "helper"]]


def test_a_lockstep_pair_is_one_step() -> None:
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

    queue, _ = build_queue(plan_of([react, dom, entry("other")], pass_orderings=[ordering]), {}, bump_of())

    assert names(queue) == [["other"], ["react", "react-dom"]]


def test_transitive_moves_no_direct_package_drags_share_one_last_step() -> None:
    plan = plan_of([entry("a")], [entry("t1", direct=False), entry("t2", direct=False)])

    queue, _ = build_queue(plan, {}, bump_of())

    assert names(queue) == [["a"], ["t1", "t2"]]


def test_package_keeps_one_step_and_leaves_the_transitive_one_out() -> None:
    plan = plan_of([entry("a"), entry("b")], [entry("t", direct=False)])

    queue, repairs = build_queue(plan, {}, bump_of(), package="b")

    assert names(queue) == [["b"]]
    assert not repairs


def test_package_matches_an_npm_alias_by_either_name() -> None:
    aliased = entry("uuid", dependency_name="uuid-v7")

    assert names(build_queue(plan_of([aliased]), {}, bump_of(), package="uuid-v7")[0]) == [["uuid-v7"]]
    assert names(build_queue(plan_of([aliased]), {}, bump_of(), package="uuid")[0]) == [["uuid-v7"]]


def test_limit_keeps_the_first_steps_and_drops_the_peer_repairs_with_the_rest() -> None:
    repair = PeerRepair(package="peer", spec="^1", is_dev=False, requirers=("a",))
    plan = plan_of([entry("a"), entry("b")], peer_repairs=[repair])

    complete = build_queue(plan, {}, bump_of())
    limited = build_queue(plan, {}, bump_of(), limit=1)

    assert (names(complete[0]), complete[1]) == ([["a"], ["b"]], True)
    assert (names(limited[0]), limited[1]) == ([["a"]], False)


def test_a_step_lists_its_direct_package_first() -> None:
    direct = entry("zz-direct", transitive_impacts=[impact("aa-rider", "1.0.0", "1.2.0")])
    rider = entry("aa-rider", "1.0.0", "1.2.0", direct=False, is_security=True)

    queue, _ = build_queue(plan_of([direct], [rider]), {}, bump_of())

    assert names(queue) == [["zz-direct", "aa-rider"]]
