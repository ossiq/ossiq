"""Turn an update plan into the ordered queue of upgrade steps."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence

from ossiq.domain.update_plan import PeerRepair, TransitiveImpact, UpdateEntry, UpdatePlan
from ossiq.sequence.steps import group_steps
from ossiq.service.upgrade.models import StepPackage


def repair_key(repair: PeerRepair) -> str:
    """The move key of a peer repair; it names no entry in the plan, so it needs a key of its own."""
    return f"peer-repair:{repair.package}"


def step_package(entry: UpdateEntry) -> StepPackage:
    return StepPackage(
        move_key=entry.move_key,
        name=entry.identity,
        registry_name=entry.package_name,
        is_direct=entry.is_direct,
        current=entry.current_version,
        target=entry.recommended_version,
        is_security=entry.is_security,
        needs_ack=entry.widens_constraint or entry.carries_known_break,
    )


def repair_package(repair: PeerRepair) -> StepPackage:
    """A repair adds a package, so it has no installed version and its target is a range."""
    return StepPackage(
        move_key=repair_key(repair),
        name=repair.package,
        registry_name=repair.package,
        is_direct=False,  # a range is not a version: keeps it out of the info, context and changelog lookups
        current="",
        target=repair.spec,
        is_repair=True,
    )


def step_packages(plan: UpdatePlan, entries: Iterable[UpdateEntry]) -> dict[str, StepPackage]:
    """Every move of the plan by move key: *entries* in the order given, then the peer repairs."""
    packages = {entry.move_key: step_package(entry) for entry in entries}
    packages.update({repair_key(repair): repair_package(repair) for repair in plan.peer_repairs})
    return packages


def step_of(group: list[str], packages: Mapping[str, StepPackage]) -> tuple[StepPackage, ...]:
    """The group's packages as a step: its direct package first, then a repair, then the rest."""
    return tuple(
        packages[key]
        for key in sorted(group, key=lambda key: (not packages[key].is_direct, not packages[key].is_repair))
    )


def step_links(plan: UpdatePlan) -> list[tuple[str, str]]:
    """Pairs of moves that share a step: a direct package and its riders, and peers that install together.

    A peer repair's family moves ride with the repair the way a direct package's transitive copies do.
    """
    riders = {(e.package_name, e.current_version): e.move_key for e in plan.transitive_entries}
    links = [(o.requirer_key, o.peer_key) for o in plan.pass_orderings if not o.honoured and o.peer_key]
    links += plan.install_together
    carriers: list[tuple[str, Sequence[TransitiveImpact]]] = [
        (direct.move_key, direct.transitive_impacts) for direct in plan.direct_entries
    ]
    carriers += [(repair_key(repair), repair.family_moves) for repair in plan.peer_repairs]
    for key, impacts in carriers:
        for impact in impacts:
            rider = riders.get((impact.package_name, impact.current_version or ""))
            if rider is not None:
                links.append((key, rider))
    return links


def build_queue(
    plan: UpdatePlan,
    epss: Mapping[str, float],
    bump: Callable[[str, str], int],
    parents: Mapping[str, str],
    *,
    package: str | None = None,
    limit: int | None = None,
) -> list[tuple[StepPackage, ...]]:
    """Order the plan's moves into steps; every move lands in one, and a failure costs only its own.

    A direct package gets a step with what has to land beside it. A transitive move no direct package
    drags along gets a step of its own, right after the step of the first direct package it sits
    under. A peer repair gets one too, right after the first step that moves one of its requirers.

    Steps go by install pass, then CVE fixes by EPSS, then smaller bumps first, then by name. A
    transitive step moves up to its parent only within its own install pass, so it never jumps ahead
    of a step from an earlier pass, and a parent from a later pass does not pull it back. A transitive
    step whose parents do not move stays where that order puts it. A repair describes the final
    tree: with no requirer moving, it goes last.

    Args:
        plan: The plan to split.
        epss: EPSS score per package name, for direct packages.
        bump: Size of a move as a version-difference index; a larger index is a larger bump.
        parents: The direct package each transitive package sits under, by package name.
        package: Keep only the step of this direct package.
        limit: Keep only the first this many steps.

    Returns:
        The steps, in the order to run them.
    """

    def order(e: UpdateEntry) -> tuple:
        bump_size = bump(e.current_version, e.recommended_version)
        return (e.install_pass, not e.is_security, -epss.get(e.package_name, 0.0), bump_size, e.identity, e.move_key)

    entries = {e.move_key: e for e in sorted(plan.all_entries, key=order)}
    packages = step_packages(plan, entries.values())
    repairs = {repair_key(repair): repair for repair in plan.peer_repairs}
    ranked = list(enumerate(group_steps(list(packages), step_links(plan))))

    def is_direct(group: list[str]) -> bool:
        return any(packages[key].is_direct for key in group)

    def is_repair(group: list[str]) -> bool:
        return not is_direct(group) and any(key in repairs for key in group)

    def install_pass(group: list[str]) -> int:
        return min(entries[key].install_pass for key in group if key in entries)

    if package is not None:
        wanted = [
            group
            for _, group in ranked
            if any(
                package in (packages[key].registry_name, packages[key].name) for key in group if packages[key].is_direct
            )
        ]
        return [step_of(group, packages) for group in wanted[:limit]]

    anchors: dict[str, tuple[int, int]] = {}
    for rank, group in ranked:
        for key in group:
            if packages[key].is_direct:
                for name in (packages[key].name, packages[key].registry_name):
                    anchors.setdefault(name, (rank, install_pass(group)))

    def position(rank: int, group: list[str]) -> tuple[int, int, int]:
        if is_direct(group):
            return (rank, 0, 0)
        found = [anchors[parent] for key in group if (parent := parents.get(packages[key].registry_name)) in anchors]
        same_pass = [anchor for anchor in found if anchor[1] == install_pass(group)]
        return (min(same_pass)[0], 1, rank) if same_pass else (rank, 0, 0)

    by_position = sorted(
        ((position(rank, group), group) for rank, group in ranked if not is_repair(group)), key=lambda p: p[0]
    )
    steps = [group for _, group in by_position]

    def after(group: list[str]) -> int:
        requirers = {name for key in group if key in repairs for name in repairs[key].requirers}
        moves_one = (
            any(packages[key].registry_name in requirers for key in step if key not in repairs) for step in steps
        )
        return next((index for index, moved in enumerate(moves_one) if moved), len(steps))

    placed = [((index, 0, 0), group) for index, group in enumerate(steps)]
    placed += [((after(group), 1, rank), group) for rank, group in ranked if is_repair(group)]
    placed.sort(key=lambda p: p[0])
    return [step_of(group, packages) for _, group in placed[:limit]]
