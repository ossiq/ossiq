"""Turn an update plan into the ordered queue of upgrade steps."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from ossiq.domain.update_plan import UpdateEntry, UpdatePlan
from ossiq.sequence.steps import group_steps
from ossiq.service.upgrade.models import StepPackage


def step_package(entry: UpdateEntry) -> StepPackage:
    return StepPackage(
        move_key=entry.move_key,
        name=entry.identity,
        registry_name=entry.package_name,
        is_direct=entry.is_direct,
        current=entry.current_version,
        target=entry.recommended_version,
    )


def step_of(group: list[str], by_key: Mapping[str, UpdateEntry]) -> tuple[StepPackage, ...]:
    """The group's packages as a step, its direct package first."""
    return tuple(step_package(by_key[key]) for key in sorted(group, key=lambda key: not by_key[key].is_direct))


def step_links(plan: UpdatePlan) -> list[tuple[str, str]]:
    """Pairs of moves that share a step: a direct package and its riders, and peers npm cannot separate."""
    riders = {(e.package_name, e.current_version): e.move_key for e in plan.transitive_entries}
    links = [(o.requirer_key, o.peer_key) for o in plan.pass_orderings if not o.honoured and o.peer_key]
    for direct in plan.direct_entries:
        for impact in direct.transitive_impacts:
            rider = riders.get((impact.package_name, impact.current_version or ""))
            if rider is not None:
                links.append((direct.move_key, rider))
    return links


def build_queue(
    plan: UpdatePlan,
    epss: Mapping[str, float],
    bump: Callable[[str, str], int],
    *,
    package: str | None = None,
    limit: int | None = None,
) -> tuple[list[tuple[StepPackage, ...]], bool]:
    """Order the plan's moves into steps: one per direct package, with what has to land beside it.

    Steps go by install pass, then CVE fixes by EPSS, then smaller bumps first, then by name. Transitive
    moves no direct package drags along share one last step.
    shortcut: a plan made of peer repairs alone yields no steps, since a repair names no move.

    Args:
        plan: The plan to split.
        epss: EPSS score per package name, for direct packages.
        bump: Size of a move as a version-difference index; a larger index is a larger bump.
        package: Keep only the step of this direct package.
        limit: Keep only the first this many steps.

    Returns:
        The steps, and whether the plan's peer repairs ride with the last one. They describe the
        final tree, so they go only with a complete queue.
    """

    def order(e: UpdateEntry) -> tuple:
        bump_size = bump(e.current_version, e.recommended_version)
        return (e.install_pass, not e.is_security, -epss.get(e.package_name, 0.0), bump_size, e.identity, e.move_key)

    by_key = {e.move_key: e for e in sorted(plan.all_entries, key=order)}
    steps: list[list[str]] = []
    orphans: list[str] = []
    for group in group_steps(list(by_key), step_links(plan)):
        directs = [by_key[key] for key in group if by_key[key].is_direct]
        if not directs:
            orphans += group
        elif package is None or any(package in (e.package_name, e.identity) for e in directs):
            steps.append(group)
    if orphans and package is None:
        steps.append(orphans)

    complete = package is None and (limit is None or limit >= len(steps))
    queue = [step_of(group, by_key) for group in steps[:limit]]
    return queue, complete and bool(plan.peer_repairs)
