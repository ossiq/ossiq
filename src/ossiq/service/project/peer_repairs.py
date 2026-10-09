"""Plan how to put peers that sit out of their requirers' reach back where npm resolves them."""

from collections.abc import Sequence
from datetime import datetime
from functools import cmp_to_key

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import ConstraintType
from ossiq.domain.release_cutoff import ReleaseCutoff
from ossiq.domain.version import classify_npm_specifier
from ossiq.service.project.models import PeerRepair, ScanRecord
from ossiq.service.update_impact import MAX_FAMILY_SIZE, PendingBump, TransitiveImpact, resolve_override_bump
from ossiq.solver.version_matchers import version_satisfies_constraint

RANGE_PREFIXES = ("~", "^")
DEFAULT_RANGE_PREFIX = "~"


def plan_peer_repairs(
    direct: Sequence[ScanRecord],
    transitive: Sequence[ScanRecord],
    registry: AbstractPackageRegistryApi,
    *,
    allow_prerelease: bool = False,
    now: datetime | None = None,
    release_cutoff: ReleaseCutoff | None = None,
) -> list[PeerRepair]:
    """One repair per peer that is installed, but only where its requirers cannot load it.

    npm leaves a copy where it is as long as it is valid there, so a peer nested under some other
    package (vue's own @vue/server-renderer, which @vue/test-utils loads unguarded) stays out of
    reach for good. The repair asks for it directly, which places it at the root, and moves the
    stale hoisted copies of its exact-pinned family to its version so the family is one again.

    Args:
        direct: The project's direct records.
        transitive: The transitive records, for the target's family and its copies.
        registry: Registry with the scan's warm cache, for the family's pins.
        allow_prerelease: Whether a family move may land on a prerelease.
        now: Reference time for the projections.
        release_cutoff: The package manager's own limit on release age.

    Returns:
        The repairs, by package name. Empty for a tree with no peer out of reach.
    """
    by_name = {record.package_name: record for record in (*direct, *transitive)}
    dev_names = {record.package_name for record in direct if record.is_optional_dependency}
    kind = registry.package_registry
    repairs: dict[str, PeerRepair] = {}

    for record in (*direct, *transitive):
        for peer in record.unresolved_peers:
            fitting = [v for v in peer.installed_elsewhere if version_satisfies_constraint(v, peer.spec, kind)]
            target = by_name.get(peer.package)
            if not fitting or target is None:
                continue
            is_dev = record.package_name in dev_names or bool(
                record.dependency_path and record.dependency_path[0] in dev_names
            )
            known = repairs.get(peer.package)
            if known is not None:
                repairs[peer.package] = PeerRepair(
                    package=known.package,
                    spec=known.spec,
                    is_dev=known.is_dev and is_dev,
                    requirers=(*known.requirers, record.package_name),
                    family_moves=known.family_moves,
                )
                continue
            version = max(fitting, key=cmp_to_key(registry.compare_versions))
            owners = owners_of(target, version)
            repairs[peer.package] = PeerRepair(
                package=peer.package,
                spec=f"{range_prefix(owners, by_name)}{version}",
                is_dev=is_dev,
                requirers=(record.package_name,),
                family_moves=family_moves(
                    owners, peer.package, by_name, registry, allow_prerelease, now, release_cutoff
                ),
            )
    return sorted(repairs.values(), key=lambda repair: repair.package)


def owners_of(record: ScanRecord, version: str) -> list[tuple[str, str]]:
    """The packages, with their versions, that install *record*'s copy at *version* (peers aside)."""
    copy = next((c for c in record.installed_copies if c.version == version), None)
    if copy is None:
        return []
    return list(dict.fromkeys((edge.requirer_name, edge.requirer_version) for edge in copy.edges if not edge.is_peer))


def range_prefix(owners: list[tuple[str, str]], by_name: dict[str, ScanRecord]) -> str:
    """The range style of the family's owner when the project declares it (vue's `~`), else `~`.

    Tilde, not caret, by default: a lockstep family moves patch by patch together, and a range that
    let the added package run a minor ahead of its owner would split them again.
    """
    for name, _version in owners:
        declared = (by_name[name].version_constraint_declared or "") if name in by_name else ""
        if declared.startswith(RANGE_PREFIXES):
            return declared[:1]
    return DEFAULT_RANGE_PREFIX


def family_moves(
    owners: list[tuple[str, str]],
    driven_by: str,
    by_name: dict[str, ScanRecord],
    registry: AbstractPackageRegistryApi,
    allow_prerelease: bool,
    now: datetime | None,
    release_cutoff: ReleaseCutoff | None,
) -> tuple[TransitiveImpact, ...]:
    """Move each stale copy of the owners' exact-pinned family to the pinned version, where it can go.

    The family is the closure of exact pins from the owners down (vue pins @vue/compiler-dom, which
    pins @vue/shared). Only copies older than the pin move: a repair never takes anything backwards.
    A stale copy whose other users cannot take the pinned version is left alone: the repair still
    puts the peer in reach, the family just stays split around that copy.
    """
    moved_requires: dict[str, dict[str, str]] = {
        name: registry.package_version_requires(name, version) for name, version in owners
    }
    pins: dict[str, str] = {}
    frontier = list(moved_requires.values())
    while frontier and len(moved_requires) < MAX_FAMILY_SIZE:
        for dep, spec in frontier.pop().items():
            if dep in pins or classify_npm_specifier(spec) != ConstraintType.PINNED:
                continue
            pins[dep] = spec
            requires = registry.package_version_requires(dep, spec)
            moved_requires.setdefault(dep, requires)
            frontier.append(requires)

    moves: list[TransitiveImpact] = []
    for dep, pinned in pins.items():
        record = by_name.get(dep)
        if record is None:
            continue
        for copy in record.installed_copies:
            # Only copies the family left behind: a newer one belongs to someone else's newer family.
            if registry.compare_versions(copy.version, pinned) >= 0:
                continue
            impact = resolve_override_bump(
                dep,
                PendingBump(copy, pinned),
                moved_requires,
                driven_by,
                registry,
                allow_prerelease,
                now,
                release_cutoff,
            )
            if impact is not None and not impact.has_conflict:
                moves.append(impact)
    return tuple(moves)
