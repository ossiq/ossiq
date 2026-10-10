"""Impact simulation service: projects transitive dependency changes from direct package updates."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import ConstraintType, RejectionDetail
from ossiq.domain.project import ConstraintSource, IncomingEdge, InstalledCopy
from ossiq.domain.release_cutoff import ReleaseCutoff
from ossiq.domain.version import PackageVersion, PeerDependency, classify_npm_specifier
from ossiq.solver.version_matchers import satisfies_all_constraints, version_satisfies_constraint
from ossiq.timeutil import age_days_from_iso, parse_iso_datetime

if TYPE_CHECKING:
    from ossiq.service.project.models import ScanRecord


class ImpactKind(StrEnum):
    """What a candidate's requirement does to the dependency it names."""

    UPGRADE = "upgrade"
    """The installed copy has to move to satisfy it."""
    NEW_DEP = "new_dep"
    """The dependency is not installed at all today."""
    NEW_COPY = "new_copy"
    """npm only: no installed copy satisfies it, so a further copy is installed beside the others."""
    OVERRIDE_BUMP = "override_bump"
    """npm only: a copy that has to move with the candidate, through an override OSS IQ writes or
    rewrites (keyed to that copy), so the tree stays consistent instead of splitting."""
    PEER = "peer"
    """npm only: an installed package peer-requires a range the candidate falls outside of."""


@dataclass(frozen=True)
class TransitiveImpact:
    """Impact on a single transitive dependency caused by a direct package update."""

    package_name: str
    # None means this is a brand-new transitive dep not currently in the tree.
    current_version: str | None
    # None means no version satisfies all merged constraints (hard conflict).
    projected_version: str | None
    # Constraint the updated direct dep imposes on this transitive dep.
    new_constraint: str
    # Canonical name of the direct dep recommendation driving this impact.
    driven_by: str
    # True when projected_version violates an existing parent constraint (multi-parent diamond).
    has_conflict: bool
    # The specs behind the conflict, unjoined. None when there is no conflict to explain.
    conflict: RejectionDetail | None = None
    # Age of the projected version in days at the reference time; None when unknown.
    projected_age_days: int | None = None
    kind: ImpactKind = ImpactKind.UPGRADE
    # The override that forces the dependency to a version the requirement rules out. Set only on a
    # conflict that override causes, so a surface can say whose override it is.
    held_by_override: ConstraintSource | None = None

    @property
    def conflict_detail(self) -> str | None:
        """The conflict as one sentence — derived, so no surface can word it differently.

        A table that cannot afford the whole spec list reads `conflict` and elides it itself;
        see ui.renderers.impact_utils.format_rejection_detail.
        """
        return self.conflict.render() if self.conflict else None


@dataclass(frozen=True)
class DirectUpdateImpact:
    """Aggregated transitive impact of updating a single direct dependency."""

    package_name: str
    recommended_version: str
    transitive_impacts: list[TransitiveImpact]
    # False if any existing transitive dep cannot be resolved without a constraint violation.
    is_actionable: bool
    # Populated by Phase 4c fallback logic when the recommended_version is not actionable.
    fallback_version: str | None


def published_on_or_before(pv: PackageVersion, now: datetime | None) -> bool:
    """True when the version's publish date is unknown or not after the reference time."""
    if now is None or pv.published_date_iso is None:
        return True
    published = parse_iso_datetime(pv.published_date_iso)
    if published is None:
        return True
    return published <= now


def find_best_satisfying_package_version(
    package_name: str,
    constraints: list[str],
    registry: AbstractPackageRegistryApi,
    allow_prerelease: bool = False,
    now: datetime | None = None,
    release_cutoff: ReleaseCutoff | None = None,
) -> PackageVersion | None:
    """Return the newest PackageVersion of package_name satisfying all constraints.

    Uses registry.package_versions() which is cache-warm after the scan pass for packages
    already in the tree — brand-new deps may cost one HTTP fetch each. Skips yanked,
    unpublished, post-cutoff (when now is set), past the package manager's `release_cutoff`, and
    (by default) prerelease versions, matching the hard-filter behaviour of SolvablePool.build().

    Deliberately avoids the SAT solver: we only need hard constraint satisfaction
    (L1 logic), not weighted soft penalties.
    """
    filtered = (
        pv
        for pv in registry.package_versions(package_name)
        if not pv.is_yanked
        and not pv.is_unpublished
        and (allow_prerelease or not pv.is_prerelease)
        and published_on_or_before(pv, now)
        and (release_cutoff is None or release_cutoff.admits(package_name, parse_iso_datetime(pv.published_date_iso)))
        and satisfies_all_constraints(pv.version, constraints, registry.package_registry)
    )
    return registry.newest_version(filtered)


def find_best_satisfying_version(
    package_name: str,
    constraints: list[str],
    registry: AbstractPackageRegistryApi,
    allow_prerelease: bool = False,
    now: datetime | None = None,
    release_cutoff: ReleaseCutoff | None = None,
) -> str | None:
    """Return the newest version string satisfying all constraints, or None."""
    best = find_best_satisfying_package_version(
        package_name, constraints, registry, allow_prerelease, now=now, release_cutoff=release_cutoff
    )
    if best is None:
        return None
    return best.version


def assess_new_dependency(
    dep_name: str,
    new_constraint: str,
    driven_by: str,
    registry: AbstractPackageRegistryApi,
    allow_prerelease: bool = False,
    installed_names: set[str] | None = None,
    now: datetime | None = None,
    release_cutoff: ReleaseCutoff | None = None,
) -> TransitiveImpact | None:
    """Assess a requirement on a package the scan holds no record of.

    Returns None when the package is installed anyway (outside the production-path scan scope, e.g.
    a transitive dep of a dev package). Otherwise returns an informational impact projected at the
    newest version satisfying the requirement, with its age so the plan can flag versions younger
    than the cooldown (the cooldown hold itself does not apply).
    """
    if installed_names and dep_name in installed_names:
        return None
    best = find_best_satisfying_package_version(
        dep_name, [new_constraint], registry, allow_prerelease, now=now, release_cutoff=release_cutoff
    )
    return TransitiveImpact(
        package_name=dep_name,
        current_version=None,
        projected_version=best.version if best else None,
        new_constraint=new_constraint,
        driven_by=driven_by,
        has_conflict=False,
        projected_age_days=age_days_from_iso(best.published_date_iso, now=now) if best else None,
        kind=ImpactKind.NEW_DEP,
    )


def assess_transitive_impact(
    dep_name: str,
    new_constraint: str,
    driven_by: str,
    transitive_by_name: dict[str, ScanRecord],
    registry: AbstractPackageRegistryApi,
    allow_prerelease: bool = False,
    installed_names: set[str] | None = None,
    now: datetime | None = None,
    old_constraint_from_driven_by: str | None = None,
    release_cutoff: ReleaseCutoff | None = None,
) -> TransitiveImpact | None:
    """Assess whether a new constraint on dep_name creates an impact.

    Returns None when the installed version already satisfies the new constraint,
    or when the package is already installed (present in installed_names) but outside
    the production-path scan scope (e.g. a transitive dep of a dev package).
    Returns TransitiveImpact with current_version=None for brand-new transitive deps —
    projected at the newest constraint-satisfying version, with its age so the plan can
    flag versions younger than the cooldown (the cooldown hold itself does not apply).
    Returns TransitiveImpact with has_conflict=True when no version satisfies all constraints.
    """
    record = transitive_by_name.get(dep_name)

    if record is None:
        return assess_new_dependency(
            dep_name, new_constraint, driven_by, registry, allow_prerelease, installed_names, now, release_cutoff
        )

    if version_satisfies_constraint(record.installed_version, new_constraint, registry.package_registry):
        return None

    base_constraints = list(record.all_constraints)
    if old_constraint_from_driven_by and old_constraint_from_driven_by in base_constraints:
        base_constraints.remove(old_constraint_from_driven_by)
    # all_constraints carries one entry per parent, so a widely-shared dep repeats the same spec
    # a dozen times. Duplicates never changed what satisfies_all_constraints accepts; they only
    # ever reached a human, as an unreadable wall of identical specs.
    merged_constraints = list(dict.fromkeys(base_constraints + [new_constraint]))
    best = find_best_satisfying_package_version(
        dep_name, merged_constraints, registry, allow_prerelease, now=now, release_cutoff=release_cutoff
    )

    if best is None:
        return TransitiveImpact(
            package_name=dep_name,
            current_version=record.installed_version,
            projected_version=None,
            new_constraint=new_constraint,
            driven_by=driven_by,
            has_conflict=True,
            conflict=RejectionDetail("no version satisfies", tuple(merged_constraints)),
        )

    projected = best.version
    violating = [
        c for c in base_constraints if not version_satisfies_constraint(projected, c, registry.package_registry)
    ]
    return TransitiveImpact(
        package_name=dep_name,
        current_version=record.installed_version,
        projected_version=projected,
        new_constraint=new_constraint,
        driven_by=driven_by,
        has_conflict=bool(violating),
        conflict=RejectionDetail(f"{projected} violates", tuple(violating)) if violating else None,
        projected_age_days=age_days_from_iso(best.published_date_iso, now=now),
    )


# How many packages the family closure follows before it stops. A candidate that drags in more than
# this has no override verdict worth the registry fetches to find it.
MAX_FAMILY_SIZE = 200


@dataclass(frozen=True)
class PendingBump:
    """A copy that has to move with the candidate, to be re-solved once everything that moves is known.

    Either an override OSS IQ wrote that the candidate's requirement rules out, or a copy the
    candidate would otherwise leave behind (see `copy_to_move`)."""

    copy: InstalledCopy
    spec: str


@dataclass(frozen=True)
class EdgeVerdict:
    """What one requirement of a moved package does under a package manager that nests copies."""

    impact: TransitiveImpact | None = None
    # The version the dependency would move to, which is what its own requirements are read at.
    moves_to: str | None = None
    bump: PendingBump | None = None


def ranges_intersect(first: str, second: str, versions: Iterable[str], registry: AbstractPackageRegistryApi) -> bool:
    """npm's `semver.intersects`, decided over the versions that exist.

    A version is enough to say two ranges overlap, and a published one is what an install would
    pick, so no range algebra is needed.
    """
    kind = registry.package_registry
    return any(
        version_satisfies_constraint(version, first, kind) and version_satisfies_constraint(version, second, kind)
        for version in versions
    )


def known_versions(dep_name: str, copies: list[InstalledCopy], registry: AbstractPackageRegistryApi) -> set[str]:
    """Every version of the package worth testing a range against: the published and the installed."""
    return {pv.version for pv in registry.package_versions(dep_name)} | {copy.version for copy in copies}


def governing_copy(
    dep_name: str,
    copies: list[InstalledCopy],
    spec: str,
    ancestry: set[str],
    registry: AbstractPackageRegistryApi,
) -> InstalledCopy | None:
    """The installed copy whose override rule would apply to a new edge with this spec, or None.

    Follows npm's own matching (arborist `OverrideSet.getEdgeRule`): a rule keyed to a range
    applies to an edge whose range overlaps it, and one scoped under other packages applies only
    beneath them. The package's versions are only looked up once a keyed rule needs them, which
    most requirements never do.
    """
    versions: set[str] | None = None
    for copy in copies:
        info = copy.constraint_info
        if info.type != ConstraintType.OVERRIDE or info.override_value is None:
            continue
        if not all(name in ancestry for name in info.scope_path or ()):
            continue
        if info.override_key is not None:
            versions = versions or known_versions(dep_name, copies, registry)
            if not ranges_intersect(info.override_key, spec, versions, registry):
                continue
        return copy
    return None


def has_override_rules(transitive_by_name: dict[str, ScanRecord]) -> bool:
    """Whether any installed copy in the tree is governed by an override rule."""
    return any(
        copy.constraint_info.type == ConstraintType.OVERRIDE and copy.constraint_info.override_value is not None
        for record in transitive_by_name.values()
        for copy in record.installed_copies
    )


def copy_to_move(copies: Sequence[InstalledCopy], spec: str, requirer: str, movers: set[str]) -> InstalledCopy | None:
    """The copy to move in place instead of nesting a further one beside it, or None to nest.

    npm keeps a locked copy that still satisfies its other users and nests the new one under the
    requirer. Two layouts make that the wrong answer:

    - A lockstep family: the requirer pinned its copy exactly and pins the new version exactly too
      (vue and @vue/shared). Nesting splits the family between stale hoisted copies and new nested
      ones, and whatever resolves the hoisted ones now runs against a mismatched set.
    - A copy left holding only peers: once its owners move, npm prunes it, and the new copy nests out
      of reach of those peers (vue's @vue/server-renderer, which @vue/test-utils optionally peers on).

    Args:
        copies: Every installed copy of the dependency.
        spec: What the requirer now asks of it.
        requirer: The package making the requirement, whose current copy is the one to consider.
        movers: Every package moving with the candidate so far, the candidate included.
    """
    pinned = classify_npm_specifier(spec) == ConstraintType.PINNED
    for copy in copies:
        owned = [edge for edge in copy.edges if not edge.is_peer and edge.requirer_name == requirer]
        if not owned:
            continue
        if pinned and all(classify_npm_specifier(edge.spec) == ConstraintType.PINNED for edge in owned):
            return copy
        owners = {edge.requirer_name for edge in copy.edges if not edge.is_peer}
        if owners <= movers and any(edge.is_peer for edge in copy.edges):
            return copy
    return None


def assess_nested_edge(
    dep_name: str,
    spec: str,
    driven_by: str,
    chain: tuple[str, ...],
    record: ScanRecord | None,
    registry: AbstractPackageRegistryApi,
    allow_prerelease: bool = False,
    installed_names: set[str] | None = None,
    now: datetime | None = None,
    release_cutoff: ReleaseCutoff | None = None,
) -> EdgeVerdict:
    """Assess one requirement of a moved package under a package manager that nests copies.

    When no installed copy satisfies the spec, npm installs one that does and leaves the others be,
    which is the answer here too, except where that splits a lockstep family or strands a copy
    peers rely on (`copy_to_move`): then the copy is asked to move instead. An `overrides` rule forces
    a single version, so it is the other thing this can reject, or (when OSS IQ wrote it) ask to
    have bumped.

    Args:
        dep_name: The dependency the requirement names.
        spec: The range the moved package asks of it.
        driven_by: The direct package whose update this is part of.
        chain: The packages from the candidate down to the one making the requirement.
        record: The scan's record for dep_name; None when it is not in the production scan.
    """
    if record is None:
        impact = assess_new_dependency(
            dep_name, spec, driven_by, registry, allow_prerelease, installed_names, now, release_cutoff
        )
        return EdgeVerdict(impact=impact)

    copies = record.installed_copies or [InstalledCopy(record.installed_version, (), record.constraint_info)]
    ancestry = {*chain, *(record.dependency_path or ())}

    governing = governing_copy(dep_name, copies, spec, ancestry, registry)
    if governing is not None:
        info = governing.constraint_info
        forced = info.override_value or ""
        # A `$name` value follows a root dependency's spec, so it has no version of its own to clash.
        if forced.startswith("$") or ranges_intersect(
            forced, spec, known_versions(dep_name, copies, registry), registry
        ):
            return EdgeVerdict()
        if info.is_ossiq_authored:
            best = find_best_satisfying_package_version(
                dep_name, [spec], registry, allow_prerelease, now=now, release_cutoff=release_cutoff
            )
            return EdgeVerdict(moves_to=best.version if best else None, bump=PendingBump(governing, spec))
        return EdgeVerdict(
            impact=TransitiveImpact(
                package_name=dep_name,
                current_version=governing.version,
                projected_version=None,
                new_constraint=spec,
                driven_by=driven_by,
                has_conflict=True,
                conflict=RejectionDetail(f"forced to {forced}, wanted", (spec,)),
                held_by_override=info,
            )
        )

    if any(version_satisfies_constraint(copy.version, spec, registry.package_registry) for copy in copies):
        return EdgeVerdict()

    best = find_best_satisfying_package_version(
        dep_name, [spec], registry, allow_prerelease, now=now, release_cutoff=release_cutoff
    )
    held = copy_to_move(copies, spec, chain[-1], {*chain, driven_by})
    if held is not None:
        # Re-solved once everything that moves is known (resolve_override_bump): the copy moves in
        # place through a keyed override, or the candidate is refused when its other users can't follow.
        return EdgeVerdict(moves_to=best.version if best else None, bump=PendingBump(held, spec))
    # A further copy is only a conflict when nothing published could be that copy.
    return EdgeVerdict(
        impact=TransitiveImpact(
            package_name=dep_name,
            current_version=record.installed_version,
            projected_version=best.version if best else None,
            new_constraint=spec,
            driven_by=driven_by,
            has_conflict=best is None,
            conflict=None if best else RejectionDetail("no version satisfies", (spec,)),
            projected_age_days=age_days_from_iso(best.published_date_iso, now=now) if best else None,
            kind=ImpactKind.NEW_COPY,
        ),
        moves_to=best.version if best else None,
    )


def resolve_override_bump(
    dep_name: str,
    pending: PendingBump,
    moved_requires: dict[str, dict[str, str]],
    driven_by: str,
    registry: AbstractPackageRegistryApi,
    allow_prerelease: bool = False,
    now: datetime | None = None,
    release_cutoff: ReleaseCutoff | None = None,
) -> TransitiveImpact | None:
    """Re-solve a copy that moves with the candidate, once everything that moves is known.

    The keyed override that moves it covers every edge into the copy. Edges from packages that move
    are swapped for what those packages ask at their new versions; the rest, peer edges included,
    must still hold. Edges the current version already breaches are ignored: an override OSS IQ
    wrote earlier was written to get past them.

    Returns:
        An OVERRIDE_BUMP at the newest version satisfying what remains, a conflict naming the
        requirements when none does, or None when the current version already satisfies them all.
    """
    copy = pending.copy
    constraints = [
        edge.spec
        for edge in copy.edges
        if edge.requirer_name not in moved_requires
        and version_satisfies_constraint(copy.version, edge.spec, registry.package_registry)
    ]
    constraints += [requires[dep_name] for requires in moved_requires.values() if dep_name in requires]
    constraints = list(dict.fromkeys(constraints))

    best = find_best_satisfying_package_version(
        dep_name, constraints, registry, allow_prerelease, now=now, release_cutoff=release_cutoff
    )
    if best is not None and best.version == copy.version:
        return None
    if best is None:
        return TransitiveImpact(
            package_name=dep_name,
            current_version=copy.version,
            projected_version=None,
            new_constraint=pending.spec,
            driven_by=driven_by,
            has_conflict=True,
            conflict=RejectionDetail("no version satisfies", tuple(constraints)),
            kind=ImpactKind.OVERRIDE_BUMP,
        )
    return TransitiveImpact(
        package_name=dep_name,
        current_version=copy.version,
        projected_version=best.version,
        new_constraint=pending.spec,
        driven_by=driven_by,
        has_conflict=False,
        projected_age_days=age_days_from_iso(best.published_date_iso, now=now),
        kind=ImpactKind.OVERRIDE_BUMP,
    )


def simulate_nested(
    package_name: str,
    candidate_version: str,
    transitive_by_name: dict[str, ScanRecord],
    registry: AbstractPackageRegistryApi,
    allow_prerelease: bool = False,
    installed_names: set[str] | None = None,
    now: datetime | None = None,
    release_cutoff: ReleaseCutoff | None = None,
) -> list[TransitiveImpact]:
    """Project what updating a package does to the tree when the package manager nests copies.

    The candidate's own requirements are all reported. Where the tree has override rules, the
    packages that move with it are followed too (vue pins @vue/compiler-dom, which pins
    @vue/shared): only for what an override makes of them, since a further copy of an ordinary
    dependency is not news at that depth. OSS IQ's own overrides are then re-solved against the
    whole family at once, so a family that moves together is not blocked by its old pins.
    """
    candidate_requires = registry.package_version_requires(package_name, candidate_version)
    follow_family = has_override_rules(transitive_by_name)

    moved_requires: dict[str, dict[str, str]] = {package_name: candidate_requires}
    frontier: deque[tuple[dict[str, str], tuple[str, ...]]] = deque([(candidate_requires, (package_name,))])
    bumps: dict[str, PendingBump] = {}
    impacts: list[TransitiveImpact] = []

    while frontier:
        requires, chain = frontier.popleft()
        for dep_name, spec in requires.items():
            verdict = assess_nested_edge(
                dep_name,
                spec,
                package_name,
                chain,
                transitive_by_name.get(dep_name),
                registry,
                allow_prerelease,
                installed_names,
                now,
                release_cutoff,
            )
            if verdict.bump is not None:
                bumps.setdefault(dep_name, verdict.bump)
            impact = verdict.impact
            # Past the candidate's own requirements only a failure is worth reporting: a held
            # override, or a pin on a version nobody published.
            if impact is not None and (len(chain) == 1 or impact.has_conflict):
                impacts.append(impact)
            if (
                (follow_family or verdict.bump is not None)
                and verdict.moves_to is not None
                and dep_name not in moved_requires
                and len(moved_requires) < MAX_FAMILY_SIZE
            ):
                dep_requires = registry.package_version_requires(dep_name, verdict.moves_to)
                moved_requires[dep_name] = dep_requires
                frontier.append((dep_requires, (*chain, dep_name)))

    for dep_name, pending in bumps.items():
        bump = resolve_override_bump(
            dep_name, pending, moved_requires, package_name, registry, allow_prerelease, now, release_cutoff
        )
        if bump is not None:
            impacts.append(bump)
    return impacts


def incoming_peer_edges(copies: Sequence[InstalledCopy], installed_version: str) -> tuple[IncomingEdge, ...]:
    """The peer requirements installed packages place on the copy a bump would replace.

    Only the copy at *installed_version*: a peer binds the instance its requirer resolves, so edges
    onto a nested copy of the same package are untouched when the primary one moves.
    """
    return tuple(edge for copy in copies if copy.version == installed_version for edge in copy.edges if edge.is_peer)


def moves_with_candidate(requirer: ScanRecord, requirer_version: str, movers: set[str]) -> bool:
    """Whether the requirer's copy is replaced when the candidate is, rather than left behind.

    True when every package that asks for that copy is itself moving (the candidate, or something
    it pulls along), so nothing is left holding the old copy in place. A copy nobody is known to ask
    for is not assumed to move: refusing a bump is the safe error, an install that fails is not.
    """
    copy = next((c for c in requirer.installed_copies if c.version == requirer_version), None)
    if copy is None:
        return False
    owners = {edge.requirer_name for edge in copy.edges if not edge.is_peer}
    return bool(owners) and owners <= movers


def assess_incoming_peers(
    package_name: str,
    candidate_version: str,
    incoming_peers: Sequence[IncomingEdge],
    moved: Mapping[str, str],
    transitive_by_name: dict[str, ScanRecord],
    registry: AbstractPackageRegistryApi,
    installed_version: str | None,
    bumped: Mapping[tuple[str, str], str] | None = None,
) -> list[TransitiveImpact]:
    """Report each installed package whose peer range the candidate would fall outside of.

    A peer, unlike an ordinary dependency, is satisfied by the one instance the requirer resolves,
    so npm cannot nest its way around it. Three things keep this from refusing a bump it should
    allow:

    - A requirer that moves with the candidate (vue pins @vue/server-renderer to its own version)
      is judged at the version it moves to, and its peers at that version. Its copy moves when an
      override moves it in place (`bumped`), or when nothing but movers asks for it.
    - A range the installed version already violates is existing drift, not a consequence of this
      bump, so it does not gate the candidate.
    - A requirer outside `transitive_by_name` is a direct dependency, whose joint move with the
      candidate is the solver's to decide, not a single-candidate simulation's.

    Args:
        package_name: The package being bumped.
        candidate_version: The version it would move to.
        incoming_peers: The peer edges onto its installed copy (see `incoming_peer_edges`).
        moved: {package: projected version} for what the candidate's own requirements pull along.
        transitive_by_name: The scan's transitive records, for the requirers' copies and edges.
        registry: Registry, for each moved requirer's peers at its new version.
        installed_version: The version being replaced, to tell existing drift from new breakage.
        bumped: {(package, copy version): new version} for the copies an override moves in place.

    Returns:
        One conflicting impact per requirer, carrying every range of it the candidate falls outside.
    """
    kind = registry.package_registry
    movers = {package_name, *moved}
    violated: dict[str, tuple[str, list[str]]] = {}
    for edge in incoming_peers:
        requirer = transitive_by_name.get(edge.requirer_name)
        if requirer is None or edge.requirer_name == package_name:
            continue
        spec = edge.spec
        if version_satisfies_constraint(candidate_version, spec, kind):
            continue
        if installed_version and not version_satisfies_constraint(installed_version, spec, kind):
            continue
        new_version = (bumped or {}).get((edge.requirer_name, edge.requirer_version))
        if (
            new_version is None
            and edge.requirer_name in moved
            and moves_with_candidate(requirer, edge.requirer_version, movers)
        ):
            new_version = moved[edge.requirer_name]
        if new_version is not None:
            new_peer = registry.package_version_peers(edge.requirer_name, new_version).get(package_name)
            if new_peer is None or version_satisfies_constraint(candidate_version, new_peer.spec, kind):
                continue
            spec = new_peer.spec
        specs = violated.setdefault(edge.requirer_name, (edge.requirer_version, []))[1]
        if spec not in specs:
            specs.append(spec)

    return [
        TransitiveImpact(
            package_name=requirer_name,
            current_version=requirer_version,
            projected_version=None,
            new_constraint=specs[0],
            driven_by=package_name,
            has_conflict=True,
            conflict=RejectionDetail(f"{candidate_version} violates", tuple(specs)),
            kind=ImpactKind.PEER,
        )
        for requirer_name, (requirer_version, specs) in violated.items()
    ]


MAX_PEER_DEPTH = 4


@dataclass(frozen=True)
class PeerSetWalk:
    """The context `assess_candidate_peers` walks a candidate's peer set in."""

    driven_by: str
    transitive_by_name: dict[str, ScanRecord]
    registry: AbstractPackageRegistryApi
    allow_prerelease: bool
    installed_names: set[str]
    now: datetime | None
    release_cutoff: ReleaseCutoff | None
    direct_versions: Mapping[str, str]

    def satisfies(self, version: str, spec: str) -> bool:
        return version_satisfies_constraint(version, spec, self.registry.package_registry)

    def peers_of(
        self,
        requirer: str,
        version: str,
        previous: Mapping[str, PeerDependency],
        depth: int,
        planned: dict[str, str],
    ) -> list[TransitiveImpact]:
        """Impacts of the peers *requirer* declares at *version*; see `assess_candidate_peers`.

        *planned* holds what this walk already installs or moves ({name: version}, the candidate
        included): a peer on one of those is judged against that version, not added again.
        """
        impacts: list[TransitiveImpact] = []
        for dep_name, peer in self.registry.package_version_peers(requirer, version).items():
            if dep_name == requirer:
                continue
            spec = peer.spec or "*"
            if dep_name in planned:
                if not self.satisfies(planned[dep_name], spec):
                    impacts.append(self.conflict(dep_name, None, spec, f"{planned[dep_name]} violates"))
                continue
            record = self.transitive_by_name.get(dep_name)
            held = self.direct_versions.get(dep_name)
            if held is not None:
                current = held
            elif record is not None:
                current = record.installed_version
            else:
                if not peer.optional and dep_name not in self.installed_names:
                    impacts.extend(self.newly_installed(dep_name, spec, depth, planned))
                continue
            if self.satisfies(current, spec):
                continue
            earlier = previous.get(dep_name)
            if earlier is not None and not self.satisfies(current, earlier.spec or "*"):
                continue
            if record is None:
                if depth > 0:
                    impacts.append(self.conflict(dep_name, current, spec, f"held at {current}, wanted"))
                continue
            impacts.append(self.move_copy(dep_name, record, requirer, spec))
        return impacts

    def newly_installed(self, dep_name: str, spec: str, depth: int, planned: dict[str, str]) -> list[TransitiveImpact]:
        """A required peer nothing installed satisfies: npm installs the newest that does, peers and all."""
        best = find_best_satisfying_package_version(
            dep_name, [spec], self.registry, self.allow_prerelease, now=self.now, release_cutoff=self.release_cutoff
        )
        if best is None:
            return [self.conflict(dep_name, None, spec, "no version satisfies")]
        impacts = [
            TransitiveImpact(
                package_name=dep_name,
                current_version=None,
                projected_version=best.version,
                new_constraint=spec,
                driven_by=self.driven_by,
                has_conflict=False,
                projected_age_days=age_days_from_iso(best.published_date_iso, now=self.now),
                kind=ImpactKind.NEW_DEP,
            )
        ]
        planned[dep_name] = best.version
        if depth + 1 < MAX_PEER_DEPTH:
            impacts += self.peers_of(dep_name, best.version, {}, depth + 1, planned)
        return impacts

    def move_copy(self, dep_name: str, record: ScanRecord, requirer: str, spec: str) -> TransitiveImpact:
        """The copy *requirer* resolves has to move to a version its peer range accepts."""
        copies = record.installed_copies or [InstalledCopy(record.installed_version, (), record.constraint_info)]
        copy = next(
            (c for c in copies if any(edge.requirer_name == requirer for edge in c.edges)),
            next((c for c in copies if c.version == record.installed_version), copies[0]),
        )
        info = copy.constraint_info
        if info.is_user_override and info.override_value is not None:
            return replace(
                self.conflict(dep_name, copy.version, spec, f"forced to {info.override_value}, wanted"),
                held_by_override=info,
            )
        constraints = list(
            dict.fromkeys(
                [spec, *(edge.spec for edge in copy.edges if edge.spec and self.satisfies(copy.version, edge.spec))]
            )
        )
        best = find_best_satisfying_package_version(
            dep_name,
            constraints,
            self.registry,
            self.allow_prerelease,
            now=self.now,
            release_cutoff=self.release_cutoff,
        )
        if best is None:
            return self.conflict(dep_name, copy.version, spec, "no version satisfies", tuple(constraints))
        return TransitiveImpact(
            package_name=dep_name,
            current_version=copy.version,
            projected_version=best.version,
            new_constraint=spec,
            driven_by=self.driven_by,
            has_conflict=False,
            projected_age_days=age_days_from_iso(best.published_date_iso, now=self.now),
            kind=ImpactKind.OVERRIDE_BUMP,
        )

    def conflict(
        self, dep_name: str, current: str | None, spec: str, label: str, items: tuple[str, ...] | None = None
    ) -> TransitiveImpact:
        return TransitiveImpact(
            package_name=dep_name,
            current_version=current,
            projected_version=None,
            new_constraint=spec,
            driven_by=self.driven_by,
            has_conflict=True,
            conflict=RejectionDetail(label, items or (spec,)),
            kind=ImpactKind.PEER,
        )


def assess_candidate_peers(
    package_name: str,
    candidate_version: str,
    transitive_by_name: dict[str, ScanRecord],
    registry: AbstractPackageRegistryApi,
    allow_prerelease: bool = False,
    installed_names: set[str] | None = None,
    now: datetime | None = None,
    installed_version: str | None = None,
    release_cutoff: ReleaseCutoff | None = None,
    direct_versions: Mapping[str, str] | None = None,
) -> list[TransitiveImpact]:
    """Assess the peers the candidate itself declares against what the tree holds.

    A peer binds the one instance the requirer resolves, and a declared range binds whatever an
    override would let npm install: the override silences npm's check, not the incompatibility. So:

    - An optional peer absent from the tree binds nothing; one that is present is enforced.
    - A required peer that is absent is installed alongside, as npm 7+ does. It blocks when nothing
      published satisfies it, and the peers of what npm would install are walked the same way
      (bounded by MAX_PEER_DEPTH), since npm resolves the whole peer set at once.
    - A peer present but out of range moves its copy through a keyed override, or blocks when the
      copy's other users, or an override the user wrote, can't let it.
    - A range the installed release declared too, and the tree already violated, is existing drift.
    - The candidate's own peers on direct dependencies are the solver's and the reconciliation's to
      settle; only a peer reached through a newly installed package is checked against them here.

    Args:
        package_name: The package being bumped.
        candidate_version: The version it would move to.
        transitive_by_name: The scan's transitive records.
        registry: Registry, for declared peers and published versions.
        allow_prerelease: Whether a projection may land on a prerelease.
        installed_names: Every package installed anywhere in the tree.
        now: Reference time for the projections.
        installed_version: The version being replaced, to tell existing drift from new breakage.
        release_cutoff: The package manager's own limit on release age.
        direct_versions: {name: version} for direct dependencies, which a new peer's peers may name.
    """
    previous = registry.package_version_peers(package_name, installed_version) if installed_version else {}
    walk = PeerSetWalk(
        driven_by=package_name,
        transitive_by_name=transitive_by_name,
        registry=registry,
        allow_prerelease=allow_prerelease,
        installed_names=installed_names or set(),
        now=now,
        release_cutoff=release_cutoff,
        direct_versions=direct_versions or {},
    )
    return walk.peers_of(package_name, candidate_version, previous, depth=0, planned={package_name: candidate_version})


def simulate_single(
    package_name: str,
    candidate_version: str,
    transitive_by_name: dict[str, ScanRecord],
    registry: AbstractPackageRegistryApi,
    allow_prerelease: bool = False,
    installed_names: set[str] | None = None,
    now: datetime | None = None,
    installed_version: str | None = None,
    release_cutoff: ReleaseCutoff | None = None,
    incoming_peers: Sequence[IncomingEdge] = (),
    direct_versions: Mapping[str, str] | None = None,
) -> DirectUpdateImpact:
    """Simulate the transitive impact of updating package_name to candidate_version.

    This is the hot path for Phase 4c's post_solve_validator — registry is cache-warm,
    no network calls expected, no SAT solver invocation.

    installed_version: the currently installed version of package_name. When provided,
    the old requirements from that version are fetched so stale constraints it imposed
    on transitive deps are replaced rather than merged with the new requirements. Only a package
    manager that allows one copy per name needs it: where copies nest, each edge is judged on its
    own and nothing of the old version's constraints is merged in the first place.

    release_cutoff: the package manager's own limit on release age. A transitive dep is projected
    at a version the installer would actually move it to, never one past that limit.

    incoming_peers: the peer requirements installed packages place on package_name (see
    `incoming_peer_edges`). A candidate outside one of those ranges is not actionable unless the
    requirer moves with it; the candidate's own peers are checked against the tree as well.

    direct_versions: {name: version} for direct dependencies, which the peers of a package the
    candidate newly pulls in may name (see `assess_candidate_peers`).
    """
    impacts: list[TransitiveImpact] = []
    if registry.one_copy_per_name:
        new_requires = registry.package_version_requires(package_name, candidate_version)
        old_requires: dict[str, str] = {}
        if installed_version and installed_version != candidate_version:
            old_requires = registry.package_version_requires(package_name, installed_version)

        for dep_name, constraint in new_requires.items():
            impact = assess_transitive_impact(
                dep_name,
                constraint,
                package_name,
                transitive_by_name,
                registry,
                allow_prerelease,
                installed_names,
                now,
                old_constraint_from_driven_by=old_requires.get(dep_name),
                release_cutoff=release_cutoff,
            )
            if impact is not None:
                impacts.append(impact)
    else:
        impacts = simulate_nested(
            package_name,
            candidate_version,
            transitive_by_name,
            registry,
            allow_prerelease,
            installed_names,
            now,
            release_cutoff,
        )

    moved: dict[str, str] = {}
    bumped: dict[tuple[str, str], str] = {}
    for impact in impacts:
        if (version := impact.projected_version) is not None and not impact.has_conflict:
            if version != impact.current_version:
                moved[impact.package_name] = version
            if impact.kind == ImpactKind.OVERRIDE_BUMP and impact.current_version is not None:
                bumped[(impact.package_name, impact.current_version)] = version
    impacts.extend(
        assess_incoming_peers(
            package_name,
            candidate_version,
            incoming_peers,
            moved,
            transitive_by_name,
            registry,
            installed_version,
            bumped,
        )
    )
    impacts.extend(
        assess_candidate_peers(
            package_name,
            candidate_version,
            transitive_by_name,
            registry,
            allow_prerelease,
            installed_names,
            now,
            installed_version,
            release_cutoff,
            direct_versions,
        )
    )

    # A new transitive dep (current_version=None) with no projection is informational; a conflict
    # blocks wherever it is, a required peer that nothing published satisfies included.
    is_actionable = all(
        not i.has_conflict and (i.current_version is None or i.projected_version is not None) for i in impacts
    )
    return DirectUpdateImpact(
        package_name=package_name,
        recommended_version=candidate_version,
        transitive_impacts=impacts,
        is_actionable=is_actionable,
        fallback_version=None,
    )


def simulate_update_impacts(
    recommendations: dict[str, str],
    transitive_records: list[ScanRecord],
    registry: AbstractPackageRegistryApi,
    allow_prerelease: bool = False,
    installed_names: set[str] | None = None,
    now: datetime | None = None,
    installed_versions: dict[str, str] | None = None,
    release_cutoff: ReleaseCutoff | None = None,
    incoming_peers_by_name: Mapping[str, Sequence[IncomingEdge]] | None = None,
) -> dict[str, DirectUpdateImpact]:
    """Simulate transitive impacts for all recommended direct dep updates.

    recommendations: {canonical_package_name: recommended_version} from the solver
    transitive_records: all transitive ScanRecords from the scan (all_constraints populated)
    installed_names: complete set of canonical package names currently installed in the project
        (including transitive deps of dev packages). When provided, packages present here are
        not flagged as new transitive deps even if absent from the scan's transitive_records.
    installed_versions: {canonical_package_name: installed_version} for direct deps. When
        provided, stale constraints imposed by the installed version on transitive deps are
        stripped before merging with the new candidate's constraints — same logic as the
        post-solve validator uses via simulate_single(installed_version=…).
    now: reference time (the cutoff date when set) for deterministic projections and ages.
    release_cutoff: the package manager's own limit on release age, forwarded to simulate_single.
    incoming_peers_by_name: {canonical_package_name: peer edges onto its installed copy}, forwarded
        to simulate_single so each recommendation is checked against the peers placed on it.

    Keys in the returned dict match the keys of recommendations.
    """
    transitive_by_name = {r.package_name: r for r in transitive_records}
    return {
        pkg: simulate_single(
            pkg,
            ver,
            transitive_by_name,
            registry,
            allow_prerelease,
            installed_names,
            now,
            installed_version=installed_versions.get(pkg) if installed_versions else None,
            release_cutoff=release_cutoff,
            incoming_peers=(incoming_peers_by_name or {}).get(pkg, ()),
            direct_versions=installed_versions,
        )
        for pkg, ver in recommendations.items()
    }
