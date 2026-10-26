"""What one requirement edge does to the nodes it connects.

Pure functions over Dependency, kept apart from LockfileTreeBuilder so the `version_defined` and
constraint-classification rules can be read and tested without a lockfile.
"""

from collections.abc import Callable

from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource, Dependency, IncomingEdge, PeerRequirement

# These record a decision someone made on purpose (an extra requirement, an override), so a parent's
# own specifier must not overwrite them.
NEVER_DOWNGRADED = (ConstraintType.ADDITIVE, ConstraintType.OVERRIDE)


def merge_extras(child: Dependency, extras: list[str]) -> None:
    """Add the extras an edge enables to those child already has.

    Extras gate the target's own requirements, so every edge that turns one on counts: the union
    is what the target installs with.
    """
    if extras:
        child.extras = sorted({*(child.extras or ()), *extras})


def record_incoming_edge(child: Dependency, edge: IncomingEdge) -> None:
    """Append edge to child's requirer records.

    `parent_constraints` is the flat spec list the solver reads for multi-parent (diamond)
    dependencies; `parent_edges` keeps who asked; a peer edge also lands in `peer_requirements`.
    """
    child.parent_constraints.append(edge.spec)
    child.parent_edges.append(edge)
    if edge.is_peer:
        child.peer_requirements.append(
            PeerRequirement(requirer_name=edge.requirer_name, spec=edge.spec, optional=edge.optional)
        )


def settle_version_defined(child: Dependency, spec: str, *, displaces_peer_fallback: bool) -> None:
    """Set child's `version_defined` to spec, unless spec only restates the installed version.

    A spec equal to the installed version adds nothing to record, but when it displaces the peer
    fallback it still clears the peer spec an earlier edge left behind.

    Args:
        child: The required node.
        spec: The specifier the requirer declared for it.
        displaces_peer_fallback: Whether this is a real (non-peer) edge arriving at a node that
            so far only peers have required.
    """
    # NOTE: `version_defined` is a last-writer-wins accumulator across every parent, root and
    # transitive alike. It feeds the solver and is not user-facing; user-facing surfaces read
    # `version_constraint_declared` instead (see domain/project.py).
    if spec != child.version_installed:
        child.version_defined = spec
    elif displaces_peer_fallback:
        child.version_defined = None


def reclassify_constraint(child: Dependency, spec: str, classify: Callable[[str | None], ConstraintType]) -> None:
    """Reclassify child's constraint from spec, unless it is one of NEVER_DOWNGRADED.

    The type is rederived even when spec equals the installed version, since a bare "4.17.21"
    is still a pin.

    Args:
        child: The required node.
        spec: The specifier the requirer declared for it.
        classify: Maps a specifier to its specificity type for this ecosystem.
    """
    if child.constraint_info.type in NEVER_DOWNGRADED:
        return
    child.constraint_info = ConstraintSource(
        type=classify(spec),
        source_file=child.constraint_info.source_file,
        scope_path=child.constraint_info.scope_path,
    )


def apply_requirement(
    child: Dependency,
    edge: IncomingEdge,
    *,
    from_root: bool,
    classify: Callable[[str | None], ConstraintType],
) -> None:
    """Record edge on child and update what child reports as declared.

    Args:
        child: The required node.
        edge: One requirer's specifier for child.
        from_root: Whether the requirer is the project's own package.
        classify: Maps a specifier to its specificity type for this ecosystem.
    """
    # NOTE: read the earlier requirers before recording this edge, or it would count as one.
    has_real_requirer = any(not earlier.is_peer for earlier in child.parent_edges)
    only_peers_so_far = bool(child.parent_edges) and not has_real_requirer

    record_incoming_edge(child, edge)

    # The root manifest's own declaration is the only user-facing "declared constraint". Capture
    # it from this edge so it does not depend on the order the other parents are processed in.
    if from_root:
        child.version_constraint_declared = edge.spec

    # A peer edge says what the requirer tolerates, not what to install, so it must not overwrite
    # what a real requirer (the root manifest above all) declared. A node reached only through
    # peers has nothing else to go on and keeps the peer spec as its fallback declaration.
    if edge.is_peer and has_real_requirer:
        return

    settle_version_defined(child, edge.spec, displaces_peer_fallback=not edge.is_peer and only_peers_so_far)
    reclassify_constraint(child, edge.spec, classify)


def attach_child(parent: Dependency, child: Dependency, category: str | None) -> None:
    """Hang child under parent: plain dependencies as `dependencies`, grouped ones as optional.

    Args:
        parent: The requiring node.
        child: The required node.
        category: The group the requirement came from (dev, peer, ...); None for production.
    """
    # NOTE: keyed by name alone, not name and version, because any one level of the tree holds
    # a single version of a package.
    if category:
        child.categories.append(category)
        parent.optional_dependencies[child.name] = child
    else:
        parent.dependencies[child.name] = child
