"""Order package moves into install passes, so no pass leaves a peer range broken mid-install.

Pure: the caller decides what each range admits and hands over booleans; nothing here knows what a
version is.
"""

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class PeerLink:
    """A peer range between two packages that both move, `requirer` asking something of `peer`."""

    requirer: str
    peer: str
    installed_admits_target: bool
    """The requirer's installed range admits the peer's target version."""
    target_admits_installed: bool
    """The requirer's target range admits the peer's installed version."""


@dataclass(frozen=True)
class InstallSequence:
    """The passes that reach the final state, each move in exactly one."""

    pass_of: dict[str, int]
    """1-based pass number per move key."""
    ordered: tuple[PeerLink, ...] = ()
    """Links whose requirer is held strictly before its peer: the requirer's old range still
    forbids the peer's target, and its new one lets it go first."""
    unresolved: tuple[PeerLink, ...] = ()
    """Links that wanted a strict order but sit on a cycle, so both ends share a pass."""


def sequence_moves(moves: Sequence[str], links: Sequence[PeerLink]) -> InstallSequence:
    """Assign each move to the latest pass its peer links allow, in as few passes as they need.

    A link gives at most two constraints. If the requirer's target range rejects the peer's
    installed version, the peer must not land after it. If the requirer's installed range rejects
    the peer's target, the requirer must not land after the peer, and strictly before it whenever
    its target range lets it go first; when neither can go first they are a lockstep pair and
    share a pass. These are difference constraints, so the pass count is the longest chain of
    strict ones, found by relaxation.

    Args:
        moves: Unique key of every package that moves.
        links: Peer ranges between moves; a link naming an unknown key is ignored.

    Returns:
        The pass of each move, and the links that were ordered or could not be.
    """
    known = set(moves)
    edges: list[tuple[str, str, bool, PeerLink]] = []  # (lands first, lands after, strict, link)
    for link in links:
        if link.requirer == link.peer or not {link.requirer, link.peer} <= known:
            continue
        if not link.target_admits_installed:
            edges.append((link.peer, link.requirer, False, link))
        if not link.installed_admits_target:
            edges.append((link.requirer, link.peer, link.target_admits_installed, link))

    after: dict[str, set[str]] = {move: set() for move in moves}
    for first, then, _, _ in edges:
        after[first].add(then)

    def reaches(start: str, goal: str) -> bool:
        seen, pending = set(), [start]
        while pending:
            node = pending.pop()
            if node == goal:
                return True
            if node not in seen:
                seen.add(node)
                pending.extend(after[node])
        return False

    # A strict edge with a path back is a positive cycle: no order satisfies it, so it degrades to
    # "same pass" and is reported. Every other strict edge is on no cycle and always satisfiable.
    ordered: list[PeerLink] = []
    unresolved: list[PeerLink] = []
    gaps: list[tuple[str, str, int]] = []
    for first, then, strict, link in edges:
        if strict and reaches(then, first):
            unresolved.append(link)
            strict = False
        elif strict:
            ordered.append(link)
        gaps.append((first, then, int(strict)))

    # depth = longest run of strict steps that must still follow a move; the deepest lands first.
    depth = dict.fromkeys(moves, 0)
    for _ in range(len(depth) + 1):
        changed = False
        for first, then, gap in gaps:
            if depth[first] < depth[then] + gap:
                depth[first] = depth[then] + gap
                changed = True
        if not changed:
            break
    top = max(depth.values(), default=0)
    return InstallSequence(
        pass_of={move: top - depth[move] + 1 for move in moves},
        ordered=tuple(dict.fromkeys(ordered)),
        unresolved=tuple(dict.fromkeys(unresolved)),
    )
