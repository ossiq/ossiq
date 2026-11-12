"""Group the moves of an update plan into the steps that have to land together."""

from __future__ import annotations

from collections.abc import Iterable, Sequence


def group_steps(moves: Sequence[str], links: Iterable[tuple[str, str]]) -> list[list[str]]:
    """Split *moves* into the groups that *links* tie together, without reordering them.

    A link is a lockstep pair (react and react-dom) or a direct package and the transitive copy that
    rides with it. Links are transitive, so a rider shared by two direct packages merges both.

    Args:
        moves: Unique move keys, in the order the groups should come.
        links: Pairs of moves that land together; a pair naming an unknown key is ignored.

    Returns:
        One list per group, ordered by each group's earliest member, members in *moves* order.
    """
    parent = {move: move for move in moves}

    def find(move: str) -> str:
        while parent[move] != move:
            parent[move] = parent[parent[move]]
            move = parent[move]
        return move

    for a, b in links:
        if a in parent and b in parent:
            parent[find(a)] = find(b)

    groups: dict[str, list[str]] = {}
    for move in moves:
        groups.setdefault(find(move), []).append(move)
    return list(groups.values())
