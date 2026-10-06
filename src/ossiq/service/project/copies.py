"""Group the dependency graph's nodes into the physical copies each package is installed as."""

from collections.abc import Callable, Iterable
from functools import cmp_to_key

from ossiq.domain.common import ConstraintType
from ossiq.domain.project import Dependency, InstalledCopy

# (canonical package name, installed version): what makes two graph nodes the same install.
CopyKey = tuple[str, str]


def group_nodes_by_copy(nodes: Iterable[Dependency]) -> dict[CopyKey, list[Dependency]]:
    """Bucket graph nodes by the copy they stand for, each node once.

    The walk reaches one node by every path to it, and npm aliases of one package are separate
    nodes for what is a single install, so neither may count as another copy.
    """
    grouped: dict[CopyKey, list[Dependency]] = {}
    seen: set[int] = set()
    for node in nodes:
        if id(node) in seen:
            continue
        seen.add(id(node))
        grouped.setdefault((node.canonical_name, node.version_installed), []).append(node)
    return grouped


def build_installed_copy(nodes: list[Dependency]) -> InstalledCopy:
    """One copy from the graph nodes that stand for it.

    Edges are the union over the nodes, in the order they were linked. An override on any of them
    governs the copy: the aliases are the same install, so a rule that reaches one reaches all.
    """
    edges = tuple(dict.fromkeys(edge for node in nodes for edge in node.parent_edges))
    governed = next((node for node in nodes if node.constraint_info.type == ConstraintType.OVERRIDE), nodes[0])
    return InstalledCopy(version=nodes[0].version_installed, edges=edges, constraint_info=governed.constraint_info)


def installed_copies_by_name(
    grouped: dict[CopyKey, list[Dependency]],
    compare_versions: Callable[[str, str], int],
) -> dict[str, list[InstalledCopy]]:
    """Every copy of every package, keyed by canonical name and ordered newest first.

    Args:
        grouped: Nodes bucketed by `group_nodes_by_copy`.
        compare_versions: The registry's own version ordering.

    Returns:
        For each name, its copies newest first, so the first is the one a record reports.
    """
    by_name: dict[str, list[InstalledCopy]] = {}
    for (name, _), nodes in grouped.items():
        by_name.setdefault(name, []).append(build_installed_copy(nodes))
    for copies in by_name.values():
        copies.sort(key=cmp_to_key(lambda a, b: compare_versions(b.version, a.version)))
    return by_name
