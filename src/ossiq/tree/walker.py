"""Walk an already-built Dependency graph.

Read-only: nothing here changes the graph or touches I/O, so the scan pipeline and its tests share
one traversal.
"""

from collections.abc import Iterator

from ossiq.domain.common import normalize_dist_name
from ossiq.domain.project import Dependency

# A node and the names of its ancestors, from the root's direct child down to (not including) it.
NodePath = tuple[Dependency, list[str]]


class DependencyWalker:
    """Enumerate the packages installed under a project's root node."""

    def __init__(self, root: Dependency):
        self.root = root

    def walk_all_paths(
        self, *, include_optional_roots: bool = False, include_enabled_extras: bool = False
    ) -> Iterator[NodePath]:
        """Yield every package installed under the root, once per distinct path that reaches it.

        `path` lists the ancestor names from the root's direct child down to, but not including, the
        node, so ["react-dom"] for scheduler. Packages npm installs only because something
        peer-requires them (typescript for @nuxt/ui) come last, once each, with the requirer chain
        as their path; they sit on no production edge yet are installed.

        Args:
            include_optional_roots: Also start from the root's dev, peer and optional direct dependencies.
            include_enabled_extras: Also follow a package's optional edges that belong to an extra the
                project enables on it (PyPI `pkg[extra]`), which the lockfile installs.

        Yields:
            Each node with its path.
        """
        roots = self.direct_dependencies(include_optional_roots)
        reached = {id(root) for root in roots}
        # Every node the production walk reaches, with its own name at the end of the path: the
        # starting points for finding what only a peer requirement installs.
        reached_with_path = [(root, [root.name]) for root in roots]

        for root in roots:
            for node, path in self.walk_production_paths(root, [root.name], {id(root)}, include_enabled_extras):
                if id(node) not in reached:
                    reached.add(id(node))
                    reached_with_path.append((node, [*path, node.name]))
                yield node, path

        yield from self.walk_peer_installs(reached_with_path, reached, include_enabled_extras)

    def direct_dependencies(self, include_optional_roots: bool = False) -> list[Dependency]:
        """Return the root's production dependencies, plus its dev, peer and optional ones on request."""
        roots = list(self.root.dependencies.values())
        if include_optional_roots:
            roots += self.root.optional_dependencies.values()
        return roots

    def walk_production_paths(
        self,
        node: Dependency,
        path: list[str],
        in_path: set[int],
        include_enabled_extras: bool = False,
    ) -> Iterator[NodePath]:
        """Yield everything node installs, depth first, without cross-path deduplication.

        Args:
            node: The package whose installed children to walk.
            path: Ancestor names down to and including node.
            in_path: Ids of the nodes on the current path; a child already there is a back-edge
                of a circular dependency and is skipped.
            include_enabled_extras: Follow extras the project enables, as in `installed_children`.

        Yields:
            Each descendant with its path.
        """
        for child in self.installed_children(node, include_enabled_extras):
            if id(child) in in_path:
                continue
            yield child, path
            yield from self.walk_production_paths(
                child, [*path, child.name], in_path | {id(child)}, include_enabled_extras
            )

    def walk_peer_installs(
        self,
        reached_with_path: list[NodePath],
        reached: set[int],
        include_enabled_extras: bool = False,
    ) -> Iterator[NodePath]:
        """Yield the packages npm installs for a peer requirement, and what each of them depends on.

        Args:
            reached_with_path: Nodes already yielded, each with its path including its own name.
            reached: Ids of those nodes, updated in place so nothing is yielded twice.
            include_enabled_extras: Follow extras the project enables, as in `installed_children`.

        Yields:
            Each newly found node with its path.
        """
        pending = list(reached_with_path)
        while pending:
            node, path = pending.pop()
            for child in [*self.installed_children(node, include_enabled_extras), *self.required_peers(node)]:
                if id(child) not in reached:
                    reached.add(id(child))
                    pending.append((child, [*path, child.name]))
                    yield child, path

    @staticmethod
    def installed_children(node: Dependency, include_enabled_extras: bool = False) -> list[Dependency]:
        """Return what node installs on production edges, plus the extras the project enables when asked."""
        children = list(node.dependencies.values())
        if include_enabled_extras and node.extras:
            enabled = {normalize_dist_name(extra) for extra in node.extras}
            children += [
                child
                for child in node.optional_dependencies.values()
                if enabled & {normalize_dist_name(category) for category in child.categories}
            ]
        return children

    @staticmethod
    def required_peers(node: Dependency) -> list[Dependency]:
        """Return the packages node peer-requires and npm therefore installs for it; optional peers are left out."""
        return [
            child
            for child in node.optional_dependencies.values()
            if any(
                edge.is_peer
                and not edge.optional
                and edge.requirer_name == node.name
                and edge.requirer_version == node.version_installed
                for edge in child.parent_edges
            )
        ]
