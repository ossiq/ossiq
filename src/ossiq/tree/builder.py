"""Build a linked Dependency graph from a parsed lockfile.

Subclasses read one lockfile format through the `get_*` / `extract_*` hooks; the two-pass linking
algorithm here is shared by all of them.
"""

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any

from ossiq.domain.common import ConstraintType
from ossiq.domain.project import Dependency, IncomingEdge, UnresolvedPeer
from ossiq.domain.version import normalize_version
from ossiq.tree.edges import apply_requirement, attach_child, merge_extras

CATEGORY_PEER = "peer"

# (name, version_installed): one lockfile entry, which is one node.
NodeKey = tuple[str, str]


class LockfileTreeBuilder(ABC):
    """Link the packages of a parsed lockfile into a Dependency graph.

    This reads what a lockfile recorded; it does not solve versions (see ossiq.solver for that).
    """

    def __init__(self, raw_data: Any):
        self.raw_data = raw_data
        self.registry: dict[NodeKey, Dependency] = {}

    # -- Lockfile format hooks: what a subclass has to say about its format ------------------------

    @abstractmethod
    def get_all_packages(self) -> Iterable[dict]:
        """Return every package entry in the lockfile."""

    @abstractmethod
    def extract_package_identity(self, pkg_data: dict) -> tuple[str, str]:
        """Return the (name, version_installed) of a package entry."""

    @abstractmethod
    def extract_package_metadata(self, pkg_data: dict) -> tuple[str | None, str | None, str | None]:
        """Return the (source, marker, version_defined) of a package entry."""

    @abstractmethod
    def get_raw_dependencies(self, pkg_data: dict) -> Iterable[tuple[str | None, Iterable[dict]]]:
        """Return a package's requirement entries as (category, entries) groups; None is production."""

    @abstractmethod
    def extract_dependency_identity(self, dep_data: dict) -> tuple[str, str | None]:
        """Return the (name, version_constraint) of a requirement entry."""

    @abstractmethod
    def build_initial_dependency(
        self,
        name: str,
        canonical_name: str,
        version_installed: str,
        source: str | None,
        required_engine: str | None,
        version_defined: str | None,
    ) -> Dependency:
        """Create the unlinked node for one package, with the constraint info its ecosystem uses."""

    def extract_dependency_extras(self, dep_data: dict) -> list[str]:
        """Return the extras a requirement entry asks of its target; none unless the format records them."""
        return []

    def extract_peer_optional(self, pkg_data: dict, name: str) -> bool:
        """Return whether pkg_data marks its peer *name* optional; never, unless the format records it."""
        return False

    def extract_canonical_name(self, pkg_data: dict) -> str | None:
        """Return the registry name when it differs from the lockfile name (an npm alias), else None."""
        return None

    def classify_constraint(self, spec: str | None) -> ConstraintType:
        """Return the specificity type of a version specifier; ecosystems override this."""
        return ConstraintType.DECLARED

    # -- Building the graph ------------------------------------------------------------------------

    def build_graph(self, root_name: str) -> Dependency | None:
        """Build the graph in two passes and return the root node.

        Registering every node first lets the second pass link forward references and cycles.

        Args:
            root_name: Name of the project's own package in the lockfile.

        Returns:
            The root node, or None when no package carries that name.
        """
        self.register_nodes()
        # Walking the packages again instead of caching them: lockfiles are small enough that
        # the simpler code wins.
        for pkg_data in self.get_all_packages():
            self.link_dependencies(pkg_data, root_name)
        return self.first_named(root_name)

    def register_nodes(self) -> None:
        """Create one unlinked node per package entry and index it by (name, version)."""
        for pkg_data in self.get_all_packages():
            name, version = self.extract_package_identity(pkg_data)
            source, required_engine, version_defined = self.extract_package_metadata(pkg_data)

            self.registry[(name, version)] = self.build_initial_dependency(
                name=name,
                # FIXME: it would be better to just implement it in each package
                # manager explicitly instead of falling back to name
                canonical_name=self.extract_canonical_name(pkg_data) or name,
                version_installed=version,
                source=source,
                required_engine=required_engine,
                version_defined=version_defined,
            )

    def link_dependencies(self, pkg_data: dict, root_name: str) -> None:
        """Link one package to everything its entry says it requires."""
        name, version = self.extract_package_identity(pkg_data)
        parent = self.registry.get((name, version))
        if parent is None:
            return

        for category, entries in self.get_raw_dependencies(pkg_data):
            for entry in entries:
                self.link_edge(parent, pkg_data, category, entry, from_root=name == root_name)

    def link_edge(
        self,
        parent: Dependency,
        parent_data: dict,
        category: str | None,
        entry: dict,
        *,
        from_root: bool,
    ) -> None:
        """Link one requirement of parent to the node it resolves to.

        Args:
            parent: The requiring node.
            parent_data: The parent's own lockfile entry.
            category: The group the entry came from (dev, peer, ...); None for production.
            entry: The requirement entry as the lockfile writes it.
            from_root: Whether parent is the project's own package.
        """
        child_name, spec = self.extract_dependency_identity(entry)
        is_peer = category == CATEGORY_PEER
        peer_optional = is_peer and self.extract_peer_optional(parent_data, child_name)

        child = self.match_child(child_name, spec, parent_data, is_peer=is_peer)
        if child is None:
            if is_peer:
                unresolved = self.unresolved_peer(child_name, spec, peer_optional)
                if unresolved is not None:
                    parent.unresolved_peers.append(unresolved)
            return

        merge_extras(child, self.extract_dependency_extras(entry))

        # An entry without a specifier (uv writes some) says nothing about what was declared, so
        # it must not overwrite what an earlier edge set.
        if spec is not None:
            edge = IncomingEdge(
                requirer_name=parent.name,
                requirer_version=parent.version_installed,
                spec=spec,
                is_peer=is_peer,
                optional=peer_optional,
            )
            apply_requirement(child, edge, from_root=from_root, classify=self.classify_constraint)

        attach_child(parent, child, category)

    # -- Finding nodes -----------------------------------------------------------------------------

    def match_child(
        self,
        name: str,
        version_constraint: str | None = None,
        parent_data: dict | None = None,
        is_peer: bool = False,
    ) -> Dependency | None:
        """Find the node a requirement resolves to, preferring the package the lockfile actually installed.

        Args:
            name: Dependency name as the parent declares it.
            version_constraint: The parent's specifier for it.
            parent_data: The parent's own lockfile entry. Formats that record where each copy
                sits (npm) use it to resolve the copy the parent actually sees; others ignore it.
            is_peer: Whether the edge is a peer. Formats that record placement resolve a peer by
                location only; others, with one copy per name, ignore it.
        """
        if version_constraint:
            # A constraint like "^5.30.0" normalizes to "5.30.0", which picks the right copy when
            # nested node_modules hold several versions and a different one (say "5.43.0") sits
            # at the top level. Strings with no leading modifier, such as "npm:lodash@~4.17.0",
            # come back unchanged and just repeat the first lookup.
            for version in (version_constraint, normalize_version(version_constraint)):
                node = self.registry.get((name, version))
                if node is not None:
                    return node

        # Formats without per-copy placement have one version per name, so this is exact for
        # them; npm resolves by location before it gets here (NPMTreeBuilderV3.match_child).
        return self.first_named(name)

    def first_named(self, name: str) -> Dependency | None:
        """Return the first registered node called name, whatever its version.

        The project's own package is registered under its name like any other, so this also
        finds the root.
        """
        return next((node for (node_name, _), node in self.registry.items() if node_name == name), None)

    def unresolved_peer(self, name: str, spec: str | None, optional: bool) -> UnresolvedPeer | None:
        """Return the record for a peer that resolved to nothing, or None when nothing needs saying.

        A required peer always gets a record, since npm ought to have installed it. An optional one
        gets a record only when another copy is installed out of reach, because a package that
        imports its optional peer unguarded breaks on exactly that layout.
        """
        elsewhere = tuple(sorted({node.version_installed for node in self.registry.values() if node.name == name}))
        if optional and not elsewhere:
            return None
        return UnresolvedPeer(package=name, spec=spec or "*", optional=optional, installed_elsewhere=elsewhere)
