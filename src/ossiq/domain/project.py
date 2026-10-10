"""
Module to define abstract Package
"""

import re
from dataclasses import dataclass, field

from .common import ConstraintType, PackageNotInstalled
from .packages_manager import PackageManagerType


@dataclass(frozen=True)
class ConstraintSource:
    """Describes how a version constraint was introduced for a dependency."""

    type: ConstraintType
    source_file: str | None  # e.g. "package.json", "pyproject.toml", "requirements.txt"
    scope_path: list[str] | None = None  # npm nested override path, e.g. ["foo", "bar"]; None for flat
    is_ossiq_authored: bool = False
    """True when this OVERRIDE-type constraint's current value matches what OSS IQ itself last wrote
    (ossiq:metadata.overrides in package.json / [tool.ossiq.metadata] in pyproject.toml). False for a
    user-authored override, or when the user has since edited it away from our last-written value."""
    override_key: str | None = None
    """npm only: the version range an override rule is keyed to (`foo@^1` -> `^1`). None when the rule
    applies to every version of the package."""
    override_value: str | None = None
    """npm only: what the matching override rule forces. May be a `$name` reference to a root dependency."""

    @property
    def is_user_override(self) -> bool:
        """Whether an override the user is responsible for governs this constraint.

        A rule OSS IQ wrote is OSS IQ's to move, so it is not one: surfaces that flag an override, and
        the gates that hold an update behind one, read this rather than testing `type` themselves.
        """
        return self.type == ConstraintType.OVERRIDE and not self.is_ossiq_authored


@dataclass(frozen=True)
class PeerRequirement:
    """A peer dependency constraint placed on this package by another installed package."""

    requirer_name: str
    spec: str
    optional: bool = False
    """npm's `peerDependenciesMeta.<name>.optional`: npm neither installs it nor keeps it installed."""


@dataclass(frozen=True)
class UnresolvedPeer:
    """A peer a package declares that nothing installed where it looks can satisfy.

    npm resolves a peer from the requirer's own location, so a copy nested under some other package
    does not count. Recorded on the requirer, since there is no target to put it on.
    """

    package: str
    spec: str
    optional: bool = False
    installed_elsewhere: tuple[str, ...] = ()
    """Versions of `package` installed out of the requirer's reach; empty when it is installed nowhere."""


@dataclass(frozen=True)
class IncomingEdge:
    """One parent's requirement on an installed package: who asked, and for what range.

    Kept per edge, not just as a spec list, because a package manager that nests copies needs to
    know which parent a spec came from to tell a sibling that moves with the candidate from one that
    stays behind.
    """

    requirer_name: str
    requirer_version: str
    spec: str
    is_peer: bool = False
    optional: bool = False
    """Only for a peer edge: npm does not keep a copy installed for an optional peer alone."""


@dataclass(frozen=True)
class InstalledCopy:
    """One physical copy of a package in the tree, with the edges that resolve to it.

    npm can install the same name at several versions (nested node_modules); every other supported
    package manager installs exactly one.
    """

    version: str
    edges: tuple[IncomingEdge, ...]
    constraint_info: ConstraintSource


@dataclass(order=True)
class Dependency:
    """
    Represents a Dependency with child (transitive) depenencies
    """

    name: str
    # Factually installed version. Fallback to version_defined if there's no lockfile
    version_installed: str
    # Real registry name for package registry lookups. For npm aliases (e.g. alias "chalk-legacy" -> "chalk"),
    # this holds the actual package name. For non-aliased packages it equals `name`. Never None.
    canonical_name: str
    # Version, nominally defined in project requirements before resolution
    version_defined: str | None = None
    # Raw version specifier declared by the root manifest itself for this package, populated
    # exactly once at root-node registration (never by Pass 2's parent-edge iteration in
    # dependency_tree.py, which may process parents in arbitrary order). None for packages
    # with no root-manifest entry, i.e. pure transitive/peer-only dependencies. This is the
    # value every user-facing consumer must read instead of version_defined, which stays a
    # last-writer-wins accumulator used internally by the solver.
    version_constraint_declared: str | None = None
    source: str | None = None
    required_engine: str | None = None
    categories: list[str] = field(default_factory=list, compare=False)

    # PyPI extras requested for this dependency, e.g. ["security", "tests"] for requests[security,tests]
    extras: list[str] | None = field(default=None, compare=False)

    # list of direct dependencies for this particular dependency
    dependencies: dict[str, "Dependency"] = field(default_factory=dict, compare=False, hash=False)
    optional_dependencies: dict[str, "Dependency"] = field(default_factory=dict, compare=False, hash=False)

    # Constraint provenance; defaults to DECLARED when not explicitly set
    constraint_info: "ConstraintSource" = field(
        default_factory=lambda: ConstraintSource(type=ConstraintType.DECLARED, source_file=""),
        compare=False,
    )

    # All version specifiers declared by every direct parent of this node.
    # Populated during graph construction (dependency_tree.py Pass 2).
    # Used by the solver to apply multi-parent L1 hard rejections for diamond deps.
    parent_constraints: list[str] = field(default_factory=list, compare=False)

    # Peer requirements placed on this package by other installed packages.
    # Populated during graph construction alongside parent_constraints.
    peer_requirements: list[PeerRequirement] = field(default_factory=list, compare=False)

    # The same edges as parent_constraints, with the requirer attached. Populated alongside it in
    # graph construction; parent_constraints stays the flat view the solver and PyPI read.
    parent_edges: list[IncomingEdge] = field(default_factory=list, compare=False)

    # Peers this package declares that resolve to nothing from where it sits (npm only).
    unresolved_peers: list[UnresolvedPeer] = field(default_factory=list, compare=False)


class Project:
    """Class for a package."""

    package_manager_type: PackageManagerType
    name: str
    project_path: str | None
    dependency_tree: Dependency
    engine_constraints: dict[str, str] | None  # e.g. {"python": "3.11"} or {"node": "18.0.0"}
    has_lockfile: bool
    declares_esm: bool

    def __init__(
        self,
        package_manager_type: PackageManagerType,
        name: str,
        project_path: str,
        dependency_tree: Dependency,
        engine_constraints: dict[str, str] | None = None,
        manifest_lock_divergent: list[str] | None = None,
        has_lockfile: bool = True,
        declares_esm: bool = False,
    ):
        self.package_manager_type = package_manager_type
        self.name = name
        self.project_path = project_path
        self.dependency_tree = dependency_tree
        self.engine_constraints = engine_constraints
        self.manifest_lock_divergent: list[str] = manifest_lock_divergent or []
        self.has_lockfile = has_lockfile
        self.declares_esm = declares_esm

    def __repr__(self):
        return f"""{self.package_manager_type.name} Package(
  name='{self.name}'
  dependencies={self.dependencies}
)"""

    def installed_package_version(self, package_name: str):
        """
        Get installed version of a package.
        """
        prod_package = self.dependencies.get(package_name, None)

        if prod_package:
            return prod_package.version_installed

        optional_package = self.optional_dependencies.get(package_name, None)

        if optional_package:
            return optional_package.version_installed

        raise PackageNotInstalled(f"Package {package_name} not found in project {self.name}")

    @property
    def package_registry(self):
        return self.package_manager_type.package_registry

    @property
    def dependencies(self):
        return self.dependency_tree.dependencies

    @property
    def optional_dependencies(self):
        return self.dependency_tree.optional_dependencies


def normalize_filename(source_name: str) -> str:
    """
    Normalize a source name (package name, directory name) to a valid filename component.
    """

    # Convert to lowercase for consistency
    normalized = source_name.lower()

    # Replace filesystem-unsafe characters, @, dots, and whitespace with underscore,
    # then collapse multiple consecutive underscores or hyphens.
    normalized = re.sub(r'[/\\:*?"<>|@.\s]+', "_", normalized)
    normalized = re.sub(r"_+", "_", normalized)

    normalized = normalized.strip("_-")

    if not normalized:
        normalized = "unnamed"

    return normalized
