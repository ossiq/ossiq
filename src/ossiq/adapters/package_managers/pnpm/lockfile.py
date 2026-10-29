"""
Dependency graph of a pnpm-lock.yaml (lockfileVersion 9, written by pnpm 9 to 12), built from its
`importers`, `packages` and `snapshots` sections.

A snapshot key is `name@version` plus a `(peer@version)` suffix when the package was installed
against particular peers, so one `name@version` can have several snapshots. The graph keeps one
node per `name@version`, like npm's.
"""

import re
from collections.abc import Iterable
from typing import Any

import yaml

from ossiq.adapters.package_managers.npm.constants import CATEGORIES_OPTIONAL
from ossiq.adapters.package_managers.npm.engines import parse_node_engine
from ossiq.adapters.package_managers.npm.lockfile import NpmRegistryTreeBuilder
from ossiq.adapters.package_managers.pnpm.constants import (
    CATALOG_PROTOCOL,
    DEFAULT_CATALOG,
    IMPORTER_SECTION_CATEGORY,
    ROOT_IMPORTER,
    WORKSPACE_FILE,
)
from ossiq.adapters.package_managers.pnpm.overrides import parse_pnpm_override_rules
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.project import Dependency
from ossiq.tree.builder import CATEGORY_PEER, NodeKey

LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

# The requirements each registry package declares, which the lockfile does not record.
DeclaredRanges = dict[NodeKey, dict[str, str]]

# `name@` or `@scope/name@` opening a reference: the package an alias points at. Parentheses are
# excluded so the peer suffix of a plain version, `18.3.1(react@18.3.1)`, does not look like one.
ALIAS_REF = re.compile(r"(?:@[^/@:()]+/)?[^/@:()]+@")


def load_lockfile(text: str) -> dict[str, Any]:
    """Decode pnpm-lock.yaml and return the document holding the project's graph.

    pnpm 11 and later may write a first document for config dependencies and the pinned pnpm; it
    has an `importers['.']` of its own, so the project's graph is the last document.

    Raises:
        PackageManagerLockfileParsingError: The text is not valid YAML or holds no mapping.
    """
    try:
        documents = [document for document in yaml.load_all(text, Loader=LOADER) if isinstance(document, dict)]
    except yaml.YAMLError as exc:
        raise PackageManagerLockfileParsingError(f"pnpm-lock.yaml is not valid YAML: {exc}") from exc
    if not documents:
        raise PackageManagerLockfileParsingError("pnpm-lock.yaml holds no lockfile document")
    return documents[-1]


def strip_peer_suffix(key: str) -> str:
    """`react-dom@18.3.1(react@18.3.1)` -> `react-dom@18.3.1`; also drops `(patch_hash=...)`."""
    # shortcut: a "(" inside a tarball URL cuts the key early and mis-keys that package;
    # upgrade to pnpm's depth-counting scan if a real lockfile carries one.
    return key.partition("(")[0]


def split_key(key: str) -> NodeKey:
    """`@scope/pkg@1.2.3` -> (`@scope/pkg`, `1.2.3`): the name ends at the first `@` past index 0."""
    at = key.find("@", 1)
    return (key[:at], key[at + 1 :]) if at > 0 else (key, "")


def ref_to_key(ref: str, name: str) -> str | None:
    """The snapshot key a dependency reference points at, or None for a `link:` to the workspace.

    Args:
        ref: A resolved value from `importers` or a snapshot: a bare version (`4.1.2`), or a
            `name@version` when the dependency is an alias for another package.
        name: The name the dependency is declared under.
    """
    if ref.startswith("link:"):
        return None
    return ref if ALIAS_REF.match(ref) else f"{name}@{ref}"


def package_identity(packages: dict[str, Any], key: str) -> NodeKey:
    """The (name, version) a snapshot key installs.

    Tarball, git and file keys carry their location where a version belongs; the `packages` entry
    then records the real version.
    """
    base = strip_peer_suffix(key)
    name, version = split_key(base)
    return name, (packages.get(base) or {}).get("version", version)


def registry_parents(lockfile: dict[str, Any]) -> list[NodeKey]:
    """The registry packages that require others, which is where the lockfile has no ranges to give.

    Packages from git, tarballs and directories are left out: the registry has no document for them.
    """
    packages = lockfile.get("packages") or {}
    parents = []
    for key, snapshot in (lockfile.get("snapshots") or {}).items():
        resolution = (packages.get(strip_peer_suffix(key)) or {}).get("resolution") or {}
        requires = (snapshot or {}).keys() & {"dependencies", "optionalDependencies"}
        if requires and not resolution.keys() & {"tarball", "type"}:
            parents.append(package_identity(packages, key))
    return list(dict.fromkeys(parents))


class PnpmTreeBuilderV9(NpmRegistryTreeBuilder):
    """Tree builder for pnpm lockfile v9.

    A snapshot records resolved versions only, never the ranges its package asked for. Those come
    in as *declared_ranges*, fetched from the registry by the adapter, so the builder stays free
    of I/O; an edge without a known range simply carries none.
    """

    # shortcut: overrides in package.json#pnpm (pnpm 9 and 10) are labelled as the workspace
    # file too; upgrade if the label starts to matter.
    overrides_file = WORKSPACE_FILE

    def __init__(self, raw_data: dict[str, Any], root: NodeKey, declared_ranges: DeclaredRanges | None = None):
        """
        Args:
            raw_data: The project document of pnpm-lock.yaml.
            root: The (name, version) of the project's own package, which the lockfile does not name.
            declared_ranges: What each registry package declares for its dependencies.
        """
        super().__init__(raw_data, parse_pnpm_override_rules(raw_data.get("overrides")))
        self.packages: dict[str, Any] = raw_data.get("packages") or {}
        self.snapshots: dict[str, Any] = raw_data.get("snapshots") or {}
        self.declared_ranges = declared_ranges or {}
        self.entries = self.build_entries(root)

    # Entries: the lockfile re-cut into one dict per node

    def make_entry(
        self, name: str, package: NodeKey, refs: dict[str, str], info: dict[str, Any], *, importer: bool = False
    ) -> dict[str, Any]:
        """One node's entry: *name* is what it is installed as, *package* what it really is (aliases differ)."""
        return {
            "name": name,
            "version": package[1],
            "package": package,
            "refs": refs,
            "info": info,
            "importer": importer,
        }

    def snapshot_entry(self, key: str, name: str | None = None) -> dict[str, Any]:
        """The entry of one snapshot, its `packages` metadata merged in; *name* installs it under an alias."""
        info = {**(self.packages.get(strip_peer_suffix(key)) or {}), **(self.snapshots.get(key) or {})}
        refs = {**(info.get("dependencies") or {}), **(info.get("optionalDependencies") or {})}
        package = package_identity(self.packages, key)
        return self.make_entry(name or package[0], package, refs, info)

    def build_entries(self, root: NodeKey) -> list[dict[str, Any]]:
        """The root, then every snapshot, then one extra entry per alias a dependency is installed under.

        pnpm installs `chalk@4.1.2` once and links it as `chalk-legacy`; npm shows the alias as a node
        of its own, so the graph does too.
        """
        importer = (self.raw_data.get("importers") or {}).get(ROOT_IMPORTER) or {}
        root_refs = {
            name: item["version"]
            for section in IMPORTER_SECTION_CATEGORY
            for name, item in (importer.get(section) or {}).items()
        }
        entries = [self.make_entry(root[0], root, root_refs, importer, importer=True)]
        entries.extend(self.snapshot_entry(key) for key in self.snapshots)

        seen = {(entry["name"], entry["version"]) for entry in entries}
        for refs in [root_refs, *(entry["refs"] for entry in entries[1:])]:
            for name, ref in refs.items():
                key = ref_to_key(ref, name)
                if key is None:
                    continue
                package = package_identity(self.packages, key)
                if package[0] != name and (name, package[1]) not in seen:
                    seen.add((name, package[1]))
                    entries.append(self.snapshot_entry(key, name))
        return entries

    def resolve_catalog(self, name: str, specifier: str) -> str:
        """The range a `catalog:` specifier stands for, as the lockfile's `catalogs` records it."""
        if not specifier.startswith(CATALOG_PROTOCOL):
            return specifier
        catalog = specifier.removeprefix(CATALOG_PROTOCOL) or DEFAULT_CATALOG
        return ((self.raw_data.get("catalogs") or {}).get(catalog) or {}).get(name, {}).get("specifier", specifier)

    # Lockfile format hooks

    def get_all_packages(self) -> Iterable[dict]:
        return self.entries

    def extract_package_identity(self, pkg_data: dict) -> tuple[str, str]:
        return pkg_data["name"], pkg_data["version"]

    def extract_canonical_name(self, pkg_data: dict) -> str | None:
        real_name = pkg_data["package"][0]
        return real_name if real_name != pkg_data["name"] else None

    def extract_package_metadata(self, pkg_data: dict) -> tuple[str | None, str | None, str | None]:
        resolution = pkg_data["info"].get("resolution") or {}
        engine = parse_node_engine(pkg_data["info"].get("engines"))
        return resolution.get("tarball") or resolution.get("repo"), f"node: {engine}" if engine else None, None

    def get_raw_dependencies(self, pkg_data: dict) -> Iterable[tuple[str | None, Iterable[dict]]]:
        info = pkg_data["info"]
        if pkg_data["importer"]:
            for section, category in IMPORTER_SECTION_CATEGORY.items():
                yield (
                    category,
                    [
                        {"name": name, "version": self.resolve_catalog(name, item["specifier"])}
                        for name, item in (info.get(section) or {}).items()
                    ],
                )
            return

        ranges = self.declared_ranges.get(pkg_data["package"], {})
        peers = info.get("peerDependencies") or {}
        # A resolved peer is also listed under `dependencies`; it is yielded once, as a peer.
        yield (
            None,
            [
                {"name": name, "version": ranges.get(name)}
                for name in info.get("dependencies") or {}
                if name not in peers
            ],
        )
        yield (
            CATEGORIES_OPTIONAL,
            [{"name": name, "version": ranges.get(name)} for name in info.get("optionalDependencies") or {}],
        )
        yield CATEGORY_PEER, [{"name": name, "version": spec} for name, spec in peers.items()]

    def extract_peer_optional(self, pkg_data: dict, name: str) -> bool:
        return super().extract_peer_optional(pkg_data["info"], name)

    def match_child(
        self,
        name: str,
        version_constraint: str | None = None,
        parent_data: dict | None = None,
        is_peer: bool = False,
    ) -> Dependency | None:
        """Find the node the parent recorded for *name*: exactly the version it resolved to, never a range.

        None for a `link:` to the workspace and for a peer nothing provided, so the base class records
        the latter as unresolved.
        """
        ref = parent_data["refs"].get(name) if parent_data else None
        key = ref_to_key(ref, name) if ref else None
        if key is None:
            return None
        return self.registry.get((name, package_identity(self.packages, key)[1]))
