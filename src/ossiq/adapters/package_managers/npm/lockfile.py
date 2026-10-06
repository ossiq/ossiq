"""
Dependency graph of an npm package-lock.json (lockfileVersion 2 and 3), built from its flat
`packages` map.
"""

import logging
from collections.abc import Iterable
from typing import Any

from ossiq.adapters.package_managers.dependency_tree import BaseDependencyResolver
from ossiq.adapters.package_managers.npm.constants import (
    CATEGORIES_OVERRIDDEN,
    MANIFEST_FILE,
    PRODUCTION_SECTION,
    SECTION_CATEGORY,
)
from ossiq.adapters.package_managers.npm.engines import parse_node_engine
from ossiq.adapters.package_managers.npm.overrides import parse_override_rules, select_governing_rule
from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource, Dependency
from ossiq.domain.version import classify_npm_specifier

logger = logging.getLogger(__name__)


def package_name_from_path(path: str) -> str:
    """The name a lockfile key installs a package under: its last `node_modules/` segment.

    For an npm alias this is the alias, not the real name: `node_modules/lodash-range-tilde` holds
    `lodash` under the name `lodash-range-tilde`. For nested copies
    (`node_modules/rc-trigger/node_modules/rc-util`) it is the innermost package, consistent with
    how dependencies reference it in the lockfile.
    """
    return path.split("node_modules/")[-1]


def dependency_entries(pkg_data: dict[str, Any], section: str) -> list[dict[str, str]]:
    """The name/specifier pairs one dependency section of a lockfile entry declares."""
    return [{"name": name, "version": spec} for name, spec in pkg_data.get(section, {}).items()]


class NPMResolverV3(BaseDependencyResolver):
    """
    Concrete resolver for NPM v3 lockfiles.
    """

    def __init__(self, raw_data: dict[str, Any], overrides: dict[str, Any] | None = None):
        """
        Args:
            raw_data: The decoded package-lock.json.
            overrides: The manifest's `overrides` block. It lives in package.json only: npm does not
                copy it into the lockfile's root entry, so the lockfile alone cannot say what is forced.
        """
        super().__init__(raw_data)
        self.override_rules = parse_override_rules(overrides)
        # Lockfile key -> node, built on first use: it needs every node registered, which only
        # holds once the first pass of build_graph is done.
        self.path_nodes: dict[str, Dependency] | None = None

    def classify_constraint(self, spec: str | None) -> ConstraintType:
        return classify_npm_specifier(spec)

    def build_initial_dependency(
        self,
        name: str,
        canonical_name: str,
        version_installed: str,
        source: str | None,
        required_engine: str | None,
        version_defined: str | None,
    ) -> Dependency:
        return Dependency(
            name=name,
            canonical_name=canonical_name,
            version_installed=version_installed,
            source=source,
            required_engine=required_engine,
            version_defined=version_defined,
            constraint_info=ConstraintSource(
                type=classify_npm_specifier(version_defined),
                source_file=MANIFEST_FILE,
            ),
        )

    def build_graph(self, root_name: str, ossiq_overrides: dict[str, str] | None = None) -> Dependency | None:
        root = super().build_graph(root_name)
        ossiq_overrides = ossiq_overrides or {}
        # Mark every copy an override rule governs with the "overridden" category and constraint_info.
        # Every copy, not the first one found by name: nested copies are separate installs and an
        # override can pin some of them while leaving others alone.
        for node in self.registry.values():
            if node is root:
                continue
            rule = select_governing_rule(self.override_rules, node.name, node.version_installed)
            if rule is None:
                continue
            if CATEGORIES_OVERRIDDEN not in node.categories:
                node.categories.append(CATEGORIES_OVERRIDDEN)
            node.constraint_info = ConstraintSource(
                type=ConstraintType.OVERRIDE,
                source_file=MANIFEST_FILE,
                scope_path=list(rule.scope_path) or None,
                # OSS IQ only ever writes root rules, so a scoped one is the user's by construction.
                is_ossiq_authored=not rule.scope_path and ossiq_overrides.get(rule.raw_key) == rule.value,
                override_key=rule.key,
                override_value=rule.value,
            )
        return root

    def path_index(self) -> dict[str, Dependency]:
        """Lockfile key -> node, so a parent's position in the tree can be turned into its copy."""
        if self.path_nodes is None:
            self.path_nodes = {}
            for pkg_data in self.get_all_packages():
                node = self.registry.get(frozenset(self.extract_package_identity(pkg_data)))
                if node is not None:
                    self.path_nodes[pkg_data["_path"]] = node
        return self.path_nodes

    def resolve_from(self, parent_path: str, name: str) -> Dependency | None:
        """The copy Node's `require` would load for *name* when asked from *parent_path*.

        Looks in the parent's own node_modules first, then each ancestor's in turn up to the top
        level; the first hit wins. `package-lock.json` v2/v3 lays the tree out to match exactly
        this lookup, so the answer is the copy npm installed for that parent.
        """
        index = self.path_index()
        base = parent_path
        while True:
            node = index.get(f"{base}/node_modules/{name}" if base else f"node_modules/{name}")
            if node is not None:
                return node
            if not base:
                return None
            marker = base.rfind("node_modules/")
            base = base[:marker].rstrip("/") if marker >= 0 else ""

    def match_child(
        self,
        name: str,
        version_constraint: str | None = None,
        parent_data: dict | None = None,
    ) -> Dependency | None:
        """Link a dependency edge to the copy the parent actually resolves to.

        Falls back to matching by name and spec for entries the lookup cannot place (a `link: true`
        workspace entry, a hand-edited lockfile), which is also all that formats without a recorded
        position can do.
        """
        if parent_data is not None:
            resolved = self.resolve_from(parent_data.get("_path", ""), name)
            if resolved is not None:
                return resolved
            logger.debug("npm: no placed copy of %s for %r, matching by name", name, parent_data.get("_path", ""))
        return super().match_child(name, version_constraint, parent_data)

    def get_all_packages(self) -> Iterable[dict]:
        packages = self.raw_data.get("packages", {})
        for path, data in packages.items():
            pkg_info = data.copy()
            pkg_info["_path"] = path
            yield pkg_info

    def extract_package_identity(self, pkg_data: dict) -> tuple[str, str]:
        path = pkg_data.get("_path", "")
        if path == "":
            # Root package: use the name field or lockfile top-level name
            name = pkg_data.get("name") or self.raw_data.get("name", "")
        else:
            # Non-root: always the path component, never the `name` field (see package_name_from_path).
            name = package_name_from_path(path)
        version = pkg_data.get("version", "0.0.0")
        return name, version

    def get_raw_dependencies(self, pkg_data: dict) -> Iterable[tuple[str | None, Iterable[dict]]]:
        # NOTE: categories in lockfile takes PRECEDENCE over package.json
        yield None, dependency_entries(pkg_data, PRODUCTION_SECTION)
        for section, category in SECTION_CATEGORY.items():
            yield category, dependency_entries(pkg_data, section)

    def extract_canonical_name(self, pkg_data: dict) -> str | None:
        """
        Returns the canonical npm package name when the lockfile path uses an alias.

        For aliased entries like "node_modules/chalk-legacy" with {"name": "chalk"},
        returns "chalk". For non-aliased entries, returns None.
        """
        path = pkg_data.get("_path", "")
        if path == "":
            return None  # root package, not an alias
        lockfile_name = pkg_data.get("name")
        if lockfile_name and lockfile_name != package_name_from_path(path):
            return lockfile_name
        return None

    def extract_package_metadata(self, pkg_data: dict) -> tuple[str | None, str | None, str | None]:
        """
        NPM 'resolved' is the source URL.
        'engines' can be used as markers.
        """
        source = pkg_data.get("resolved")
        # FIXME: convert engines into something more consumable for the solver later
        node = parse_node_engine(pkg_data.get("engines"))
        required_engine = f"node: {node}" if node else None
        # NPM doesn't store the original 'version_defined' inside the package
        # block itself, but rather in the parent's dependency list.
        return source, required_engine, None

    def extract_dependency_identity(self, dep_data: dict) -> tuple[str, str | None]:
        """
        In NPM's dependency list, 'version' is actually the constraint (e.g., ^1.2.3).
        """
        return dep_data["name"], dep_data.get("version")
