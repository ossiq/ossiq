"""
Abstract Dependency Tree parser for transitive dependencies analysis
"""

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any

from ossiq.domain.project import Dependency


class BaseDependencyResolver(ABC):
    """
    Orchestrates the construction of a dependency graph from raw data.
    Delegates format-specific parsing (UV, NPM, etc.) to subclasses.
    """

    def __init__(self, raw_data: Any):
        self.raw_data = raw_data
        self.registry: dict[frozenset, Dependency] = {}

    @abstractmethod
    def get_all_packages(self) -> Iterable[dict]:
        """Returns an iterable of all package entries in the lockfile."""
        pass

    @abstractmethod
    def extract_package_identity(self, pkg_data: dict) -> tuple[str, str]:
        """Returns (name, version_installed)."""
        pass

    @abstractmethod
    def extract_package_metadata(self, pkg_data: dict) -> tuple[str | None, str | None, str | None]:
        """Returns (source, marker, version_defined)."""
        pass

    @abstractmethod
    def get_raw_dependencies(self, pkg_data: dict) -> Iterable[tuple[str | None, Iterable[dict]]]:
        """Returns the raw dependency requirement entries for a package."""
        pass

    @abstractmethod
    def extract_dependency_identity(self, dep_data: dict) -> tuple[str, str | None]:
        """Returns (name, version_constraint) from a dependency entry."""
        pass

    def build_graph(self, root_name: str) -> Dependency | None:
        """
        Builds the in-memory graph using a two-pass approach to handle
        forward references and circular dependencies.

        Performance is not in the consideration at this point.
        """
        # Pass 1: Instantiate all unique Dependency nodes
        for pkg_data in self.get_all_packages():
            name, version = self.extract_package_identity(pkg_data)
            source, required_engine, v_def = self.extract_package_metadata(pkg_data)

            node = Dependency(
                name=name,
                version_installed=version,
                source=source,
                required_engine=required_engine,
                version_defined=v_def,
            )
            self.registry[frozenset((name, version))] = node

        # Pass 2: Link nodes via their dependencies mapping
        for pkg_data in self.get_all_packages():
            name, version = self.extract_package_identity(pkg_data)
            parent = self.registry.get(frozenset((name, version)))

            if not parent:
                continue

            for category, dependencies in self.get_raw_dependencies(pkg_data):
                for d_data in dependencies:
                    d_name, d_ver = self.extract_dependency_identity(d_data)

                    child = self.match_child(d_name, d_ver)
                    if child:
                        # collect defined versions if it is differ from installed version
                        if d_ver != child.version_installed:
                            child.version_defined = d_ver

                        # NOTE: we intentionally do not need to use
                        # name+version combined b/c on every level
                        # of the tree there'll be only one version of a package.

                        # handle optional dependencies category
                        if category:
                            child.categories.append(category)
                            parent.optional_dependencies[child.name] = child
                        else:
                            # production dependency
                            parent.dependencies[child.name] = child

        return self.find_root(root_name)

    def match_child(self, name: str, version_constraint: str | None = None) -> Dependency | None:
        """
        Finds a dependency in the registry.
        In lockfiles, we prioritize finding the package that was actually resolved.
        """
        # 1. Try exact match first (standard)
        exact_match = self.registry.get(frozenset((name, version_constraint)), None)
        if exact_match:
            return exact_match

        # 2. Fallback: Search registry for this package name
        # We split from the right to handle scoped packages like @scope/name@version
        return self.find_root(name)

    def find_root(self, name: str) -> Dependency | None:
        """Locates the starting node of the graph."""
        return next((v for k, v in self.registry.items() if name in k), None)


class GraphExporter:
    """
    Walks the dependency graph and produces dict with dependencies
    """

    def __init__(self, root: Dependency):
        self.root = root
        self.visited = set()

    def _to_dict(self, node: Dependency) -> dict:
        # If we've seen this specific package version before,
        # return a reference to avoid bloated JSON and recursion loops.
        key = frozenset([node.name, node.version_installed])
        if key in self.visited:
            return {"key": key, "ref": "already_defined"}

        self.visited.add(key)

        return {
            "name": node.name,
            "version_installed": node.version_installed,
            "version_defined": node.version_defined,
            "source": node.source,
            "marker": node.required_engine,
            "key": key,
            # Recurse into children
            "dependencies": [self._to_dict(child) for child in node.dependencies.values()],
        }

    def export(self) -> dict:
        """Returns a dictionary representation of the graph."""
        self.visited.clear()
        return self._to_dict(self.root)
