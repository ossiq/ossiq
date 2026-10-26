"""Lockfile fixtures and concrete builders shared by the tree tests."""

from ossiq.domain.project import Dependency
from ossiq.tree.builder import LockfileTreeBuilder


class DummyBuilder(LockfileTreeBuilder):
    """
    Minimal concrete builder for testing LockfileTreeBuilder logic.
    Accepts data shaped like a UV lockfile:

        {
            "package": [
                {
                    "name": "my-app",
                    "version": "1.0.0",
                    "source": {"registry": "https://pypi.org"},
                    "marker": None,
                    "dependencies": [{"name": "requests", "version": "2.31.0"}],
                    "optional-dependencies": {
                        "dev": [{"name": "pytest", "version": "8.0.0"}],
                    },
                },
                ...
            ]
        }
    """

    def get_all_packages(self):
        return self.raw_data.get("package", [])

    def extract_package_identity(self, pkg_data):
        return pkg_data["name"], pkg_data["version"]

    def extract_package_metadata(self, pkg_data):
        source_data = pkg_data.get("source", {})
        source = source_data.get("registry") if isinstance(source_data, dict) else str(source_data)
        marker = pkg_data.get("marker")
        v_def = pkg_data.get("version_defined")
        return source, marker, v_def

    def get_raw_dependencies(self, pkg_data):
        optional = pkg_data.get("optional-dependencies", {})
        if optional:
            yield from optional.items()
        yield None, pkg_data.get("dependencies", [])

    def extract_dependency_identity(self, dep_data):
        return dep_data["name"], dep_data.get("version")

    def build_initial_dependency(
        self, name, canonical_name, version_installed, source, required_engine, version_defined
    ):
        return Dependency(
            name=name,
            canonical_name=canonical_name,
            version_installed=version_installed,
            source=source,
            required_engine=required_engine,
            version_defined=version_defined,
        )


class ExtrasBuilder(DummyBuilder):
    """DummyBuilder that, like uv.lock, reads the extras an edge enables from its `extra` key."""

    def extract_dependency_extras(self, dep_data):
        return list(dep_data.get("extra", []))


class PeerBuilder(DummyBuilder):
    """DummyBuilder that reads which peers a package marks optional from its `optional_peers` list."""

    def extract_peer_optional(self, pkg_data, name):
        return name in pkg_data.get("optional_peers", [])


def make_lockfile(*packages):
    """Build a lockfile dict from a list of package dicts."""
    return {"package": list(packages)}


def lock_pkg(name, version, *, deps=None, optional_deps=None, source=None, marker=None, version_defined=None):
    """Shorthand for building a package entry."""
    entry = {"name": name, "version": version}
    if deps is not None:
        entry["dependencies"] = deps
    if optional_deps is not None:
        entry["optional-dependencies"] = optional_deps
    if source is not None:
        entry["source"] = source
    if marker is not None:
        entry["marker"] = marker
    if version_defined is not None:
        entry["version_defined"] = version_defined
    return entry


def lock_dep(name, version=None):
    """Shorthand for a dependency reference."""
    d = {"name": name}
    if version is not None:
        d["version"] = version
    return d


def lock_edge(name, version, *extras):
    return {"name": name, "version": version, "extra": list(extras)}


def graph_of(lockfile, builder=ExtrasBuilder) -> Dependency:
    root = builder(lockfile).build_graph("my-app")
    assert root is not None
    return root
