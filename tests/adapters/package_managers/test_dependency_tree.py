"""
Tests for BaseDependencyResolver and GraphExporter
"""

import sys

import pytest

from ossiq.adapters.package_managers.dependency_tree import BaseDependencyResolver, GraphExporter
from ossiq.domain.project import Dependency

# ============================================================================
# Dummy Resolver (based on UVResolverV1R3 structure)
# ============================================================================


class DummyResolver(BaseDependencyResolver):
    """
    Minimal concrete resolver for testing BaseDependencyResolver logic.
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


# ============================================================================
# Helpers
# ============================================================================


def _make_lockfile(*packages):
    """Build a lockfile dict from a list of package dicts."""
    return {"package": list(packages)}


def _pkg(name, version, *, deps=None, optional_deps=None, source=None, marker=None, version_defined=None):
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


def _dep(name, version=None):
    """Shorthand for a dependency reference."""
    d = {"name": name}
    if version is not None:
        d["version"] = version
    return d


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def simple_lockfile():
    """Lockfile with a root package and two direct dependencies."""
    return _make_lockfile(
        _pkg("my-app", "1.0.0", deps=[_dep("requests", "2.31.0"), _dep("click", "8.1.7")]),
        _pkg("requests", "2.31.0"),
        _pkg("click", "8.1.7"),
    )


@pytest.fixture
def transitive_lockfile():
    """Lockfile with transitive (nested) dependencies."""
    return _make_lockfile(
        _pkg("my-app", "1.0.0", deps=[_dep("requests", "2.31.0")]),
        _pkg("requests", "2.31.0", deps=[_dep("urllib3", "2.1.0"), _dep("certifi", "2024.2.2")]),
        _pkg("urllib3", "2.1.0"),
        _pkg("certifi", "2024.2.2"),
    )


@pytest.fixture
def optional_deps_lockfile():
    """Lockfile with optional dependency groups."""
    return _make_lockfile(
        _pkg(
            "my-app",
            "1.0.0",
            deps=[_dep("requests", "2.31.0")],
            optional_deps={"dev": [_dep("pytest", "8.0.0")], "docs": [_dep("sphinx", "7.2.0")]},
        ),
        _pkg("requests", "2.31.0"),
        _pkg("pytest", "8.0.0"),
        _pkg("sphinx", "7.2.0"),
    )


@pytest.fixture
def circular_lockfile():
    """Lockfile with circular dependencies (A -> B -> A)."""
    return _make_lockfile(
        _pkg("my-app", "1.0.0", deps=[_dep("pkg-a", "1.0.0")]),
        _pkg("pkg-a", "1.0.0", deps=[_dep("pkg-b", "2.0.0")]),
        _pkg("pkg-b", "2.0.0", deps=[_dep("pkg-a", "1.0.0")]),
    )


# ============================================================================
# Test build_graph
# ============================================================================


class TestBuildGraph:
    """Tests for the two-pass graph construction in BaseDependencyResolver."""

    def test_returns_root_node(self, simple_lockfile):
        """Test build_graph returns the correct root dependency."""
        # Arrange
        resolver = DummyResolver(simple_lockfile)

        # Act
        root = resolver.build_graph("my-app")

        # Assert
        assert root is not None
        assert root.name == "my-app"
        assert root.version_installed == "1.0.0"

    def test_returns_none_for_missing_root(self, simple_lockfile):
        """Test build_graph returns None when root package is not found."""
        # Arrange
        resolver = DummyResolver(simple_lockfile)

        # Act
        root = resolver.build_graph("nonexistent")

        # Assert
        assert root is None

    def test_links_direct_dependencies(self, simple_lockfile):
        """Test that direct dependencies are linked to the root node."""
        # Arrange
        resolver = DummyResolver(simple_lockfile)

        # Act
        root = resolver.build_graph("my-app")

        # Assert
        assert root is not None
        assert "requests" in root.dependencies
        assert "click" in root.dependencies

    def test_links_transitive_dependencies(self, transitive_lockfile):
        """Test that transitive dependencies are linked through the chain."""
        # Arrange
        resolver = DummyResolver(transitive_lockfile)

        # Act
        root = resolver.build_graph("my-app")

        # Assert
        assert root is not None
        requests = root.dependencies["requests"]
        assert requests is not None
        assert "urllib3" in requests.dependencies
        assert "certifi" in requests.dependencies

    def test_transitive_deps_not_on_root(self, transitive_lockfile):
        """Test that transitive dependencies are not direct children of root."""
        # Arrange
        resolver = DummyResolver(transitive_lockfile)

        # Act
        root = resolver.build_graph("my-app")

        # Assert
        assert root is not None
        assert "urllib3" not in root.dependencies
        assert "certifi" not in root.dependencies

    def test_optional_dependencies_linked(self, optional_deps_lockfile):
        """Test that optional dependencies are placed in optional_dependencies dict."""
        # Arrange
        resolver = DummyResolver(optional_deps_lockfile)

        # Act
        root = resolver.build_graph("my-app")

        # Assert
        assert root is not None
        assert "pytest" in root.optional_dependencies
        assert "sphinx" in root.optional_dependencies

    def test_optional_dependencies_have_categories(self, optional_deps_lockfile):
        """Test that optional dependencies receive their category label."""
        # Arrange
        resolver = DummyResolver(optional_deps_lockfile)

        # Act
        root = resolver.build_graph("my-app")

        # Assert
        assert root is not None
        pytest_dep = root.optional_dependencies["pytest"]
        sphinx_dep = root.optional_dependencies["sphinx"]
        assert pytest_dep is not None
        assert sphinx_dep is not None
        assert "dev" in pytest_dep.categories
        assert "docs" in sphinx_dep.categories

    def test_production_deps_not_in_optional(self, optional_deps_lockfile):
        """Test that production dependencies are not in optional_dependencies."""
        # Arrange
        resolver = DummyResolver(optional_deps_lockfile)

        # Act
        root = resolver.build_graph("my-app")

        # Assert
        assert root is not None
        assert "requests" in root.dependencies
        assert "requests" not in root.optional_dependencies

    def test_circular_dependencies_do_not_loop(self, circular_lockfile):
        """Test that circular dependencies are handled without infinite recursion."""
        # Arrange
        resolver = DummyResolver(circular_lockfile)

        # Act
        root = resolver.build_graph("my-app")

        # Assert
        assert root is not None
        pkg_a = root.dependencies["pkg-a"]
        assert pkg_a is not None
        pkg_b = pkg_a.dependencies["pkg-b"]
        assert pkg_b is not None
        # pkg-b points back to the same pkg-a object (shared reference)
        assert "pkg-a" in pkg_b.dependencies

    def test_version_defined_set_when_differs_from_installed(self):
        """Test version_defined is set on child when constraint differs from installed version."""
        # Arrange
        lockfile = _make_lockfile(
            _pkg("my-app", "1.0.0", deps=[_dep("lib", ">=2.0")]),
            _pkg("lib", "2.3.0"),
        )
        resolver = DummyResolver(lockfile)

        # Act
        root = resolver.build_graph("my-app")

        # Assert
        assert root is not None
        lib = root.dependencies["lib"]
        assert lib is not None
        assert lib.version_installed == "2.3.0"
        assert lib.version_defined == ">=2.0"

    def test_version_defined_not_overwritten_when_matches_installed(self):
        """Test version_defined is not changed when constraint matches installed version."""
        # Arrange
        lockfile = _make_lockfile(
            _pkg("my-app", "1.0.0", deps=[_dep("lib", "2.3.0")]),
            _pkg("lib", "2.3.0"),
        )
        resolver = DummyResolver(lockfile)

        # Act
        root = resolver.build_graph("my-app")

        # Assert
        assert root is not None
        lib = root.dependencies["lib"]
        assert lib is not None
        assert lib.version_defined is None

    def test_registry_populated(self, simple_lockfile):
        """Test that all packages are registered in the resolver registry."""
        # Arrange
        resolver = DummyResolver(simple_lockfile)

        # Act
        resolver.build_graph("my-app")

        # Assert
        assert len(resolver.registry) == 3
        assert frozenset(["my-app", "1.0.0"]) in resolver.registry
        assert frozenset(["requests", "2.31.0"]) in resolver.registry
        assert frozenset(["click", "8.1.7"]) in resolver.registry

    def test_empty_lockfile(self):
        """Test build_graph with no packages returns None."""
        # Arrange
        resolver = DummyResolver({"package": []})

        # Act
        root = resolver.build_graph("anything")

        # Assert
        assert root is None

    def test_metadata_preserved(self):
        """Test that source and marker metadata are preserved on nodes."""
        # Arrange
        lockfile = _make_lockfile(
            _pkg("my-app", "1.0.0", deps=[_dep("lib", "1.0.0")]),
            _pkg("lib", "1.0.0", source={"registry": "https://pypi.org"}, marker='python_version >= "3.11"'),
        )
        resolver = DummyResolver(lockfile)

        # Act
        root = resolver.build_graph("my-app")

        # Assert
        assert root is not None
        lib = root.dependencies["lib"]
        assert lib is not None
        assert lib.source == "https://pypi.org"
        assert lib.required_engine == 'python_version >= "3.11"'


# ============================================================================
# Test match_child
# ============================================================================


class TestMatchChild:
    """Tests for the match_child lookup logic."""

    def test_exact_match(self):
        """Test match_child finds a package by exact name@version key."""
        # Arrange
        resolver = DummyResolver(_make_lockfile(_pkg("lib", "1.0.0")))
        resolver.build_graph("lib")

        # Act
        result = resolver.match_child("lib", "1.0.0")

        # Assert
        assert result is not None
        assert result.name == "lib" and result.version_installed == "1.0.0"

    def test_fallback_by_name(self):
        """Test match_child falls back to name-only lookup when version does not match."""
        # Arrange
        resolver = DummyResolver(_make_lockfile(_pkg("lib", "1.0.0")))
        resolver.build_graph("lib")

        # Act
        result = resolver.match_child("lib", ">=1.0")

        # Assert
        assert result is not None
        assert result.name == "lib"

    def test_no_version_constraint(self):
        """Test match_child finds package when no version constraint is given."""
        # Arrange
        resolver = DummyResolver(_make_lockfile(_pkg("lib", "1.0.0")))
        resolver.build_graph("lib")

        # Act
        result = resolver.match_child("lib")

        # Assert
        assert result is not None

    def test_returns_none_for_unknown_package(self):
        """Test match_child returns None for a package not in the registry."""
        # Arrange
        resolver = DummyResolver(_make_lockfile(_pkg("lib", "1.0.0")))
        resolver.build_graph("lib")

        # Act
        result = resolver.match_child("nonexistent", "1.0.0")

        # Assert
        assert result is None


# ============================================================================
# Test find_root
# ============================================================================


class TestFindRoot:
    """Tests for the find_root lookup."""

    def test_finds_root_by_name_prefix(self):
        """Test find_root locates a node whose key starts with name@."""
        # Arrange
        resolver = DummyResolver(_make_lockfile(_pkg("my-app", "1.0.0")))
        resolver.build_graph("my-app")

        # Act
        result = resolver.find_root("my-app")

        # Assert
        assert result is not None
        assert result.name == "my-app"

    def test_returns_none_for_missing_root(self):
        """Test find_root returns None when no matching key exists."""
        # Arrange
        resolver = DummyResolver(_make_lockfile(_pkg("my-app", "1.0.0")))
        resolver.build_graph("my-app")

        # Act
        result = resolver.find_root("other-app")

        # Assert
        assert result is None


# ============================================================================
# Test GraphExporter
# ============================================================================


class TestGraphExporter:
    """Tests for GraphExporter dict serialization."""

    def test_export_single_node(self):
        """Test exporting a single dependency with no children."""
        # Arrange
        dep = Dependency(name="lib", version_installed="1.0.0", canonical_name="lib")
        exporter = GraphExporter(dep)

        # Act
        result = exporter.export()

        # Assert
        assert result["name"] == "lib"
        assert result["version_installed"] == "1.0.0"
        assert result["dependencies"] == []

    def test_export_includes_children(self, simple_lockfile):
        """Test exported dict contains nested dependencies."""
        # Arrange
        resolver = DummyResolver(simple_lockfile)
        root = resolver.build_graph("my-app")
        assert root is not None
        exporter = GraphExporter(root)

        # Act
        result = exporter.export()

        # Assert
        child_names = [d["name"] for d in result["dependencies"]]
        assert "requests" in child_names
        assert "click" in child_names

    def test_export_transitive_chain(self, transitive_lockfile):
        """Test exported dict preserves transitive dependency chain."""
        # Arrange
        resolver = DummyResolver(transitive_lockfile)
        root = resolver.build_graph("my-app")
        assert root is not None
        exporter = GraphExporter(root)

        # Act
        result = exporter.export()

        # Assert
        requests_dict = next(d for d in result["dependencies"] if d["name"] == "requests")
        transitive_names = [d["name"] for d in requests_dict["dependencies"]]
        assert "urllib3" in transitive_names
        assert "certifi" in transitive_names

    def test_export_handles_circular_refs(self, circular_lockfile):
        """Test that circular dependencies produce a ref marker instead of recursion."""
        # Arrange
        resolver = DummyResolver(circular_lockfile)
        root = resolver.build_graph("my-app")
        assert root is not None
        exporter = GraphExporter(root)

        # Act
        result = exporter.export()

        # Assert — follow the chain until the back-reference
        pkg_a = next(d for d in result["dependencies"] if d["name"] == "pkg-a")
        pkg_b = next(d for d in pkg_a["dependencies"] if d["name"] == "pkg-b")
        back_ref = next(d for d in pkg_b["dependencies"] if d["key"] == frozenset(["pkg-a", "1.0.0"]))
        assert back_ref["ref"] == "already_defined"

    def test_export_clears_visited_between_calls(self, simple_lockfile):
        """Test that calling export() twice produces identical results."""
        # Arrange
        resolver = DummyResolver(simple_lockfile)
        root = resolver.build_graph("my-app")
        assert root is not None
        exporter = GraphExporter(root)

        # Act
        first = exporter.export()
        second = exporter.export()

        # Assert
        assert first == second

    def test_export_includes_metadata_fields(self):
        """Test exported dict includes source, marker, version_defined, and key."""
        # Arrange
        dep = Dependency(
            name="lib",
            version_installed="1.0.0",
            canonical_name="lib",
            version_defined=">=1.0",
            source="https://pypi.org",
            required_engine='python_version >= "3.11"',
        )
        exporter = GraphExporter(dep)

        # Act
        result = exporter.export()

        # Assert
        assert result["key"] == frozenset(["lib", "1.0.0"])
        assert result["version_defined"] == ">=1.0"
        assert result["source"] == "https://pypi.org"
        assert result["marker"] == 'python_version >= "3.11"'


# ============================================================================
# Test GraphExporter.descendant_counts
# ============================================================================


class TestDescendantCounts:
    """Tests for GraphExporter.descendant_counts unique-descendant counting."""

    def test_linear_chain_counts(self):
        """Test a straight A -> B -> C chain counts descendants at each level (TODO.md Step 1: A=2, B=1, C=0)."""
        # Arrange
        lockfile = _make_lockfile(
            _pkg("my-app", "1.0.0", deps=[_dep("a", "1.0.0")]),
            _pkg("a", "1.0.0", deps=[_dep("b", "1.0.0")]),
            _pkg("b", "1.0.0", deps=[_dep("c", "1.0.0")]),
            _pkg("c", "1.0.0"),
        )
        resolver = DummyResolver(lockfile)
        root = resolver.build_graph("my-app")
        assert root is not None
        exporter = GraphExporter(root)

        # Act
        counts = exporter.descendant_counts()

        # Assert
        assert counts == {"a": 2, "b": 1, "c": 0}

    def test_diamond_counts_shared_descendant_once(self):
        """Test a diamond (A->B, A->C, B->D, C->D) counts the shared descendant once (TODO.md Step 1: A=3)."""
        # Arrange
        lockfile = _make_lockfile(
            _pkg("my-app", "1.0.0", deps=[_dep("a", "1.0.0")]),
            _pkg("a", "1.0.0", deps=[_dep("b", "1.0.0"), _dep("c", "1.0.0")]),
            _pkg("b", "1.0.0", deps=[_dep("d", "1.0.0")]),
            _pkg("c", "1.0.0", deps=[_dep("d", "1.0.0")]),
            _pkg("d", "1.0.0"),
        )
        resolver = DummyResolver(lockfile)
        root = resolver.build_graph("my-app")
        assert root is not None
        exporter = GraphExporter(root)

        # Act
        counts = exporter.descendant_counts()

        # Assert — D is reachable via both B and C but counted once in A's set
        assert counts == {"a": 3, "b": 1, "c": 1, "d": 0}

    def test_cycle_resolves_without_recursion_error(self, circular_lockfile):
        """Test a circular dependency (pkg-a -> pkg-b -> pkg-a) resolves without raising."""
        # Arrange
        resolver = DummyResolver(circular_lockfile)
        root = resolver.build_graph("my-app")
        assert root is not None
        exporter = GraphExporter(root)

        # Act
        counts = exporter.descendant_counts()

        # Assert — the back-edge contributes only its own name, not a further expansion
        assert counts == {"pkg-a": 2, "pkg-b": 1}

    def test_excludes_optional_roots_by_default(self, optional_deps_lockfile):
        """Test optional (dev/docs) roots are excluded unless requested."""
        # Arrange
        resolver = DummyResolver(optional_deps_lockfile)
        root = resolver.build_graph("my-app")
        assert root is not None
        exporter = GraphExporter(root)

        # Act
        counts = exporter.descendant_counts()

        # Assert
        assert "pytest" not in counts
        assert "sphinx" not in counts
        # Counter yields 0 for an unreachable package without inserting it, so callers
        # can index directly instead of guarding every lookup with .get(name, 0)
        assert counts["pytest"] == 0
        assert "pytest" not in counts

    def test_includes_optional_roots_when_requested(self, optional_deps_lockfile):
        """Test optional (dev/docs) roots are included when requested."""
        # Arrange
        resolver = DummyResolver(optional_deps_lockfile)
        root = resolver.build_graph("my-app")
        assert root is not None
        exporter = GraphExporter(root)

        # Act
        counts = exporter.descendant_counts(include_optional_roots=True)

        # Assert
        assert counts["pytest"] == 0
        assert counts["sphinx"] == 0

    def test_optional_edges_below_root_are_not_followed(self):
        """Test a transitive package's own optional deps never count, even with optional roots on."""
        # Arrange — "b" is a dev dep of "a", not of the root
        lockfile = _make_lockfile(
            _pkg("my-app", "1.0.0", deps=[_dep("a", "1.0.0")]),
            _pkg("a", "1.0.0", optional_deps={"dev": [_dep("b", "1.0.0")]}),
            _pkg("b", "1.0.0"),
        )
        resolver = DummyResolver(lockfile)
        root = resolver.build_graph("my-app")
        assert root is not None
        exporter = GraphExporter(root)

        # Act
        counts = exporter.descendant_counts(include_optional_roots=True)

        # Assert — include_optional_roots widens the roots only, never the edges walked below them
        assert counts == {"a": 0}
        assert "b" not in counts

    def test_root_without_dependencies_returns_empty(self):
        """Test a project with no dependencies yields no counts."""
        # Arrange
        lockfile = _make_lockfile(_pkg("my-app", "1.0.0"))
        resolver = DummyResolver(lockfile)
        root = resolver.build_graph("my-app")
        assert root is not None
        exporter = GraphExporter(root)

        # Act
        counts = exporter.descendant_counts()

        # Assert
        assert counts == {}

    def test_shared_subtree_across_two_roots(self):
        """Test a subtree reachable from two direct roots is counted for both, walked once."""
        # Arrange
        lockfile = _make_lockfile(
            _pkg("my-app", "1.0.0", deps=[_dep("a", "1.0.0"), _dep("c", "1.0.0")]),
            _pkg("a", "1.0.0", deps=[_dep("shared", "1.0.0")]),
            _pkg("c", "1.0.0", deps=[_dep("shared", "1.0.0")]),
            _pkg("shared", "1.0.0", deps=[_dep("leaf", "1.0.0")]),
            _pkg("leaf", "1.0.0"),
        )
        resolver = DummyResolver(lockfile)
        root = resolver.build_graph("my-app")
        assert root is not None
        exporter = GraphExporter(root)

        # Act
        counts = exporter.descendant_counts()

        # Assert — "c" still sees the full subtree even though "a"'s walk discovered it first
        assert counts == {"a": 2, "c": 2, "shared": 1, "leaf": 0}

    def test_direct_root_that_is_also_a_transitive_dependency(self):
        """Test a direct dependency also reachable beneath another direct dependency."""
        # Arrange — "b" is both a root and a child of "a"
        lockfile = _make_lockfile(
            _pkg("my-app", "1.0.0", deps=[_dep("a", "1.0.0"), _dep("b", "1.0.0")]),
            _pkg("a", "1.0.0", deps=[_dep("b", "1.0.0")]),
            _pkg("b", "1.0.0", deps=[_dep("leaf", "1.0.0")]),
            _pkg("leaf", "1.0.0"),
        )
        resolver = DummyResolver(lockfile)
        root = resolver.build_graph("my-app")
        assert root is not None
        exporter = GraphExporter(root)

        # Act
        counts = exporter.descendant_counts()

        # Assert — "b" is skipped as a root (already discovered) but keeps its own count
        assert counts == {"a": 2, "b": 1, "leaf": 0}

    def test_three_node_cycle_resolves(self):
        """Test a longer cycle (A -> B -> C -> A) terminates and counts each node once."""
        # Arrange
        lockfile = _make_lockfile(
            _pkg("my-app", "1.0.0", deps=[_dep("pkg-a", "1.0.0")]),
            _pkg("pkg-a", "1.0.0", deps=[_dep("pkg-b", "1.0.0")]),
            _pkg("pkg-b", "1.0.0", deps=[_dep("pkg-c", "1.0.0")]),
            _pkg("pkg-c", "1.0.0", deps=[_dep("pkg-a", "1.0.0")]),
        )
        resolver = DummyResolver(lockfile)
        root = resolver.build_graph("my-app")
        assert root is not None
        exporter = GraphExporter(root)

        # Act
        counts = exporter.descendant_counts()

        # Assert — each node reaches the other two plus itself through the back-edge
        assert counts == {"pkg-a": 3, "pkg-b": 2, "pkg-c": 1}

    def test_self_dependency_does_not_hang(self):
        """Test a package depending on itself terminates."""
        # Arrange
        lockfile = _make_lockfile(
            _pkg("my-app", "1.0.0", deps=[_dep("a", "1.0.0")]),
            _pkg("a", "1.0.0", deps=[_dep("a", "1.0.0")]),
        )
        resolver = DummyResolver(lockfile)
        root = resolver.build_graph("my-app")
        assert root is not None
        exporter = GraphExporter(root)

        # Act
        counts = exporter.descendant_counts()

        # Assert — the self-edge contributes only its own name, matching the cycle contract
        assert counts == {"a": 1}

    def test_deep_chain_exceeds_recursion_limit(self):
        """Test a chain deeper than the recursion limit resolves (regression: the walk is iterative)."""
        # Arrange — a recursive implementation raises RecursionError well before this depth
        depth = sys.getrecursionlimit() * 2
        packages = [_pkg("my-app", "1.0.0", deps=[_dep("p0", "1.0.0")])]
        packages += [_pkg(f"p{i}", "1.0.0", deps=[_dep(f"p{i + 1}", "1.0.0")]) for i in range(depth - 1)]
        packages.append(_pkg(f"p{depth - 1}", "1.0.0"))
        resolver = DummyResolver(_make_lockfile(*packages))
        root = resolver.build_graph("my-app")
        assert root is not None
        exporter = GraphExporter(root)

        # Act
        counts = exporter.descendant_counts()

        # Assert
        assert counts["p0"] == depth - 1
        assert counts[f"p{depth - 1}"] == 0
