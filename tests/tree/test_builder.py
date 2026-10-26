"""Tests for LockfileTreeBuilder: registering nodes and linking requirement edges."""

import pytest

from ossiq.domain.project import IncomingEdge
from tests.tree.helpers import (
    DummyBuilder,
    graph_of,
    lock_dep,
    lock_edge,
    lock_pkg,
    make_lockfile,
)


@pytest.fixture
def simple_lockfile():
    """Lockfile with a root package and two direct dependencies."""
    return make_lockfile(
        lock_pkg("my-app", "1.0.0", deps=[lock_dep("requests", "2.31.0"), lock_dep("click", "8.1.7")]),
        lock_pkg("requests", "2.31.0"),
        lock_pkg("click", "8.1.7"),
    )


@pytest.fixture
def transitive_lockfile():
    """Lockfile with transitive (nested) dependencies."""
    return make_lockfile(
        lock_pkg("my-app", "1.0.0", deps=[lock_dep("requests", "2.31.0")]),
        lock_pkg("requests", "2.31.0", deps=[lock_dep("urllib3", "2.1.0"), lock_dep("certifi", "2024.2.2")]),
        lock_pkg("urllib3", "2.1.0"),
        lock_pkg("certifi", "2024.2.2"),
    )


@pytest.fixture
def optional_deps_lockfile():
    """Lockfile with optional dependency groups."""
    return make_lockfile(
        lock_pkg(
            "my-app",
            "1.0.0",
            deps=[lock_dep("requests", "2.31.0")],
            optional_deps={"dev": [lock_dep("pytest", "8.0.0")], "docs": [lock_dep("sphinx", "7.2.0")]},
        ),
        lock_pkg("requests", "2.31.0"),
        lock_pkg("pytest", "8.0.0"),
        lock_pkg("sphinx", "7.2.0"),
    )


@pytest.fixture
def circular_lockfile():
    """Lockfile with circular dependencies (A -> B -> A)."""
    return make_lockfile(
        lock_pkg("my-app", "1.0.0", deps=[lock_dep("pkg-a", "1.0.0")]),
        lock_pkg("pkg-a", "1.0.0", deps=[lock_dep("pkg-b", "2.0.0")]),
        lock_pkg("pkg-b", "2.0.0", deps=[lock_dep("pkg-a", "1.0.0")]),
    )


class TestBuildGraph:
    """Tests for the two-pass graph construction in LockfileTreeBuilder."""

    def test_returns_root_node(self, simple_lockfile):
        """Test build_graph returns the correct root dependency."""
        # Arrange
        builder = DummyBuilder(simple_lockfile)

        # Act
        root = builder.build_graph("my-app")

        # Assert
        assert root is not None
        assert root.name == "my-app"
        assert root.version_installed == "1.0.0"

    def test_returns_none_for_missing_root(self, simple_lockfile):
        """Test build_graph returns None when root package is not found."""
        # Arrange
        builder = DummyBuilder(simple_lockfile)

        # Act
        root = builder.build_graph("nonexistent")

        # Assert
        assert root is None

    def test_links_direct_dependencies(self, simple_lockfile):
        """Test that direct dependencies are linked to the root node."""
        # Arrange
        builder = DummyBuilder(simple_lockfile)

        # Act
        root = builder.build_graph("my-app")

        # Assert
        assert root is not None
        assert "requests" in root.dependencies
        assert "click" in root.dependencies

    def test_links_transitive_dependencies(self, transitive_lockfile):
        """Test that transitive dependencies are linked through the chain."""
        # Arrange
        builder = DummyBuilder(transitive_lockfile)

        # Act
        root = builder.build_graph("my-app")

        # Assert
        assert root is not None
        requests = root.dependencies["requests"]
        assert requests is not None
        assert "urllib3" in requests.dependencies
        assert "certifi" in requests.dependencies

    def test_edges_record_which_parent_asked_for_each_spec(self, transitive_lockfile):
        """Every incoming edge keeps its requirer next to the spec, in parent order."""
        # Arrange
        builder = DummyBuilder(transitive_lockfile)

        # Act
        root = builder.build_graph("my-app")

        # Assert
        assert root is not None
        urllib3 = root.dependencies["requests"].dependencies["urllib3"]
        assert urllib3.parent_edges == [IncomingEdge("requests", "2.31.0", "2.1.0")]
        assert urllib3.parent_constraints == ["2.1.0"]

    def test_transitive_deps_not_on_root(self, transitive_lockfile):
        """Test that transitive dependencies are not direct children of root."""
        # Arrange
        builder = DummyBuilder(transitive_lockfile)

        # Act
        root = builder.build_graph("my-app")

        # Assert
        assert root is not None
        assert "urllib3" not in root.dependencies
        assert "certifi" not in root.dependencies

    def test_optional_dependencies_linked(self, optional_deps_lockfile):
        """Test that optional dependencies are placed in optional_dependencies dict."""
        # Arrange
        builder = DummyBuilder(optional_deps_lockfile)

        # Act
        root = builder.build_graph("my-app")

        # Assert
        assert root is not None
        assert "pytest" in root.optional_dependencies
        assert "sphinx" in root.optional_dependencies

    def test_optional_dependencies_have_categories(self, optional_deps_lockfile):
        """Test that optional dependencies receive their category label."""
        # Arrange
        builder = DummyBuilder(optional_deps_lockfile)

        # Act
        root = builder.build_graph("my-app")

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
        builder = DummyBuilder(optional_deps_lockfile)

        # Act
        root = builder.build_graph("my-app")

        # Assert
        assert root is not None
        assert "requests" in root.dependencies
        assert "requests" not in root.optional_dependencies

    def test_circular_dependencies_do_not_loop(self, circular_lockfile):
        """Test that circular dependencies are handled without infinite recursion."""
        # Arrange
        builder = DummyBuilder(circular_lockfile)

        # Act
        root = builder.build_graph("my-app")

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
        lockfile = make_lockfile(
            lock_pkg("my-app", "1.0.0", deps=[lock_dep("lib", ">=2.0")]),
            lock_pkg("lib", "2.3.0"),
        )
        builder = DummyBuilder(lockfile)

        # Act
        root = builder.build_graph("my-app")

        # Assert
        assert root is not None
        lib = root.dependencies["lib"]
        assert lib is not None
        assert lib.version_installed == "2.3.0"
        assert lib.version_defined == ">=2.0"

    def test_version_defined_not_overwritten_when_matches_installed(self):
        """Test version_defined is not changed when constraint matches installed version."""
        # Arrange
        lockfile = make_lockfile(
            lock_pkg("my-app", "1.0.0", deps=[lock_dep("lib", "2.3.0")]),
            lock_pkg("lib", "2.3.0"),
        )
        builder = DummyBuilder(lockfile)

        # Act
        root = builder.build_graph("my-app")

        # Assert
        assert root is not None
        lib = root.dependencies["lib"]
        assert lib is not None
        assert lib.version_defined is None

    def test_version_constraint_declared_survives_multi_parent_processing_regardless_of_order(self):
        """version_constraint_declared always reflects the root manifest's own spec, whichever
        order the linking pass processes competing parents in - unlike version_defined, the internal
        last-writer-wins accumulator, which is free to vary with processing order."""
        root_first_lockfile = make_lockfile(
            lock_pkg("my-app", "1.0.0", deps=[lock_dep("lib", "~1.0.0")]),
            lock_pkg("lib", "1.0.5"),
            lock_pkg("other-pkg", "1.0.0", deps=[lock_dep("lib", "^1.0.0")]),
        )
        root_last_lockfile = make_lockfile(
            lock_pkg("other-pkg", "1.0.0", deps=[lock_dep("lib", "^1.0.0")]),
            lock_pkg("lib", "1.0.5"),
            lock_pkg("my-app", "1.0.0", deps=[lock_dep("lib", "~1.0.0")]),
        )

        for lockfile in (root_first_lockfile, root_last_lockfile):
            builder = DummyBuilder(lockfile)
            root = builder.build_graph("my-app")
            assert root is not None
            lib = root.dependencies["lib"]
            assert lib is not None
            assert lib.version_constraint_declared == "~1.0.0"

    def test_pinia_vue_router_regression_declared_constraint_survives_peer_override(self):
        """Regression test for the PLAN.md pinia/vue-router example: package.json declares pinia
        "~3.0.4"; vue-router's own dependency on pinia ("^3.0.4") must not clobber the declared
        value, even though it still wins the internal version_defined accumulator."""
        lockfile = make_lockfile(
            lock_pkg("my-app", "1.0.0", deps=[lock_dep("pinia", "~3.0.4"), lock_dep("vue-router", "4.0.0")]),
            lock_pkg("pinia", "3.0.4"),
            lock_pkg("vue-router", "4.0.0", deps=[lock_dep("pinia", "^3.0.4")]),
        )
        builder = DummyBuilder(lockfile)
        root = builder.build_graph("my-app")

        assert root is not None
        pinia = root.dependencies["pinia"]
        assert pinia is not None
        assert pinia.version_defined == "^3.0.4"
        assert pinia.version_constraint_declared == "~3.0.4"

    def test_pure_transitive_dep_has_no_declared_constraint(self):
        """A pure transitive dependency (no root-manifest entry) gets version_constraint_declared
        None; parent_constraints keeps tracking why it's bounded."""
        lockfile = make_lockfile(
            lock_pkg("my-app", "1.0.0", deps=[lock_dep("requests", "2.31.0")]),
            lock_pkg("requests", "2.31.0", deps=[lock_dep("urllib3", ">=2.0")]),
            lock_pkg("urllib3", "2.1.0"),
        )
        builder = DummyBuilder(lockfile)
        root = builder.build_graph("my-app")

        assert root is not None
        urllib3 = root.dependencies["requests"].dependencies["urllib3"]
        assert urllib3 is not None
        assert urllib3.version_constraint_declared is None
        assert urllib3.parent_constraints == [">=2.0"]

    def test_registry_populated(self, simple_lockfile):
        """Test that all packages are registered in the builder registry."""
        # Arrange
        builder = DummyBuilder(simple_lockfile)

        # Act
        builder.build_graph("my-app")

        # Assert
        assert len(builder.registry) == 3
        assert ("my-app", "1.0.0") in builder.registry
        assert ("requests", "2.31.0") in builder.registry
        assert ("click", "8.1.7") in builder.registry

    def test_empty_lockfile(self):
        """Test build_graph with no packages returns None."""
        # Arrange
        builder = DummyBuilder({"package": []})

        # Act
        root = builder.build_graph("anything")

        # Assert
        assert root is None

    def test_metadata_preserved(self):
        """Test that source and marker metadata are preserved on nodes."""
        # Arrange
        lockfile = make_lockfile(
            lock_pkg("my-app", "1.0.0", deps=[lock_dep("lib", "1.0.0")]),
            lock_pkg("lib", "1.0.0", source={"registry": "https://pypi.org"}, marker='python_version >= "3.11"'),
        )
        builder = DummyBuilder(lockfile)

        # Act
        root = builder.build_graph("my-app")

        # Assert
        assert root is not None
        lib = root.dependencies["lib"]
        assert lib is not None
        assert lib.source == "https://pypi.org"
        assert lib.required_engine == 'python_version >= "3.11"'


class TestMatchChild:
    """Tests for the match_child lookup logic."""

    def test_exact_match(self):
        """Test match_child finds a package by exact name@version key."""
        # Arrange
        builder = DummyBuilder(make_lockfile(lock_pkg("lib", "1.0.0")))
        builder.build_graph("lib")

        # Act
        result = builder.match_child("lib", "1.0.0")

        # Assert
        assert result is not None
        assert result.name == "lib" and result.version_installed == "1.0.0"

    def test_fallback_by_name(self):
        """Test match_child falls back to name-only lookup when version does not match."""
        # Arrange
        builder = DummyBuilder(make_lockfile(lock_pkg("lib", "1.0.0")))
        builder.build_graph("lib")

        # Act
        result = builder.match_child("lib", ">=1.0")

        # Assert
        assert result is not None
        assert result.name == "lib"

    def test_no_version_constraint(self):
        """Test match_child finds package when no version constraint is given."""
        # Arrange
        builder = DummyBuilder(make_lockfile(lock_pkg("lib", "1.0.0")))
        builder.build_graph("lib")

        # Act
        result = builder.match_child("lib")

        # Assert
        assert result is not None

    def test_returns_none_for_unknown_package(self):
        """Test match_child returns None for a package not in the registry."""
        # Arrange
        builder = DummyBuilder(make_lockfile(lock_pkg("lib", "1.0.0")))
        builder.build_graph("lib")

        # Act
        result = builder.match_child("nonexistent", "1.0.0")

        # Assert
        assert result is None

    def test_parent_data_does_not_change_a_name_based_lookup(self):
        """Formats with no recorded placement ignore the parent entry they are handed."""
        # Arrange
        builder = DummyBuilder(make_lockfile(lock_pkg("lib", "1.0.0")))
        builder.build_graph("lib")

        # Act
        result = builder.match_child("lib", ">=1.0", {"name": "someone-else", "version": "9.9.9"})

        # Assert
        assert result is builder.match_child("lib", ">=1.0")


class TestFirstNamed:
    """Tests for the first_named lookup."""

    def test_finds_root_by_name_prefix(self):
        """Test first_named locates a node by name."""
        # Arrange
        builder = DummyBuilder(make_lockfile(lock_pkg("my-app", "1.0.0")))
        builder.build_graph("my-app")

        # Act
        result = builder.first_named("my-app")

        # Assert
        assert result is not None
        assert result.name == "my-app"

    def test_returns_none_for_missing_root(self):
        """Test first_named returns None when no matching key exists."""
        # Arrange
        builder = DummyBuilder(make_lockfile(lock_pkg("my-app", "1.0.0")))
        builder.build_graph("my-app")

        # Act
        result = builder.first_named("other-app")

        # Assert
        assert result is None


class TestEdgeExtras:
    def test_an_edge_that_enables_an_extra_records_it_on_the_target(self, extras_lockfile):
        root = graph_of(extras_lockfile)

        assert root.dependencies["uvicorn"].extras == ["standard"]

    def test_a_target_no_edge_enables_an_extra_on_has_none(self, extras_lockfile):
        root = graph_of(extras_lockfile)

        assert root.dependencies["gunicorn"].extras is None

    def test_extras_from_every_edge_are_merged(self):
        lockfile = make_lockfile(
            lock_pkg(
                "my-app", "1.0.0", deps=[lock_edge("allauth", "65.19.4", "socialaccount"), lock_dep("other", "1.0.0")]
            ),
            lock_pkg("other", "1.0.0", deps=[lock_edge("allauth", "65.19.4", "headless")]),
            lock_pkg("allauth", "65.19.4"),
        )

        root = graph_of(lockfile)

        assert root.dependencies["allauth"].extras == ["headless", "socialaccount"]

    def test_a_builder_that_does_not_read_extras_leaves_them_unset(self, extras_lockfile):
        root = graph_of(extras_lockfile, DummyBuilder)

        assert root.dependencies["uvicorn"].extras is None
