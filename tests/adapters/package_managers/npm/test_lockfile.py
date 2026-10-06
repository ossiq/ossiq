# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for npm/lockfile.py: the dependency graph built from package-lock.json, edge resolution
between nested copies, and constraint classification.
"""

import json
from pathlib import Path

import pytest

from ossiq.adapters.package_managers.api_npm import PackageManagerJsNpm
from ossiq.adapters.package_managers.npm.lockfile import NPMResolverV3
from ossiq.domain.common import ConstraintType, ProjectPackagesRegistry
from ossiq.domain.project import IncomingEdge
from ossiq.solver.version_matchers import version_satisfies_constraint
from tests.adapters.package_managers.npm.helpers import build_tree

TESTDATA_NPM = Path(__file__).parents[4] / "testdata" / "npm"


# ============================================================================
# Test edge resolution: which copy does a parent's requirement land on
# ============================================================================
def npm_lock(packages: dict) -> dict:
    """A minimal lockfile whose root entry is the one under key ''."""
    return {"name": "p", "lockfileVersion": 3, "packages": packages}


class TestNpmEdgeResolution:
    """npm lays the tree out so that Node's lookup from a parent finds the copy it was given."""

    def test_edge_lands_on_the_copy_the_parent_resolves_to(self):
        """eslint's ^10 requirement reaches the hoisted minimatch, not the nested copy that sorts first."""
        # Arrange: npm sorts lockfile keys, so editorconfig's nested copy precedes the hoisted one
        lock = npm_lock(
            {
                "": {"name": "p", "dependencies": {"eslint": "^10", "editorconfig": "^1"}},
                "node_modules/editorconfig": {"version": "1.0.7", "dependencies": {"minimatch": "^9.0.1"}},
                "node_modules/editorconfig/node_modules/minimatch": {"version": "9.0.9"},
                "node_modules/eslint": {"version": "10.2.0", "dependencies": {"minimatch": "^10.2.4"}},
                "node_modules/minimatch": {"version": "10.2.5"},
            }
        )

        # Act
        root = build_tree(lock)

        # Assert
        hoisted = root.dependencies["eslint"].dependencies["minimatch"]
        nested = root.dependencies["editorconfig"].dependencies["minimatch"]
        assert (hoisted.version_installed, hoisted.parent_constraints) == ("10.2.5", ["^10.2.4"])
        assert (nested.version_installed, nested.parent_constraints) == ("9.0.9", ["^9.0.1"])

    def test_copies_remember_which_parent_asked_for_what(self):
        """parent_edges carries the requirer next to the spec, which parent_constraints drops."""
        # Arrange
        lock = npm_lock(
            {
                "": {"name": "p", "dependencies": {"eslint": "^10", "editorconfig": "^1"}},
                "node_modules/editorconfig": {"version": "1.0.7", "dependencies": {"minimatch": "^9.0.1"}},
                "node_modules/editorconfig/node_modules/minimatch": {"version": "9.0.9"},
                "node_modules/eslint": {"version": "10.2.0", "dependencies": {"minimatch": "^10.2.4"}},
                "node_modules/minimatch": {"version": "10.2.5"},
            }
        )

        # Act
        root = build_tree(lock)

        # Assert
        assert root.dependencies["eslint"].dependencies["minimatch"].parent_edges == [
            IncomingEdge("eslint", "10.2.0", "^10.2.4")
        ]
        assert root.dependencies["editorconfig"].dependencies["minimatch"].parent_edges == [
            IncomingEdge("editorconfig", "1.0.7", "^9.0.1")
        ]

    def test_inner_copy_shadows_outer_copies_across_three_levels(self):
        """Each parent resolves to the nearest enclosing node_modules that holds the name."""
        # Arrange
        lock = npm_lock(
            {
                "": {"name": "p", "dependencies": {"a": "^1", "x": "^1"}},
                "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^1", "x": "^2"}},
                "node_modules/a/node_modules/b": {"version": "1.0.0", "dependencies": {"c": "^1", "x": "^3"}},
                "node_modules/a/node_modules/b/node_modules/c": {"version": "1.0.0", "dependencies": {"x": "^3"}},
                "node_modules/a/node_modules/b/node_modules/x": {"version": "3.0.0"},
                "node_modules/a/node_modules/x": {"version": "2.0.0"},
                "node_modules/x": {"version": "1.0.0"},
            }
        )

        # Act
        root = build_tree(lock)

        # Assert
        a = root.dependencies["a"]
        b = a.dependencies["b"]
        c = b.dependencies["c"]
        assert root.dependencies["x"].version_installed == "1.0.0"
        assert a.dependencies["x"].version_installed == "2.0.0"
        assert b.dependencies["x"].version_installed == "3.0.0"
        assert c.dependencies["x"] is b.dependencies["x"]

    def test_scoped_package_parent_resolves_from_its_own_directory(self):
        """A nested `@scope/name` parent is one path segment pair, so it walks up past both."""
        # Arrange
        lock = npm_lock(
            {
                "": {"name": "p", "dependencies": {"a": "^1"}},
                "node_modules/a": {"version": "1.0.0", "dependencies": {"@s/inner": "^1"}},
                "node_modules/a/node_modules/@s/inner": {"version": "1.0.0", "dependencies": {"leaf": "^2"}},
                "node_modules/a/node_modules/leaf": {"version": "2.0.0"},
                "node_modules/leaf": {"version": "1.0.0"},
            }
        )

        # Act
        root = build_tree(lock)

        # Assert
        inner = root.dependencies["a"].dependencies["@s/inner"]
        assert inner.dependencies["leaf"].version_installed == "2.0.0"

    def test_alias_is_resolved_by_its_lockfile_key(self):
        """An alias is keyed by the name the dependent uses, so nested aliases resolve like any other copy."""
        # Arrange
        lock = npm_lock(
            {
                "": {"name": "p", "dependencies": {"a": "^1", "lodash-tilde": "npm:lodash@~4.17.0"}},
                "node_modules/a": {"version": "1.0.0", "dependencies": {"lodash-tilde": "npm:lodash@^4.0.0"}},
                "node_modules/a/node_modules/lodash-tilde": {"name": "lodash", "version": "4.0.1"},
                "node_modules/lodash-tilde": {"name": "lodash", "version": "4.17.23"},
            }
        )

        # Act
        root = build_tree(lock)

        # Assert
        assert root.dependencies["lodash-tilde"].version_installed == "4.17.23"
        nested = root.dependencies["a"].dependencies["lodash-tilde"]
        assert (nested.version_installed, nested.canonical_name) == ("4.0.1", "lodash")

    def test_peer_requirement_lands_on_the_copy_the_peer_resolves_to(self):
        """A peer is looked up from where its requirer sits, so the nested host takes the requirement."""
        # Arrange
        lock = npm_lock(
            {
                "": {"name": "p", "dependencies": {"host": "^2", "other": "^1"}},
                "node_modules/host": {"version": "2.0.0"},
                "node_modules/other": {"version": "1.0.0", "dependencies": {"plugin": "^1", "host": "^1"}},
                "node_modules/other/node_modules/host": {"version": "1.0.0"},
                "node_modules/other/node_modules/plugin": {"version": "1.0.0", "peerDependencies": {"host": "^1"}},
            }
        )

        # Act
        root = build_tree(lock)

        # Assert
        hoisted = root.dependencies["host"]
        nested = root.dependencies["other"].dependencies["host"]
        assert hoisted.peer_requirements == []
        assert [(r.requirer_name, r.spec) for r in nested.peer_requirements] == [("plugin", "^1")]
        assert nested.parent_edges[-1] == IncomingEdge("plugin", "1.0.0", "^1", is_peer=True)

    def test_entry_the_lookup_cannot_place_falls_back_to_matching_by_name(self):
        """A lockfile that doesn't follow the layout still links by name rather than dropping the edge."""
        # Arrange: x is nowhere on a's lookup path, only under an unrelated directory
        lock = npm_lock(
            {
                "": {"name": "p", "dependencies": {"a": "^1"}},
                "node_modules/a": {"version": "1.0.0", "dependencies": {"x": "^1"}},
                "node_modules/z/node_modules/x": {"version": "1.0.0"},
            }
        )

        # Act
        root = build_tree(lock)

        # Assert
        assert root.dependencies["a"].dependencies["x"].version_installed == "1.0.0"

    def test_peer_that_nothing_installed_links_nothing(self):
        """An optional peer npm left out of the tree adds no edge and no peer requirement."""
        # Arrange
        lock = npm_lock(
            {
                "": {"name": "p", "dependencies": {"a": "^1"}},
                "node_modules/a": {"version": "1.0.0", "peerDependencies": {"missing": "^1"}},
            }
        )

        # Act
        root = build_tree(lock)

        # Assert
        assert "missing" not in root.dependencies["a"].optional_dependencies

    @pytest.mark.parametrize("fixture", ["project1", "project3", "version-constrained"])
    def test_every_edge_in_a_real_lockfile_lands_on_a_copy_that_satisfies_it(self, fixture):
        """npm only installs a copy for an edge it satisfies, so no edge may end up on another copy."""
        # Arrange
        lock = json.loads((TESTDATA_NPM / fixture / "package-lock.json").read_text())
        resolver = NPMResolverV3(lock)

        # Act
        root = resolver.build_graph(lock["name"])

        # Assert
        unsatisfied = [
            (node.name, node.version_installed, edge.requirer_name, edge.spec)
            for node in resolver.registry.values()
            if node is not root
            for edge in node.parent_edges
            if not edge.spec.startswith("npm:")
            and not version_satisfies_constraint(node.version_installed, edge.spec, ProjectPackagesRegistry.NPM)
        ]
        assert unsatisfied == []

    def test_project3_keeps_each_react_is_copy_to_its_own_requirers(self):
        """rc-util 5 takes its nested react-is 18; prop-types and the rc-util 4 copies take the hoisted 16."""
        # Arrange
        lock = json.loads((TESTDATA_NPM / "project3" / "package-lock.json").read_text())
        resolver = NPMResolverV3(lock)

        # Act
        resolver.build_graph(lock["name"])

        # Assert
        nested = resolver.registry[frozenset(("react-is", "18.3.1"))]
        hoisted = resolver.registry[frozenset(("react-is", "16.13.1"))]
        assert nested.parent_constraints == ["^18.2.0"]
        assert set(hoisted.parent_constraints) == {"^16.13.1", "^16.12.0"}
        assert len(hoisted.parent_constraints) == 5

    def test_project3_keeps_each_color_copy_to_its_own_requirers(self):
        """form-render's color 3 is its own nested copy, apart from the hoisted color 4."""
        # Arrange
        lock = json.loads((TESTDATA_NPM / "project3" / "package-lock.json").read_text())
        resolver = NPMResolverV3(lock)

        # Act
        resolver.build_graph(lock["name"])

        # Assert
        assert resolver.registry[frozenset(("color", "3.2.1"))].parent_constraints == ["^3.1.2"]
        assert resolver.registry[frozenset(("color", "4.2.3"))].parent_constraints == ["^4.2.3"]


# ============================================================================
# Integration test against testdata/npm/project3 (real lockfile with aliases)
# ============================================================================
class TestNpmProject3Integration:
    """Integration tests using the real project3 lockfile (alias-heavy project)."""

    @pytest.fixture
    def project3_path(self):
        """Return path to testdata/npm/project3."""
        path = TESTDATA_NPM / "project3"
        if not path.exists():
            pytest.skip("testdata/npm/project3 not found")
        return str(path)

    def test_alias_packages_present_in_tree(self, project3_path, settings):
        """Test that all npm alias dependencies appear in the dependency tree."""
        # Arrange
        npm_manager = PackageManagerJsNpm(project3_path, settings)

        # Act
        project = npm_manager.project_info()
        deps = project.dependency_tree.dependencies

        # Assert — all aliases declared in package.json must be linked
        for alias in ["lodash-range-tilde", "lodash-range-caret", "ms-zero-caret", "ms-zero-tilde"]:
            assert alias in deps, f"Expected alias '{alias}' in dependency tree"

    def test_chalk_and_chalk_legacy_are_separate_entries(self, project3_path, settings):
        """Test that chalk and chalk-legacy coexist as separate dependencies."""
        # Arrange
        npm_manager = PackageManagerJsNpm(project3_path, settings)

        # Act
        project = npm_manager.project_info()
        deps = project.dependency_tree.dependencies

        # Assert — both the alias and the non-alias version must be present
        assert "chalk" in deps, "Expected 'chalk' (v5) in dependency tree"
        assert "chalk-legacy" in deps, "Expected 'chalk-legacy' alias in dependency tree"
        assert deps["chalk"] is not deps["chalk-legacy"]


# ============================================================================
# Test constraint classification for npm specifiers
# ============================================================================
class TestConstraintClassification:
    """Test that constraint_info.type is set correctly based on version specifiers."""

    @pytest.mark.parametrize(
        "dep_key,dep_section,expected_type",
        [
            ("express", "dependencies", ConstraintType.DECLARED),  # "^4.18.0"
            ("lodash", "dependencies", ConstraintType.DECLARED),  # "~4.17.21"
            ("jest", "optional_dependencies", ConstraintType.NARROWED),  # ">=29.0.0"
        ],
    )
    def test_constraint_type_from_specifier(
        self, dep_key, dep_section, expected_type, npm_project_with_lockfile, settings
    ):
        """Caret/tilde → DECLARED; comparison operator → NARROWED."""
        project = PackageManagerJsNpm(npm_project_with_lockfile, settings).project_info()
        dep = getattr(project.dependency_tree, dep_section)[dep_key]
        assert dep.constraint_info.type == expected_type

    def test_bare_exact_version_is_pinned(self, temp_project_dir, settings):
        """Bare x.y.z (no operator) should be PINNED."""
        pkg_json = Path(temp_project_dir) / "package.json"
        lockfile = Path(temp_project_dir) / "package-lock.json"
        pkg_json.write_text(
            json.dumps(
                {
                    "name": "pin-test",
                    "version": "1.0.0",
                    "dependencies": {"lodash": "4.17.21"},
                }
            )
        )
        lockfile.write_text(
            json.dumps(
                {
                    "name": "pin-test",
                    "version": "1.0.0",
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "pin-test", "version": "1.0.0", "dependencies": {"lodash": "4.17.21"}},
                        "node_modules/lodash": {"version": "4.17.21"},
                    },
                }
            )
        )
        project = PackageManagerJsNpm(temp_project_dir, settings).project_info()
        lodash = project.dependency_tree.dependencies["lodash"]
        assert lodash.constraint_info.type == ConstraintType.PINNED
