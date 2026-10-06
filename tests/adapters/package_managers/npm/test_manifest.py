# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for npm/manifest.py: dependencies and categories read from package.json alone, and npm aliases.
"""

import json
from pathlib import Path

import pytest

from ossiq.adapters.package_managers.api_npm import PackageManagerJsNpm
from ossiq.adapters.package_managers.npm.constants import CATEGORIES_DEV, CATEGORIES_OPTIONAL, CATEGORIES_PEER


# ============================================================================
# Test parse_package_json
# ============================================================================
class TestParsePackageJson:
    """Test suite for parse_package_json() method."""

    def test_parse_basic_dependencies(self, npm_project_with_lockfile, settings):
        """Test parsing main dependencies from package.json."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        with open(Path(npm_project_with_lockfile) / "package.json", encoding="utf-8") as f:
            project_data = json.load(f)

        dependency_tree = npm_manager.parse_package_json(project_data)

        # Main dependencies should contain express and lodash
        express = dependency_tree.dependencies["express"]
        lodash = dependency_tree.dependencies["lodash"]
        assert express is not None
        assert lodash is not None
        assert express.version_defined == "^4.18.0"
        assert lodash.version_defined == "~4.17.21"

        # Version normalization should strip modifiers
        assert express.version_installed == "4.18.0"
        assert lodash.version_installed == "4.17.21"

    def test_parses_all_non_production_categories(self, npm_project_with_lockfile, settings):
        """All non-production category sections land in optional_dependencies with the right category tag."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)
        with open(Path(npm_project_with_lockfile) / "package.json", encoding="utf-8") as f:
            project_data = json.load(f)

        opt = npm_manager.parse_package_json(project_data).optional_dependencies
        assert CATEGORIES_DEV in opt["jest"].categories
        assert CATEGORIES_DEV in opt["eslint"].categories
        assert CATEGORIES_OPTIONAL in opt["fsevents"].categories
        assert CATEGORIES_PEER in opt["react"].categories

    def test_parse_dual_category_dependencies(self, npm_project_dual_category_deps, settings):
        """
        Test dependencies that appear in multiple categories.

        lodash is both in dependencies and devDependencies.
        jest is both in devDependencies and peerDependencies.
        """
        npm_manager = PackageManagerJsNpm(npm_project_dual_category_deps, settings)

        with open(Path(npm_project_dual_category_deps) / "package.json", encoding="utf-8") as f:
            project_data = json.load(f)

        dependency_tree = npm_manager.parse_package_json(project_data)
        lodash_package = dependency_tree.dependencies["lodash"]
        jest_package = dependency_tree.optional_dependencies["jest"]

        assert "jest" not in dependency_tree.dependencies
        # lodash should be in main dependencies (takes precedence)
        assert lodash_package is not None
        # lodash should also have dev category
        assert CATEGORIES_DEV in lodash_package.categories

        # jest should have both dev and peer categories
        assert CATEGORIES_DEV in jest_package.categories
        assert CATEGORIES_PEER in jest_package.categories

    def test_parse_empty_dependencies(self, temp_project_dir, settings):
        """Test parsing when project has no dependencies."""
        package_json_path = Path(temp_project_dir) / "package.json"
        package_json_path.write_text('{"name": "empty-project", "version": "1.0.0"}')

        npm_manager = PackageManagerJsNpm(temp_project_dir, settings)

        with open(package_json_path, encoding="utf-8") as f:
            project_data = json.load(f)

        dependency_tree = npm_manager.parse_package_json(project_data)

        assert len(dependency_tree.dependencies) == 0
        assert len(dependency_tree.optional_dependencies) == 0


# ============================================================================
# Fixtures: aliases and overrides
# ============================================================================
@pytest.fixture
def npm_project_with_aliases(temp_project_dir):
    """
    Create a project whose lockfile contains npm alias packages.

    The lockfile intentionally has 'name' fields that differ from the path
    component (e.g. node_modules/lodash-tilde has name="lodash"), verifying
    that the adapter uses the path component as identity.
    """
    package_json_path = Path(temp_project_dir) / "package.json"
    lockfile_path = Path(temp_project_dir) / "package-lock.json"

    package_json_content = {
        "name": "alias-test-project",
        "version": "1.0.0",
        "dependencies": {
            "lodash-tilde": "npm:lodash@~4.17.0",
            "lodash-caret": "npm:lodash@^4.17.0",
            "chalk-legacy": "npm:chalk@4.1.2",
        },
    }
    package_json_path.write_text(json.dumps(package_json_content, indent=2))

    lockfile_content = {
        "name": "alias-test-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "alias-test-project",
                "version": "1.0.0",
                "dependencies": {
                    "lodash-tilde": "npm:lodash@~4.17.0",
                    "lodash-caret": "npm:lodash@^4.17.0",
                    "chalk-legacy": "npm:chalk@4.1.2",
                },
            },
            # Aliases: 'name' differs from path component
            "node_modules/lodash-tilde": {"name": "lodash", "version": "4.17.23"},
            "node_modules/lodash-caret": {"name": "lodash", "version": "4.17.23"},
            "node_modules/chalk-legacy": {"name": "chalk", "version": "4.1.2"},
        },
    }
    lockfile_path.write_text(json.dumps(lockfile_content, indent=2))

    return temp_project_dir


# ============================================================================
# Test PackageManagerJsNpm.parse_npm_alias helper
# ============================================================================
class TestParseNpmAlias:
    """Test suite for the _parse_npm_alias module-level helper."""

    @pytest.mark.parametrize(
        "version,expected_name,expected_constraint",
        [
            ("npm:lodash@~4.17.0", "lodash", "~4.17.0"),
            ("npm:chalk@4.1.2", "chalk", "4.1.2"),
            ("npm:@scope/pkg@^1.0.0", "@scope/pkg", "^1.0.0"),
            ("^4.18.0", None, "^4.18.0"),
        ],
    )
    def test_parses_alias(self, version, expected_name, expected_constraint):
        """Test that alias specifiers are parsed and plain versions pass through."""
        canonical_name, constraint = PackageManagerJsNpm.parse_npm_alias(version)
        assert canonical_name == expected_name
        assert constraint == expected_constraint


# ============================================================================
# Test NPM alias packages (lockfile path)
# ============================================================================
class TestNpmAliases:
    """Test suite for npm alias packages (npm:pkg@version specifiers in lockfile)."""

    def test_alias_packages_resolved_in_tree(self, npm_project_with_aliases, settings):
        """Alias packages appear as direct deps with correct version_installed, version_defined, and canonical_name."""
        npm_manager = PackageManagerJsNpm(npm_project_with_aliases, settings)
        project = npm_manager.project_info()
        deps = project.dependency_tree.dependencies

        assert "lodash-tilde" in deps
        assert "lodash-caret" in deps
        assert "chalk-legacy" in deps

        assert deps["lodash-tilde"].version_installed == "4.17.23"
        assert deps["lodash-caret"].version_installed == "4.17.23"
        assert deps["chalk-legacy"].version_installed == "4.1.2"

        assert deps["lodash-tilde"].version_defined == "npm:lodash@~4.17.0"
        assert deps["lodash-caret"].version_defined == "npm:lodash@^4.17.0"
        assert deps["chalk-legacy"].version_defined == "npm:chalk@4.1.2"

        assert deps["lodash-tilde"].canonical_name == "lodash"
        assert deps["lodash-caret"].canonical_name == "lodash"
        assert deps["chalk-legacy"].canonical_name == "chalk"

    def test_two_aliases_for_same_package_are_separate_entries(self, npm_project_with_aliases, settings):
        """Two aliases pointing to the same package resolve as distinct Dependency objects."""
        npm_manager = PackageManagerJsNpm(npm_project_with_aliases, settings)
        project = npm_manager.project_info()
        tilde = project.dependency_tree.dependencies["lodash-tilde"]
        caret = project.dependency_tree.dependencies["lodash-caret"]

        assert tilde is not caret
        assert tilde.version_defined != caret.version_defined


# ============================================================================
# Ordering and ownership semantics that callers observe
# ============================================================================
class TestManifestOnlyOrdering:
    """parse_package_json() without a lockfile: the order of `categories` and of
    `optional_dependencies` is part of the output, and differs from the lockfile path."""

    def test_categories_are_listed_dev_then_peer_then_optional(self, settings, temp_project_dir):
        manifest = {
            "name": "app",
            "version": "1.0.0",
            "devDependencies": {"o": "^1.0.0"},
            "peerDependencies": {"o": "^1.0.0"},
            "optionalDependencies": {"o": "^1.0.0"},
        }

        tree = PackageManagerJsNpm(temp_project_dir, settings).parse_package_json(manifest)

        assert tree.optional_dependencies["o"].categories == [CATEGORIES_DEV, CATEGORIES_PEER, CATEGORIES_OPTIONAL]

    def test_optional_dependencies_follow_section_then_file_order(self, settings, temp_project_dir):
        manifest = {
            "name": "app",
            "version": "1.0.0",
            "dependencies": {"prod": "^1.0.0"},
            "devDependencies": {"d2": "^1.0.0", "prod": "^1.0.0", "d1": "^1.0.0"},
            "peerDependencies": {"p": "^1.0.0", "d1": "^1.0.0"},
            "optionalDependencies": {"o": "^1.0.0", "p": "^1.0.0"},
        }

        tree = PackageManagerJsNpm(temp_project_dir, settings).parse_package_json(manifest)

        assert list(tree.dependencies) == ["prod"]
        assert tree.dependencies["prod"].categories == [CATEGORIES_DEV]
        assert list(tree.optional_dependencies) == ["d2", "d1", "p", "o"]
