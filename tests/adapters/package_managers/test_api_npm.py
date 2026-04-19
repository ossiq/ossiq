# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for PackageManagerJsNpm adapter.

Tests focus on:
1. API sanity checks (static methods, initialization)
2. Package.json parsing (dependencies, devDependencies, etc.)
3. Lockfile parsing for NPM version 3
4. Parser selection logic
5. Project info extraction with and without lockfile
6. Error handling
7. npm alias packages (npm:pkg@version) and overrides
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from ossiq.adapters.package_managers.api_npm import (
    CATEGORIES_DEV,
    CATEGORIES_OPTIONAL,
    CATEGORIES_OVERRIDDEN,
    CATEGORIES_PEER,
    NPMResolverV3,
    PackageManagerJsNpm,
)
from ossiq.domain.common import ConstraintType, ProjectPackagesRegistry
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import NPM
from ossiq.settings import Settings

TESTDATA_NPM = Path(__file__).parents[3] / "testdata" / "npm"

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def settings():
    """Create Settings instance for testing."""
    return Settings()


@pytest.fixture
def temp_project_dir():
    """Create a temporary directory for test projects."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def npm_project_with_lockfile(temp_project_dir):
    """
    Create a temporary NPM project with package.json and package-lock.json files.

    Returns a project with:
    - Main dependencies: express, lodash
    - Dev dependencies: jest, eslint
    - Optional dependencies: fsevents
    - Peer dependencies: react
    """
    package_json_path = Path(temp_project_dir) / "package.json"
    lockfile_path = Path(temp_project_dir) / "package-lock.json"

    # Create package.json
    package_json_content = {
        "name": "test-npm-project",
        "version": "1.0.0",
        "dependencies": {"express": "^4.18.0", "lodash": "~4.17.21"},
        "devDependencies": {"jest": ">=29.0.0", "eslint": "^8.0.0"},
        "optionalDependencies": {"fsevents": "^2.3.2"},
        "peerDependencies": {"react": "^18.0.0"},
    }
    package_json_path.write_text(json.dumps(package_json_content, indent=2))

    # Create package-lock.json (lockfile version 3)
    lockfile_content = {
        "name": "test-npm-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {
                "name": "test-npm-project",
                "version": "1.0.0",
                "dependencies": {"express": "^4.18.0", "lodash": "~4.17.21"},
                "devDependencies": {"jest": ">=29.0.0", "eslint": "^8.0.0"},
                "optionalDependencies": {"fsevents": "^2.3.2"},
                "peerDependencies": {"react": "^18.0.0"},
            },
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/jest": {"version": "29.7.0", "dev": True},
            "node_modules/eslint": {"version": "8.56.0", "dev": True},
            "node_modules/fsevents": {"version": "2.3.3", "optional": True},
            "node_modules/react": {"version": "18.2.0", "peer": True},
        },
    }
    lockfile_path.write_text(json.dumps(lockfile_content, indent=2))

    return temp_project_dir


@pytest.fixture
def npm_project_without_lockfile(temp_project_dir):
    """Create a project with only package.json (no package-lock.json)."""
    package_json_path = Path(temp_project_dir) / "package.json"

    package_json_content = {
        "name": "no-lockfile-project",
        "version": "1.0.0",
        "dependencies": {"express": "^4.18.0"},
        "devDependencies": {"jest": "^29.0.0"},
    }
    package_json_path.write_text(json.dumps(package_json_content, indent=2))

    return temp_project_dir


@pytest.fixture
def npm_project_dual_category_deps(temp_project_dir):
    """
    Create NPM project where a dependency appears in multiple categories.

    This tests the edge case where one package is both a main dependency
    and in optional/dev/peer dependencies.
    """
    package_json_path = Path(temp_project_dir) / "package.json"
    lockfile_path = Path(temp_project_dir) / "package-lock.json"

    package_json_content = {
        "name": "dual-category-project",
        "version": "1.0.0",
        "dependencies": {"lodash": "^4.17.21"},
        "devDependencies": {"lodash": "^4.17.21", "jest": "^29.0.0"},
        "optionalDependencies": {"fsevents": "^2.3.2"},
        "peerDependencies": {"jest": "^29.0.0"},
    }
    package_json_path.write_text(json.dumps(package_json_content, indent=2))

    lockfile_content = {
        "name": "dual-category-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "dual-category-project",
                "version": "1.0.0",
                "dependencies": {"lodash": "^4.17.21"},
                "devDependencies": {"lodash": "^4.17.21", "jest": "^29.0.0"},
            },
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/jest": {"version": "29.7.0"},
            "node_modules/fsevents": {"version": "2.3.3"},
        },
    }
    lockfile_path.write_text(json.dumps(lockfile_content, indent=2))

    return temp_project_dir


@pytest.fixture
def npm_project_unsupported_lockfile(temp_project_dir):
    """Create a project with an unsupported lockfile version."""
    package_json_path = Path(temp_project_dir) / "package.json"
    lockfile_path = Path(temp_project_dir) / "package-lock.json"

    package_json_content = {"name": "unsupported-lockfile-project", "version": "1.0.0", "dependencies": {}}
    package_json_path.write_text(json.dumps(package_json_content, indent=2))

    # Lockfile with unsupported version
    lockfile_content = {"name": "unsupported-lockfile-project", "version": "1.0.0", "lockfileVersion": 99}
    lockfile_path.write_text(json.dumps(lockfile_content, indent=2))

    return temp_project_dir


@pytest.fixture
def npm_project_missing_main_package(temp_project_dir):
    """Create a lockfile that doesn't contain the main project package."""
    package_json_path = Path(temp_project_dir) / "package.json"
    lockfile_path = Path(temp_project_dir) / "package-lock.json"

    package_json_content = {"name": "missing-main-project", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}
    package_json_path.write_text(json.dumps(package_json_content, indent=2))

    # Lockfile without the main package (empty string key)
    lockfile_content = {
        "name": "missing-main-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {"node_modules/express": {"version": "4.18.2"}},
    }
    lockfile_path.write_text(json.dumps(lockfile_content, indent=2))

    return temp_project_dir


@pytest.fixture
def npm_project_missing_dependency_in_lockfile(temp_project_dir):
    """Create project where a package.json dependency is not in lockfile."""
    package_json_path = Path(temp_project_dir) / "package.json"
    lockfile_path = Path(temp_project_dir) / "package-lock.json"

    package_json_content = {
        "name": "missing-dep-project",
        "version": "1.0.0",
        "dependencies": {"express": "^4.18.0", "missing-package": "^1.0.0"},
    }
    package_json_path.write_text(json.dumps(package_json_content, indent=2))

    lockfile_content = {
        "name": "missing-dep-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "missing-dep-project", "version": "1.0.0"},
            "node_modules/express": {"version": "4.18.2"},
        },
    }
    lockfile_path.write_text(json.dumps(lockfile_content, indent=2))

    return temp_project_dir


# ============================================================================
# Test Static Methods
# ============================================================================


class TestProjectFiles:
    """Test suite for project_files() static method."""

    def test_project_files_paths_with_lockfile(self, npm_project_with_lockfile):
        """Test that project_files returns correct file paths when lockfile exists."""
        npm_project = PackageManagerJsNpm.project_files(npm_project_with_lockfile)

        assert npm_project.manifest == os.path.join(npm_project_with_lockfile, "package.json")
        assert npm_project.lockfile == os.path.join(npm_project_with_lockfile, "package-lock.json")

    def test_project_files_paths_without_lockfile(self, npm_project_without_lockfile):
        """Test that project_files returns None for lockfile when it doesn't exist."""
        npm_project = PackageManagerJsNpm.project_files(npm_project_without_lockfile)

        assert npm_project.manifest == os.path.join(npm_project_without_lockfile, "package.json")
        assert npm_project.lockfile is None

    def test_project_files_namedtuple_fields(self, temp_project_dir):
        """Test that NpmProject namedtuple has correct fields."""
        npm_project = PackageManagerJsNpm.project_files(temp_project_dir)

        # Test namedtuple field access
        assert hasattr(npm_project, "manifest")
        assert hasattr(npm_project, "lockfile")


class TestHasPackageManager:
    """Test suite for has_package_manager() static method."""

    def test_has_package_manager_with_lockfile(self, npm_project_with_lockfile):
        """Test detection when package.json exists (with lockfile)."""
        assert PackageManagerJsNpm.has_package_manager(npm_project_with_lockfile) is True

    def test_has_package_manager_without_lockfile(self, npm_project_without_lockfile):
        """Test detection succeeds even without lockfile (only package.json needed)."""
        assert PackageManagerJsNpm.has_package_manager(npm_project_without_lockfile) is True

    def test_has_package_manager_empty_directory(self, temp_project_dir):
        """Test detection fails in empty directory."""
        assert PackageManagerJsNpm.has_package_manager(temp_project_dir) is False

    def test_has_package_manager_only_lockfile(self, temp_project_dir):
        """Test detection fails when only package-lock.json exists (no package.json)."""
        lockfile_path = Path(temp_project_dir) / "package-lock.json"
        lockfile_path.write_text('{"lockfileVersion": 3}')

        assert PackageManagerJsNpm.has_package_manager(temp_project_dir) is False


# ============================================================================
# Test Initialization
# ============================================================================


class TestInitialization:
    """Test suite for PackageManagerJsNpm initialization."""

    def test_initialization_success(self, npm_project_with_lockfile, settings):
        """Test successful initialization with valid project."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        assert npm_manager.project_path == npm_project_with_lockfile
        assert npm_manager.settings == settings
        assert npm_manager.package_manager_type == NPM

    def test_repr_method(self, npm_project_with_lockfile, settings):
        """Test string representation of NPM manager."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        assert repr(npm_manager) == "npm Package Manager"


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

    def test_parse_dev_dependencies(self, npm_project_with_lockfile, settings):
        """Test parsing devDependencies with categories."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        with open(Path(npm_project_with_lockfile) / "package.json", encoding="utf-8") as f:
            project_data = json.load(f)

        dependency_tree = npm_manager.parse_package_json(project_data)
        jest_package = dependency_tree.optional_dependencies["jest"]
        eslint_package = dependency_tree.optional_dependencies["eslint"]

        # Dev dependencies should be in optional_dependencies
        assert jest_package is not None
        assert eslint_package is not None

        # Verify categories are assigned
        assert CATEGORIES_DEV in jest_package.categories
        assert CATEGORIES_DEV in eslint_package.categories

    def test_parse_optional_dependencies(self, npm_project_with_lockfile, settings):
        """Test parsing optionalDependencies category."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        with open(Path(npm_project_with_lockfile) / "package.json", encoding="utf-8") as f:
            project_data = json.load(f)

        dependency_tree = npm_manager.parse_package_json(project_data)
        fsevents_package = dependency_tree.optional_dependencies["fsevents"]

        # Optional dependencies
        assert fsevents_package is not None
        assert CATEGORIES_OPTIONAL in fsevents_package.categories

    def test_parse_peer_dependencies(self, npm_project_with_lockfile, settings):
        """Test parsing peerDependencies category."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        with open(Path(npm_project_with_lockfile) / "package.json", encoding="utf-8") as f:
            project_data = json.load(f)

        dependency_tree = npm_manager.parse_package_json(project_data)
        react_package = dependency_tree.optional_dependencies["react"]

        assert react_package is not None
        assert CATEGORIES_PEER in react_package.categories

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
# Test parse_lockfile_v3
# ============================================================================


class TestParseLockfileV3:
    """Test suite for parse_lockfile_v3() method."""

    def test_parse_lockfile_updates_versions(self, npm_project_with_lockfile, settings):
        """Test that lockfile parsing updates version_installed from lockfile."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        with open(Path(npm_project_with_lockfile) / "package-lock.json", encoding="utf-8") as f:
            lockfile_data = json.load(f)

        dependency_tree = npm_manager.parse_lockfile_v3(lockfile_data)

        express_package = dependency_tree.dependencies["express"]
        lodash_package = dependency_tree.dependencies["lodash"]
        jest_package = dependency_tree.optional_dependencies["jest"]
        eslint_package = dependency_tree.optional_dependencies["eslint"]
        # Check that versions are updated from lockfile
        assert express_package.version_installed == "4.18.2"
        assert lodash_package.version_installed == "4.17.21"
        assert jest_package.version_installed == "29.7.0"
        assert eslint_package.version_installed == "8.56.0"

    def test_parse_lockfile_preserves_version_defined(self, npm_project_with_lockfile, settings):
        """Test that version_defined is preserved from package.json."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        with open(Path(npm_project_with_lockfile) / "package-lock.json", encoding="utf-8") as f:
            lockfile_data = json.load(f)

        dependency_tree = npm_manager.parse_lockfile_v3(lockfile_data)
        express_package = dependency_tree.dependencies["express"]
        lodash_package = dependency_tree.dependencies["lodash"]

        # version_defined should match package.json (with modifiers)
        assert express_package.version_defined == "^4.18.0"
        assert lodash_package.version_defined == "~4.17.21"

    def test_parse_lockfile_missing_main_package_error(self, npm_project_missing_main_package, settings):
        """Test error when main project package is not in lockfile."""
        npm_manager = PackageManagerJsNpm(npm_project_missing_main_package, settings)

        with open(Path(npm_project_missing_main_package) / "package-lock.json", encoding="utf-8") as f:
            lockfile_data = json.load(f)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            npm_manager.parse_lockfile_v3(lockfile_data)

        assert "Could not parse NPM lockfile" in str(excinfo.value)

    def test_parse_lockfile_missing_dependency_error(self, npm_project_missing_dependency_in_lockfile, settings):
        """Test error when a package.json dependency is missing from lockfile."""
        npm_manager = PackageManagerJsNpm(npm_project_missing_dependency_in_lockfile, settings)

        with open(Path(npm_project_missing_dependency_in_lockfile) / "package-lock.json", encoding="utf-8") as f:
            lockfile_data = json.load(f)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            npm_manager.parse_lockfile_v3(lockfile_data)

        assert "Could not parse NPM lockfile" in str(excinfo.value)


# ============================================================================
# Test get_lockfile_parser
# ============================================================================


class TestGetLockfileParser:
    """Test suite for get_lockfile_parser() method."""

    def test_get_parser_v3(self, npm_project_with_lockfile, settings):
        """Test getting parser for lockfile version 3."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        parser = npm_manager.get_lockfile_parser(3)

        assert parser is not None
        assert parser == npm_manager.parse_lockfile_v3

    def test_get_parser_unsupported_version(self, npm_project_with_lockfile, settings):
        """Test error for unsupported lockfile version."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            npm_manager.get_lockfile_parser(99)

        assert "There's no parser for NPM lockfile version `99`" in str(excinfo.value)

    def test_get_parser_version_1_unsupported(self, npm_project_with_lockfile, settings):
        """Test that version 1 is not supported."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            npm_manager.get_lockfile_parser(1)

        assert "There's no parser for NPM lockfile version `1`" in str(excinfo.value)

    def test_get_parser_with_none(self, npm_project_with_lockfile, settings):
        """Test error when lockfile version is None."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            npm_manager.get_lockfile_parser(None)

        assert "There's no parser for NPM lockfile version `None`" in str(excinfo.value)


# ============================================================================
# Test project_info
# ============================================================================


class TestProjectInfo:
    """Test suite for project_info() method."""

    def test_project_info_with_lockfile(self, npm_project_with_lockfile, settings):
        """Test extracting project info with lockfile present."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        project = npm_manager.project_info()

        assert project.name == "test-npm-project"
        assert project.project_path == npm_project_with_lockfile
        assert project.package_manager_type == NPM

        # Check main dependencies (versions from lockfile)
        assert "express" in project.dependency_tree.dependencies
        assert "lodash" in project.dependency_tree.dependencies
        assert project.dependency_tree.dependencies["express"].version_installed == "4.18.2"
        assert project.dependency_tree.dependencies["lodash"].version_installed == "4.17.21"

        # Check optional dependencies
        assert "jest" in project.dependency_tree.optional_dependencies
        assert "eslint" in project.dependency_tree.optional_dependencies
        assert "fsevents" in project.dependency_tree.optional_dependencies
        assert "react" in project.dependency_tree.optional_dependencies

    def test_project_info_without_lockfile(self, npm_project_without_lockfile, settings):
        """Test extracting project info without lockfile (versions from package.json)."""
        npm_manager = PackageManagerJsNpm(npm_project_without_lockfile, settings)

        project = npm_manager.project_info()

        assert project.name == "no-lockfile-project"

        # Without lockfile, versions come from package.json (normalized)
        assert "express" in project.dependency_tree.dependencies
        assert "jest" in project.dependency_tree.optional_dependencies

        # Versions should be normalized (modifiers removed)
        assert project.dependency_tree.dependencies["express"].version_installed == "4.18.0"
        assert project.dependency_tree.dependencies["express"].version_defined == "^4.18.0"

    def test_project_info_with_dual_category_deps(self, npm_project_dual_category_deps, settings):
        """
        Test project with dependencies in multiple categories.
        """
        npm_manager = PackageManagerJsNpm(npm_project_dual_category_deps, settings)

        project = npm_manager.project_info()

        assert project.name == "dual-category-project"

        # lodash is main dependency with dev category
        assert "lodash" in project.dependency_tree.dependencies
        assert CATEGORIES_DEV in project.dependency_tree.dependencies["lodash"].categories

        # jest is optional with dev and peer categories
        assert "jest" in project.dependency_tree.optional_dependencies
        assert CATEGORIES_DEV in project.dependency_tree.optional_dependencies["jest"].categories
        # NOTE: lockfile overrides package.json categorization!
        assert CATEGORIES_PEER not in project.dependency_tree.optional_dependencies["jest"].categories

    def test_project_info_fallback_name(self, temp_project_dir, settings):
        """Test that project name falls back to directory name if not in package.json."""
        package_json_path = Path(temp_project_dir) / "package.json"

        # package.json without name
        package_json_path.write_text('{"version": "1.0.0"}')

        npm_manager = PackageManagerJsNpm(temp_project_dir, settings)

        project = npm_manager.project_info()

        # Should use directory name as fallback

        assert project.name == os.path.basename(temp_project_dir)

    def test_project_info_unsupported_lockfile_version(self, npm_project_unsupported_lockfile, settings):
        """Test error when lockfile version is unsupported."""
        npm_manager = PackageManagerJsNpm(npm_project_unsupported_lockfile, settings)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            npm_manager.project_info()

        assert "There's no parser for NPM lockfile version `99`" in str(excinfo.value)

    def test_project_info_package_registry(self, npm_project_with_lockfile, settings):
        """Test that project has correct package registry."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        project = npm_manager.project_info()

        # NPM uses NPM ecosystem

        assert project.package_registry == ProjectPackagesRegistry.NPM

    def test_project_info_installed_package_version(self, npm_project_with_lockfile, settings):
        """Test installed_package_version() method on Project."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        project = npm_manager.project_info()

        # Test getting version from main dependencies
        assert project.installed_package_version("express") == "4.18.2"
        assert project.installed_package_version("lodash") == "4.17.21"

        # Test getting version from optional dependencies
        assert project.installed_package_version("jest") == "29.7.0"
        assert project.installed_package_version("eslint") == "8.56.0"


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


@pytest.fixture
def npm_project_with_overrides(temp_project_dir):
    """
    Create a project whose lockfile root entry declares overrides.

    lodash is a transitive dependency of express that is forced to 4.0.0
    via overrides.
    """
    package_json_path = Path(temp_project_dir) / "package.json"
    lockfile_path = Path(temp_project_dir) / "package-lock.json"

    package_json_content = {
        "name": "overrides-test-project",
        "version": "1.0.0",
        "dependencies": {"express": "^4.18.0"},
        "overrides": {"lodash": "4.0.0"},
    }
    package_json_path.write_text(json.dumps(package_json_content, indent=2))

    lockfile_content = {
        "name": "overrides-test-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "overrides-test-project",
                "version": "1.0.0",
                "dependencies": {"express": "^4.18.0"},
                "overrides": {"lodash": "4.0.0"},
            },
            "node_modules/express": {
                "version": "4.18.2",
                "dependencies": {"lodash": "^4.17.0"},
            },
            "node_modules/lodash": {"version": "4.0.0"},
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
            ("npm:ms@^0.7.0", "ms", "^0.7.0"),
            ("npm:@scope/pkg@^1.0.0", "@scope/pkg", "^1.0.0"),
            ("^4.18.0", None, "^4.18.0"),
            ("~1.2.3", None, "~1.2.3"),
            ("4.1.2", None, "4.1.2"),
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

    def test_alias_packages_are_linked_to_root(self, npm_project_with_aliases, settings):
        """Test that alias packages appear as direct dependencies of the root."""
        # Arrange
        npm_manager = PackageManagerJsNpm(npm_project_with_aliases, settings)

        # Act
        project = npm_manager.project_info()

        # Assert — all three aliases must be linked
        assert "lodash-tilde" in project.dependency_tree.dependencies
        assert "lodash-caret" in project.dependency_tree.dependencies
        assert "chalk-legacy" in project.dependency_tree.dependencies

    def test_alias_version_installed_is_resolved(self, npm_project_with_aliases, settings):
        """Test that version_installed reflects the lockfile-resolved version, not the constraint."""
        # Arrange
        npm_manager = PackageManagerJsNpm(npm_project_with_aliases, settings)

        # Act
        project = npm_manager.project_info()

        # Assert
        assert project.dependency_tree.dependencies["lodash-tilde"].version_installed == "4.17.23"
        assert project.dependency_tree.dependencies["lodash-caret"].version_installed == "4.17.23"
        assert project.dependency_tree.dependencies["chalk-legacy"].version_installed == "4.1.2"

    def test_alias_version_defined_is_full_constraint(self, npm_project_with_aliases, settings):
        """Test that version_defined stores the full npm alias specifier from the lockfile."""
        # Arrange
        npm_manager = PackageManagerJsNpm(npm_project_with_aliases, settings)

        # Act
        project = npm_manager.project_info()

        # Assert
        assert project.dependency_tree.dependencies["lodash-tilde"].version_defined == "npm:lodash@~4.17.0"
        assert project.dependency_tree.dependencies["lodash-caret"].version_defined == "npm:lodash@^4.17.0"
        assert project.dependency_tree.dependencies["chalk-legacy"].version_defined == "npm:chalk@4.1.2"

    def test_two_aliases_for_same_package_are_separate_entries(self, npm_project_with_aliases, settings):
        """Test that two aliases pointing to the same package resolve independently."""
        # Arrange
        npm_manager = PackageManagerJsNpm(npm_project_with_aliases, settings)

        # Act
        project = npm_manager.project_info()
        tilde = project.dependency_tree.dependencies["lodash-tilde"]
        caret = project.dependency_tree.dependencies["lodash-caret"]

        # Assert — distinct Dependency objects with their own version_defined
        assert tilde is not caret
        assert tilde.version_defined != caret.version_defined

    def test_alias_canonical_name_is_set(self, npm_project_with_aliases, settings):
        """Test that canonical_name is set to the real package name for alias dependencies."""
        # Arrange
        npm_manager = PackageManagerJsNpm(npm_project_with_aliases, settings)

        # Act
        project = npm_manager.project_info()
        deps = project.dependency_tree.dependencies

        # Assert — alias names map to canonical package names
        assert deps["lodash-tilde"].canonical_name == "lodash"
        assert deps["lodash-caret"].canonical_name == "lodash"
        assert deps["chalk-legacy"].canonical_name == "chalk"


# ============================================================================
# Test npm alias packages (no-lockfile path)
# ============================================================================


class TestNpmAliasesNoLockfile:
    """Test suite for npm alias handling in parse_package_json (no lockfile)."""

    def test_alias_version_installed_is_normalized_constraint(self, temp_project_dir, settings):
        """Test that version_installed is the normalized constraint for alias specs."""
        # Arrange
        package_json_path = Path(temp_project_dir) / "package.json"
        package_json_path.write_text(
            json.dumps(
                {
                    "name": "no-lockfile-alias",
                    "version": "1.0.0",
                    "dependencies": {
                        "lodash-tilde": "npm:lodash@~4.17.0",
                        "chalk-exact": "npm:chalk@4.1.2",
                    },
                }
            )
        )
        npm_manager = PackageManagerJsNpm(temp_project_dir, settings)

        # Act
        project = npm_manager.project_info()

        # Assert — version_installed is the clean version, not the npm: spec
        assert project.dependency_tree.dependencies["lodash-tilde"].version_installed == "4.17.0"
        assert project.dependency_tree.dependencies["chalk-exact"].version_installed == "4.1.2"

    def test_alias_version_defined_is_full_spec(self, temp_project_dir, settings):
        """Test that version_defined preserves the full npm alias specifier."""
        # Arrange
        package_json_path = Path(temp_project_dir) / "package.json"
        package_json_path.write_text(
            json.dumps(
                {
                    "name": "no-lockfile-alias",
                    "version": "1.0.0",
                    "dependencies": {"lodash-tilde": "npm:lodash@~4.17.0"},
                }
            )
        )
        npm_manager = PackageManagerJsNpm(temp_project_dir, settings)

        # Act
        project = npm_manager.project_info()

        # Assert
        assert project.dependency_tree.dependencies["lodash-tilde"].version_defined == "npm:lodash@~4.17.0"

    def test_alias_canonical_name_is_set_from_package_json(self, temp_project_dir, settings):
        """Test that canonical_name is extracted from npm alias spec when no lockfile is present."""
        # Arrange
        package_json_path = Path(temp_project_dir) / "package.json"
        package_json_path.write_text(
            json.dumps(
                {
                    "name": "no-lockfile-alias",
                    "version": "1.0.0",
                    "dependencies": {
                        "lodash-tilde": "npm:lodash@~4.17.0",
                        "chalk-exact": "npm:chalk@4.1.2",
                        "express": "^4.18.0",
                    },
                }
            )
        )
        npm_manager = PackageManagerJsNpm(temp_project_dir, settings)

        # Act
        project = npm_manager.project_info()
        deps = project.dependency_tree.dependencies

        # Assert — alias deps get canonical_name, regular deps fall back to their own name
        assert deps["lodash-tilde"].canonical_name == "lodash"
        assert deps["chalk-exact"].canonical_name == "chalk"
        assert deps["express"].canonical_name == "express"


# ============================================================================
# Test overrides
# ============================================================================


class TestNpmOverrides:
    """Test suite for npm overrides support."""

    def test_overridden_package_gets_category(self, npm_project_with_overrides, settings):
        """Test that packages listed in overrides receive the 'overridden' category."""
        # Arrange
        npm_manager = PackageManagerJsNpm(npm_project_with_overrides, settings)

        # Act
        project = npm_manager.project_info()

        # Find lodash (transitive dep of express, overridden to 4.0.0)
        lodash = project.dependency_tree.dependencies["express"].dependencies.get("lodash")
        assert lodash is not None
        assert CATEGORIES_OVERRIDDEN in lodash.categories

    def test_non_overridden_packages_have_no_override_category(self, npm_project_with_overrides, settings):
        """Test that packages not in overrides do not get the 'overridden' category."""
        # Arrange
        npm_manager = PackageManagerJsNpm(npm_project_with_overrides, settings)

        # Act
        project = npm_manager.project_info()

        # Assert
        express = project.dependency_tree.dependencies["express"]
        assert CATEGORIES_OVERRIDDEN not in express.categories

    def test_flatten_overrides_flat(self):
        """Test flattening of simple {name: version} overrides."""
        # Arrange / Act
        flat, scope_paths = NPMResolverV3._flatten_overrides({"foo": "1.0.0", "bar": "2.0.0"})

        # Assert
        assert flat == {"foo": "1.0.0", "bar": "2.0.0"}
        assert scope_paths == {}

    def test_flatten_overrides_nested_with_dot(self):
        """Test that "." in a nested block maps to the outer package name and scope_paths captures nesting."""
        # Arrange / Act
        flat, scope_paths = NPMResolverV3._flatten_overrides({"foo": {".": "1.0.0", "bar": "2.0.0"}})

        # Assert
        assert flat["foo"] == "1.0.0"
        assert flat["bar"] == "2.0.0"
        assert scope_paths.get("bar") == ["foo"]

    def test_flatten_overrides_empty(self):
        """Test that empty overrides produce an empty mapping."""
        # Arrange / Act
        flat, scope_paths = NPMResolverV3._flatten_overrides({})

        # Assert
        assert flat == {}
        assert scope_paths == {}

    def test_project_without_overrides_has_no_overridden_packages(self, npm_project_with_lockfile, settings):
        """Test that a project without overrides has no packages with overridden category."""
        # Arrange
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        # Act
        project = npm_manager.project_info()

        # Assert — walk all direct deps and their children
        for dep in project.dependency_tree.dependencies.values():
            assert CATEGORIES_OVERRIDDEN not in dep.categories


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

    def test_alias_installed_versions_are_resolved(self, project3_path, settings):
        """Test that alias version_installed comes from lockfile, not the constraint."""
        # Arrange
        npm_manager = PackageManagerJsNpm(project3_path, settings)

        # Act
        project = npm_manager.project_info()
        deps = project.dependency_tree.dependencies

        # Assert — resolved versions (not constraint strings)
        assert deps["lodash-range-tilde"].version_installed == "4.17.23"
        assert deps["lodash-range-caret"].version_installed == "4.17.23"
        assert deps["ms-zero-caret"].version_installed == "0.7.3"
        assert deps["ms-zero-tilde"].version_installed == "0.7.3"

    def test_alias_version_defined_contains_constraint(self, project3_path, settings):
        """Test that version_defined stores the full npm alias specifier."""
        # Arrange
        npm_manager = PackageManagerJsNpm(project3_path, settings)

        # Act
        project = npm_manager.project_info()
        deps = project.dependency_tree.dependencies

        # Assert
        assert deps["lodash-range-tilde"].version_defined == "npm:lodash@~4.17.0"
        assert deps["lodash-range-caret"].version_defined == "npm:lodash@^4.17.0"
        assert deps["ms-zero-caret"].version_defined == "npm:ms@^0.7.0"
        assert deps["ms-zero-tilde"].version_defined == "npm:ms@~0.7.0"

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

    def test_chalk_legacy_canonical_name_is_chalk(self, project3_path, settings):
        """Test that the chalk-legacy alias carries canonical_name='chalk' for registry lookups."""
        # Arrange
        npm_manager = PackageManagerJsNpm(project3_path, settings)

        # Act
        project = npm_manager.project_info()

        # Assert
        chalk_legacy = project.dependency_tree.dependencies["chalk-legacy"]
        assert chalk_legacy.canonical_name == "chalk"

    def test_chalk_canonical_name_equals_name(self, project3_path, settings):
        """Test that the non-alias chalk dependency has canonical_name equal to its own name."""
        # Arrange
        npm_manager = PackageManagerJsNpm(project3_path, settings)

        # Act
        project = npm_manager.project_info()

        # Assert
        chalk = project.dependency_tree.dependencies["chalk"]
        assert chalk.canonical_name == "chalk"


# ============================================================================
# Test constraint classification for npm specifiers
# ============================================================================


class TestConstraintClassification:
    """Test that constraint_info.type is set correctly based on version specifiers."""

    def test_caret_range_is_declared(self, npm_project_with_lockfile, settings):
        """^version (npm default) should be DECLARED."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)
        project = npm_manager.project_info()
        # express: "^4.18.0" in package.json
        express = project.dependency_tree.dependencies["express"]
        assert express.constraint_info.type == ConstraintType.DECLARED

    def test_tilde_range_is_declared(self, npm_project_with_lockfile, settings):
        """~version should be DECLARED."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)
        project = npm_manager.project_info()
        # lodash: "~4.17.21" in package.json
        lodash = project.dependency_tree.dependencies["lodash"]
        assert lodash.constraint_info.type == ConstraintType.DECLARED

    def test_comparison_operator_is_narrowed(self, npm_project_with_lockfile, settings):
        """>=version should be NARROWED."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)
        project = npm_manager.project_info()
        # jest: ">=29.0.0" in package.json
        jest = project.dependency_tree.optional_dependencies["jest"]
        assert jest.constraint_info.type == ConstraintType.NARROWED

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

    def test_no_lockfile_caret_is_declared(self, temp_project_dir, settings):
        """^version without lockfile should be DECLARED."""
        pkg_json = Path(temp_project_dir) / "package.json"
        pkg_json.write_text(json.dumps({"name": "t", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}))
        project = PackageManagerJsNpm(temp_project_dir, settings).project_info()
        assert project.dependency_tree.dependencies["express"].constraint_info.type == ConstraintType.DECLARED

    def test_no_lockfile_pinned_version_is_pinned(self, temp_project_dir, settings):
        """Bare x.y.z without lockfile should be PINNED."""
        pkg_json = Path(temp_project_dir) / "package.json"
        pkg_json.write_text(json.dumps({"name": "t", "version": "1.0.0", "dependencies": {"lodash": "4.17.21"}}))
        project = PackageManagerJsNpm(temp_project_dir, settings).project_info()
        assert project.dependency_tree.dependencies["lodash"].constraint_info.type == ConstraintType.PINNED

    def test_no_lockfile_range_is_narrowed(self, temp_project_dir, settings):
        """>=x <y without lockfile should be NARROWED."""
        pkg_json = Path(temp_project_dir) / "package.json"
        pkg_json.write_text(json.dumps({"name": "t", "version": "1.0.0", "dependencies": {"lodash": ">=1 <2"}}))
        project = PackageManagerJsNpm(temp_project_dir, settings).project_info()
        assert project.dependency_tree.dependencies["lodash"].constraint_info.type == ConstraintType.NARROWED
