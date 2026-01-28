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
"""

import json
import tempfile
from pathlib import Path

import pytest

from ossiq.adapters.package_managers.api_npm import (
    CATEGORIES_DEV,
    CATEGORIES_OPTIONAL,
    CATEGORIES_PEER,
    PackageManagerJsNpm,
)
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import NPM
from ossiq.domain.project import Dependency
from ossiq.settings import Settings

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

        import os

        assert npm_project.manifest == os.path.join(npm_project_with_lockfile, "package.json")
        assert npm_project.lockfile == os.path.join(npm_project_with_lockfile, "package-lock.json")

    def test_project_files_paths_without_lockfile(self, npm_project_without_lockfile):
        """Test that project_files returns None for lockfile when it doesn't exist."""
        npm_project = PackageManagerJsNpm.project_files(npm_project_without_lockfile)

        import os

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
        express = Dependency.lookup_by_name(dependency_tree.dependencies, "express")
        lodash = Dependency.lookup_by_name(dependency_tree.dependencies, "lodash")
        assert express is not None
        assert lodash is not None
        assert express.version_defined == "^4.18.0"
        assert express.version_defined == "~4.17.21"

        # Version normalization should strip modifiers
        assert express.version_installed == "4.18.0"
        assert express.version_installed == "4.17.21"

    def test_parse_dev_dependencies(self, npm_project_with_lockfile, settings):
        """Test parsing devDependencies with categories."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        with open(Path(npm_project_with_lockfile) / "package.json", encoding="utf-8") as f:
            project_data = json.load(f)

        dependency_tree = npm_manager.parse_package_json(project_data)
        jest_package = Dependency.lookup_by_name(dependency_tree.optional_dependencies, "jest")
        eslint_package = Dependency.lookup_by_name(dependency_tree.optional_dependencies, "eslint")

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
        fsevents_package = Dependency.lookup_by_name(dependency_tree.optional_dependencies, "fsevents")

        # Optional dependencies
        assert fsevents_package is not None
        assert CATEGORIES_OPTIONAL in fsevents_package.categories

    def test_parse_peer_dependencies(self, npm_project_with_lockfile, settings):
        """Test parsing peerDependencies category."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        with open(Path(npm_project_with_lockfile) / "package.json", encoding="utf-8") as f:
            project_data = json.load(f)

        dependency_tree = npm_manager.parse_package_json(project_data)
        react_package = Dependency.lookup_by_name(dependency_tree.optional_dependencies, "react")

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
        lodash_package = Dependency.lookup_by_name(dependency_tree.optional_dependencies, "lodash")
        jest_package = Dependency.lookup_by_name(dependency_tree.optional_dependencies, "jest")
        jest_package_prod = Dependency.lookup_by_name(dependency_tree.dependencies, "jest")
        # lodash should be in main dependencies (takes precedence)
        assert lodash_package is not None
        # lodash should also have dev category
        assert CATEGORIES_DEV in lodash_package.categories

        # jest should be in optional_dependencies (not in main dependencies)
        assert jest_package is not None
        assert jest_package_prod is None
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

        express_package = Dependency.lookup_by_name(dependency_tree.dependencies, "express")
        lodash_package = Dependency.lookup_by_name(dependency_tree.dependencies, "lodash")
        jest_package = Dependency.lookup_by_name(dependency_tree.optional_dependencies, "jest")
        eslint_package = Dependency.lookup_by_name(dependency_tree.optional_dependencies, "eslint")
        # Check that versions are updated from lockfile
        assert express_package.version_installed == "4.18.2"  # ty: ignore
        assert lodash_package.version_installed == "4.17.21"  # ty: ignore
        assert jest_package.version_installed == "29.7.0"  # ty: ignore
        assert eslint_package.version_installed == "8.56.0"  # ty: ignore

    def test_parse_lockfile_preserves_version_defined(self, npm_project_with_lockfile, settings):
        """Test that version_defined is preserved from package.json."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        with open(Path(npm_project_with_lockfile) / "package-lock.json", encoding="utf-8") as f:
            lockfile_data = json.load(f)

        dependency_tree = npm_manager.parse_lockfile_v3(lockfile_data)
        express_package = Dependency.lookup_by_name(dependency_tree.dependencies, "express")
        lodash_package = Dependency.lookup_by_name(dependency_tree.dependencies, "lodash")

        # version_defined should match package.json (with modifiers)
        assert express_package.version_defined == "^4.18.0"  # ty: ignore
        assert lodash_package.version_defined == "~4.17.21"  # ty: ignore

    def test_parse_lockfile_missing_main_package_error(self, npm_project_missing_main_package, settings):
        """Test error when main project package is not in lockfile."""
        npm_manager = PackageManagerJsNpm(npm_project_missing_main_package, settings)

        with open(Path(npm_project_missing_main_package) / "package-lock.json", encoding="utf-8") as f:
            lockfile_data = json.load(f)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            npm_manager.parse_lockfile_v3(lockfile_data)

        assert "Cannot extract project package from NPM lockfile" in str(excinfo.value)

    def test_parse_lockfile_missing_dependency_error(self, npm_project_missing_dependency_in_lockfile, settings):
        """Test error when a package.json dependency is missing from lockfile."""
        npm_manager = PackageManagerJsNpm(npm_project_missing_dependency_in_lockfile, settings)

        with open(Path(npm_project_missing_dependency_in_lockfile) / "package-lock.json", encoding="utf-8") as f:
            lockfile_data = json.load(f)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            npm_manager.parse_lockfile_v3(lockfile_data)

        assert "Couldn't resolve missing-package" in str(excinfo.value)
        assert "node_modules/missing-package not found in lockfile" in str(excinfo.value)


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
        assert "express" in project.dependencies
        assert "lodash" in project.dependencies
        assert project.dependencies["express"].version_installed == "4.18.2"
        assert project.dependencies["lodash"].version_installed == "4.17.21"

        # Check optional dependencies
        assert "jest" in project.optional_dependencies
        assert "eslint" in project.optional_dependencies
        assert "fsevents" in project.optional_dependencies
        assert "react" in project.optional_dependencies

    def test_project_info_without_lockfile(self, npm_project_without_lockfile, settings):
        """Test extracting project info without lockfile (versions from package.json)."""
        npm_manager = PackageManagerJsNpm(npm_project_without_lockfile, settings)

        project = npm_manager.project_info()

        assert project.name == "no-lockfile-project"

        # Without lockfile, versions come from package.json (normalized)
        assert "express" in project.dependencies
        assert "jest" in project.optional_dependencies

        # Versions should be normalized (modifiers removed)
        assert project.dependencies["express"].version_installed == "4.18.0"
        assert project.dependencies["express"].version_defined == "^4.18.0"

    def test_project_info_with_dual_category_deps(self, npm_project_dual_category_deps, settings):
        """Test project with dependencies in multiple categories."""
        npm_manager = PackageManagerJsNpm(npm_project_dual_category_deps, settings)

        project = npm_manager.project_info()

        assert project.name == "dual-category-project"

        # lodash is main dependency with dev category
        assert "lodash" in project.dependencies
        assert CATEGORIES_DEV in project.dependencies["lodash"].categories

        # jest is optional with dev and peer categories
        assert "jest" in project.optional_dependencies
        assert CATEGORIES_DEV in project.optional_dependencies["jest"].categories
        assert CATEGORIES_PEER in project.optional_dependencies["jest"].categories

    def test_project_info_fallback_name(self, temp_project_dir, settings):
        """Test that project name falls back to directory name if not in package.json."""
        package_json_path = Path(temp_project_dir) / "package.json"

        # package.json without name
        package_json_path.write_text('{"version": "1.0.0"}')

        npm_manager = PackageManagerJsNpm(temp_project_dir, settings)

        project = npm_manager.project_info()

        # Should use directory name as fallback
        import os

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
        from ossiq.domain.common import ProjectPackagesRegistry

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
