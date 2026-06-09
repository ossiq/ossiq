# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for PackageManagerJsNpm adapter.

Tests focus on:
1. API sanity checks (static methods, initialization)
2. Package.json parsing (dependencies, devDependencies, etc.)
3. Lockfile parsing for NPM versions 2 and 3
4. Parser selection logic
5. Project info extraction with and without lockfile
6. Error handling
7. npm alias packages (npm:pkg@version) and overrides
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from ossiq.adapters.package_managers.api_npm import (
    CATEGORIES_DEV,
    CATEGORIES_OPTIONAL,
    CATEGORIES_OVERRIDDEN,
    CATEGORIES_PEER,
    NPM_STATE_FILE,
    NPMResolverV3,
    PackageManagerJsNpm,
)
from ossiq.adapters.package_managers.dependency_tree import GraphExporter
from ossiq.domain.common import ConstraintType, ProjectPackagesRegistry
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import NPM
from ossiq.service.update import UpdateEntry, UpdatePlan
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


@pytest.fixture
def npm_project_with_v2_lockfile(temp_project_dir):
    """
    Create a temporary NPM project with a v2 package-lock.json.

    v2 lockfiles (npm v7/v8 default) contain both a packages flat-map
    (identical format to v3) and a legacy dependencies nested-tree for
    npm v6 back-compat. The legacy section should be ignored during parsing.
    """
    package_json_path = Path(temp_project_dir) / "package.json"
    lockfile_path = Path(temp_project_dir) / "package-lock.json"

    package_json_content = {
        "name": "test-npm-v2-project",
        "version": "1.0.0",
        "dependencies": {"express": "^4.18.0", "lodash": "~4.17.21"},
        "devDependencies": {"jest": ">=29.0.0"},
    }
    package_json_path.write_text(json.dumps(package_json_content, indent=2))

    lockfile_content = {
        "name": "test-npm-v2-project",
        "version": "1.0.0",
        "lockfileVersion": 2,
        "requires": True,
        "packages": {
            "": {
                "name": "test-npm-v2-project",
                "version": "1.0.0",
                "dependencies": {"express": "^4.18.0", "lodash": "~4.17.21"},
                "devDependencies": {"jest": ">=29.0.0"},
            },
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/jest": {"version": "29.7.0", "dev": True},
        },
        # Legacy v1-style nested tree — must be ignored by the parser
        "dependencies": {
            "express": {"version": "4.18.2", "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"},
            "lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
            "jest": {"version": "29.7.0", "dev": True},
        },
    }
    lockfile_path.write_text(json.dumps(lockfile_content, indent=2))

    return temp_project_dir


@pytest.fixture
def npm_project_with_v2_lockfile_missing_packages(temp_project_dir):
    """Create a malformed v2 lockfile that lacks the packages section."""
    package_json_path = Path(temp_project_dir) / "package.json"
    lockfile_path = Path(temp_project_dir) / "package-lock.json"

    package_json_content = {"name": "bad-v2-project", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}
    package_json_path.write_text(json.dumps(package_json_content, indent=2))

    lockfile_content = {
        "name": "bad-v2-project",
        "version": "1.0.0",
        "lockfileVersion": 2,
        # packages section intentionally absent
        "dependencies": {"express": {"version": "4.18.2"}},
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
# Test parse_lockfile_v2
# ============================================================================


class TestParseLockfileV2:
    """Test suite for parse_lockfile_v2() method."""

    def test_parse_lockfile_v2_updates_versions(self, npm_project_with_v2_lockfile, settings):
        """Test that v2 lockfile parsing reads version_installed from packages section."""
        npm_manager = PackageManagerJsNpm(npm_project_with_v2_lockfile, settings)

        with open(Path(npm_project_with_v2_lockfile) / "package-lock.json", encoding="utf-8") as f:
            lockfile_data = json.load(f)

        dependency_tree = npm_manager.parse_lockfile_v2(lockfile_data)

        assert dependency_tree.dependencies["express"].version_installed == "4.18.2"
        assert dependency_tree.dependencies["lodash"].version_installed == "4.17.21"
        assert dependency_tree.optional_dependencies["jest"].version_installed == "29.7.0"

    def test_parse_lockfile_v2_preserves_version_defined(self, npm_project_with_v2_lockfile, settings):
        """Test that version_defined retains the package.json specifier including modifiers."""
        npm_manager = PackageManagerJsNpm(npm_project_with_v2_lockfile, settings)

        with open(Path(npm_project_with_v2_lockfile) / "package-lock.json", encoding="utf-8") as f:
            lockfile_data = json.load(f)

        dependency_tree = npm_manager.parse_lockfile_v2(lockfile_data)

        assert dependency_tree.dependencies["express"].version_defined == "^4.18.0"
        assert dependency_tree.dependencies["lodash"].version_defined == "~4.17.21"

    def test_parse_lockfile_v2_ignores_legacy_dependencies_section(self, npm_project_with_v2_lockfile, settings):
        """Test that the legacy nested dependencies tree in v2 does not affect parsing."""
        npm_manager = PackageManagerJsNpm(npm_project_with_v2_lockfile, settings)

        with open(Path(npm_project_with_v2_lockfile) / "package-lock.json", encoding="utf-8") as f:
            lockfile_data = json.load(f)

        dependency_tree = npm_manager.parse_lockfile_v2(lockfile_data)

        # Result must match what packages section says, not the legacy section
        assert set(dependency_tree.dependencies.keys()) == {"express", "lodash"}
        assert "jest" in dependency_tree.optional_dependencies

    def test_parse_lockfile_v2_missing_packages_raises(self, npm_project_with_v2_lockfile_missing_packages, settings):
        """Test that a v2 lockfile without a packages section raises an error."""
        npm_manager = PackageManagerJsNpm(npm_project_with_v2_lockfile_missing_packages, settings)

        with open(Path(npm_project_with_v2_lockfile_missing_packages) / "package-lock.json", encoding="utf-8") as f:
            lockfile_data = json.load(f)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            npm_manager.parse_lockfile_v2(lockfile_data)

        assert "missing the 'packages' section" in str(excinfo.value)


# ============================================================================
# Test get_lockfile_parser
# ============================================================================


class TestGetLockfileParser:
    """Test suite for get_lockfile_parser() method."""

    def test_get_parser_v2(self, npm_project_with_lockfile, settings):
        """Test getting parser for lockfile version 2."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)

        parser = npm_manager.get_lockfile_parser(2)

        assert parser is not None
        assert parser == npm_manager.parse_lockfile_v2

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

    def test_project_info_with_lockfile_has_lockfile_true(self, npm_project_with_lockfile, settings):
        """Projects parsed from a lockfile have has_lockfile=True."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)
        project = npm_manager.project_info()
        assert project.has_lockfile is True

    def test_project_info_without_lockfile_has_lockfile_false(self, npm_project_without_lockfile, settings):
        """Projects parsed from package.json only have has_lockfile=False."""
        npm_manager = PackageManagerJsNpm(npm_project_without_lockfile, settings)
        project = npm_manager.project_info()
        assert project.has_lockfile is False


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


# ============================================================================
# Helpers for update-command tests
# ============================================================================


def make_npm_update_entry(
    name: str,
    current: str,
    recommended: str,
    version_defined: str | None = None,
    is_direct: bool = True,
) -> UpdateEntry:
    return UpdateEntry(
        package_name=name,
        current_version=current,
        recommended_version=recommended,
        is_direct=is_direct,
        reason=None,
        version_defined=version_defined,
    )


def make_npm_update_plan(
    direct: list[UpdateEntry] | None = None,
    transitive: list[UpdateEntry] | None = None,
    project_path: str = "/tmp/test-npm",
) -> UpdatePlan:
    return UpdatePlan(
        project_name="test-npm-project",
        project_path=project_path,
        registry_type="NPM",
        package_manager_name="npm",
        direct_entries=direct or [],
        transitive_entries=transitive or [],
    )


# ============================================================================
# Test generate_update_script
# ============================================================================


class TestGenerateUpdateScript:
    """Tests for the bash script generated by generate_update_script()."""

    @pytest.fixture
    def npm(self, settings, temp_project_dir):
        return PackageManagerJsNpm(temp_project_dir, settings)

    def test_script_contains_ignore_scripts(self, npm):
        script = npm.generate_update_script(make_npm_update_plan())
        assert "npm install --ignore-scripts" in script

    def test_bare_npm_install_not_in_script(self, npm):
        script = npm.generate_update_script(make_npm_update_plan())
        assert "npm install\n" not in script

    def test_script_is_valid_bash(self, npm):
        script = npm.generate_update_script(make_npm_update_plan())
        assert script.startswith("#!/usr/bin/env bash")
        assert "set -euo pipefail" in script

    def test_script_contains_freeze_and_restore(self, npm):
        script = npm.generate_update_script(make_npm_update_plan())
        assert "ossiq helpers npm freeze-state" in script
        assert "ossiq helpers npm restore-state" in script

    def test_script_cd_to_project_path(self, npm):
        plan = make_npm_update_plan(project_path="/tmp/my-project")
        script = npm.generate_update_script(plan)
        assert "cd /tmp/my-project" in script

    def test_header_comment_shows_entry_counts(self, npm):
        direct = [make_npm_update_entry("express", "4.18.0", "4.19.0")]
        transitive = [make_npm_update_entry("ms", "2.1.2", "2.1.3", is_direct=False)]
        script = npm.generate_update_script(make_npm_update_plan(direct=direct, transitive=transitive))
        assert "1 direct" in script
        assert "1 transitive" in script

    def test_cli_extra_args_forwarded_to_freeze(self, npm):
        script = npm.generate_update_script(make_npm_update_plan(), cli_extra_args="--dry-run")
        assert "freeze-state" in script
        assert "--dry-run" in script

    def test_rollback_comment_present(self, npm):
        script = npm.generate_update_script(make_npm_update_plan())
        assert "# ROLLBACK:" in script


# ============================================================================
# Test execute_update
# ============================================================================


class TestExecuteUpdate:
    """Tests for execute_update() — verifies subprocess invocation and state management."""

    @pytest.fixture
    def npm(self, settings, temp_project_dir):
        return PackageManagerJsNpm(temp_project_dir, settings)

    def test_calls_npm_install_with_ignore_scripts(self, npm, temp_project_dir):
        plan = make_npm_update_plan(project_path=temp_project_dir)
        state_path = os.path.join(temp_project_dir, NPM_STATE_FILE)
        open(state_path, "w").close()
        with (
            patch.object(npm, "freeze_state"),
            patch.object(npm, "restore_state"),
            patch("ossiq.adapters.package_managers.api_npm.subprocess.run") as mock_run,
        ):
            npm.execute_update(plan)
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args == ["npm", "install", "--ignore-scripts"]

    def test_deletes_state_file_on_success(self, npm, temp_project_dir):
        plan = make_npm_update_plan(project_path=temp_project_dir)
        state_path = os.path.join(temp_project_dir, NPM_STATE_FILE)
        open(state_path, "w").close()
        with (
            patch.object(npm, "freeze_state"),
            patch.object(npm, "restore_state") as mock_restore,
            patch("ossiq.adapters.package_managers.api_npm.subprocess.run"),
        ):
            npm.execute_update(plan)
        assert not os.path.exists(state_path)
        mock_restore.assert_not_called()

    def test_restores_state_on_failure(self, npm, temp_project_dir):
        plan = make_npm_update_plan(project_path=temp_project_dir)
        with (
            patch.object(npm, "freeze_state"),
            patch.object(npm, "restore_state") as mock_restore,
            patch("ossiq.adapters.package_managers.api_npm.subprocess.run", side_effect=RuntimeError("fail")),
        ):
            with pytest.raises(RuntimeError):
                npm.execute_update(plan)
        mock_restore.assert_called_once_with(temp_project_dir)


# ============================================================================
# Test restore_state
# ============================================================================


def write_state_file(
    project_dir: str,
    original_overrides: dict,
    locked_overrides: dict | None = None,
    recommended_versions: dict | None = None,
) -> None:
    """Write a minimal .ossiq_npm_state.json to project_dir."""
    import json as _json

    state = {
        "original_overrides": original_overrides,
        "locked_overrides": locked_overrides or {},
        "recommended_versions": recommended_versions or {},
    }
    state_path = os.path.join(project_dir, NPM_STATE_FILE)
    with open(state_path, "w", encoding="utf-8") as f:
        _json.dump(state, f)


def write_pkg_json(project_dir: str, overrides: dict | None = None) -> None:
    """Write a minimal package.json with optional overrides to project_dir."""
    import json as _json

    pkg: dict = {"name": "test", "version": "1.0.0"}
    if overrides is not None:
        pkg["overrides"] = overrides
    manifest_path = os.path.join(project_dir, "package.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        _json.dump(pkg, f)


class TestRestoreState:
    """Tests for restore_state() — verifies overrides are fully restored and state file deleted."""

    @pytest.fixture
    def npm(self, settings, temp_project_dir):
        return PackageManagerJsNpm(temp_project_dir, settings)

    def test_fully_restores_original_overrides(self, npm, temp_project_dir):
        write_state_file(temp_project_dir, original_overrides={"lodash": "4.0.0"})
        write_pkg_json(temp_project_dir, overrides={"lodash": "4.17.21", "ms": "2.1.3"})

        npm.restore_state(temp_project_dir)

        import json as _json

        with open(os.path.join(temp_project_dir, "package.json"), encoding="utf-8") as f:
            pkg = _json.load(f)
        assert pkg["overrides"] == {"lodash": "4.0.0"}

    def test_recommended_version_applied_to_original_override(self, npm, temp_project_dir):
        write_state_file(
            temp_project_dir,
            original_overrides={"lodash": "4.0.0", "express": "4.18.0"},
            recommended_versions={"express": "4.19.0"},
        )
        write_pkg_json(temp_project_dir, overrides={"lodash": "4.17.21", "express": "4.19.0", "ms": "2.1.3"})

        npm.restore_state(temp_project_dir)

        import json as _json

        with open(os.path.join(temp_project_dir, "package.json"), encoding="utf-8") as f:
            pkg = _json.load(f)
        assert pkg["overrides"] == {"lodash": "4.0.0", "express": "4.19.0"}

    def test_original_override_kept_when_no_recommended_version(self, npm, temp_project_dir):
        write_state_file(temp_project_dir, original_overrides={"lodash": "4.0.0"})
        write_pkg_json(temp_project_dir, overrides={"lodash": "4.17.21", "ms": "2.1.3"})

        npm.restore_state(temp_project_dir)

        import json as _json

        with open(os.path.join(temp_project_dir, "package.json"), encoding="utf-8") as f:
            pkg = _json.load(f)
        assert pkg["overrides"] == {"lodash": "4.0.0"}

    def test_dollar_sign_override_not_replaced_by_recommended(self, npm, temp_project_dir):
        write_state_file(
            temp_project_dir,
            original_overrides={"foo": "$bar"},
            recommended_versions={"foo": "2.0.0"},
        )
        write_pkg_json(temp_project_dir, overrides={"foo": "2.0.0"})

        npm.restore_state(temp_project_dir)

        import json as _json

        with open(os.path.join(temp_project_dir, "package.json"), encoding="utf-8") as f:
            pkg = _json.load(f)
        assert pkg["overrides"] == {"foo": "$bar"}

    def test_recommended_but_not_in_original_not_added(self, npm, temp_project_dir):
        write_state_file(
            temp_project_dir,
            original_overrides={"lodash": "4.0.0"},
            recommended_versions={"ms": "2.1.3", "lodash": "4.17.21"},
        )
        write_pkg_json(temp_project_dir, overrides={"lodash": "4.17.21", "ms": "2.1.3"})

        npm.restore_state(temp_project_dir)

        import json as _json

        with open(os.path.join(temp_project_dir, "package.json"), encoding="utf-8") as f:
            pkg = _json.load(f)
        assert "ms" not in pkg["overrides"]
        assert pkg["overrides"] == {"lodash": "4.17.21"}

    def test_removes_overrides_key_when_originally_absent(self, npm, temp_project_dir):
        write_state_file(temp_project_dir, original_overrides={})
        write_pkg_json(temp_project_dir, overrides={"lodash": "4.17.21"})

        npm.restore_state(temp_project_dir)

        import json as _json

        with open(os.path.join(temp_project_dir, "package.json"), encoding="utf-8") as f:
            pkg = _json.load(f)
        assert "overrides" not in pkg

    def test_deletes_state_file_after_restore(self, npm, temp_project_dir):
        write_state_file(temp_project_dir, original_overrides={})
        write_pkg_json(temp_project_dir)

        npm.restore_state(temp_project_dir)

        assert not os.path.exists(os.path.join(temp_project_dir, NPM_STATE_FILE))

    def test_returns_summary_string(self, npm, temp_project_dir):
        write_state_file(temp_project_dir, original_overrides={"lodash": "4.0.0"})
        write_pkg_json(temp_project_dir, overrides={"lodash": "4.17.21"})

        result = npm.restore_state(temp_project_dir)

        assert isinstance(result, str)
        assert len(result) > 0


# ============================================================================
# Test dev-chain transitive dependency visibility (js-cookie / CVE scenario)
# ============================================================================


@pytest.fixture
def npm_project_with_dev_transitive_deps(temp_project_dir):
    """
    Project where a devDependency (test-utils) has a production dep (js-helper)
    which in turn has a production dep (js-cookie).

    This mirrors the real-world scenario:
      root (devDependencies) → @vue/test-utils
      @vue/test-utils (dependencies) → js-beautify
      js-beautify (dependencies) → js-cookie  ← has CVE, must not be invisible
    """
    package_json_path = Path(temp_project_dir) / "package.json"
    lockfile_path = Path(temp_project_dir) / "package-lock.json"

    package_json_content = {
        "name": "test-project",
        "version": "1.0.0",
        "devDependencies": {"test-utils": "^1.0.0"},
    }
    package_json_path.write_text(json.dumps(package_json_content, indent=2))

    lockfile_content = {
        "name": "test-project",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"name": "test-project", "devDependencies": {"test-utils": "^1.0.0"}},
            "node_modules/test-utils": {
                "version": "1.0.0",
                "dev": True,
                "dependencies": {"js-helper": "^2.0.0"},
            },
            "node_modules/js-helper": {
                "version": "2.0.0",
                "dev": True,
                "dependencies": {"js-cookie": "^3.0.5"},
            },
            "node_modules/js-cookie": {"version": "3.0.5", "dev": True},
        },
    }
    lockfile_path.write_text(json.dumps(lockfile_content, indent=2))

    return temp_project_dir


class TestDevTransitiveDeps:
    """Test that transitive deps of devDependencies are reachable in the graph."""

    def test_graph_links_dev_transitive_chain(self, npm_project_with_dev_transitive_deps, settings):
        """The graph must correctly wire dev dep → js-helper → js-cookie via production edges."""
        npm_manager = PackageManagerJsNpm(npm_project_with_dev_transitive_deps, settings)
        project = npm_manager.project_info()
        tree = project.dependency_tree

        test_utils = tree.optional_dependencies["test-utils"]
        assert "js-helper" in test_utils.dependencies, "js-helper must be a production edge of test-utils"
        js_helper = test_utils.dependencies["js-helper"]
        assert "js-cookie" in js_helper.dependencies, "js-cookie must be a production edge of js-helper"

    def test_walk_with_optional_roots_discovers_dev_transitive(self, npm_project_with_dev_transitive_deps, settings):
        """walk_all_paths(include_optional_roots=True) must yield js-cookie."""
        npm_manager = PackageManagerJsNpm(npm_project_with_dev_transitive_deps, settings)
        project = npm_manager.project_info()
        walker = GraphExporter(project.dependency_tree)

        discovered = {node.name for node, _ in walker.walk_all_paths(include_optional_roots=True)}
        assert "js-cookie" in discovered
        assert "js-helper" in discovered

    def test_walk_without_optional_roots_misses_dev_transitive(self, npm_project_with_dev_transitive_deps, settings):
        """walk_all_paths(include_optional_roots=False) must NOT yield js-cookie (no prod chain)."""
        npm_manager = PackageManagerJsNpm(npm_project_with_dev_transitive_deps, settings)
        project = npm_manager.project_info()
        walker = GraphExporter(project.dependency_tree)

        discovered = {node.name for node, _ in walker.walk_all_paths(include_optional_roots=False)}
        assert "js-cookie" not in discovered
        assert "js-helper" not in discovered
