# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for PackageManagerJsNpm: project detection, lockfile version selection, project_info()
with and without a lockfile, execute_update() and install_package().
"""

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from ossiq.adapters.package_managers.api_npm import PackageManagerJsNpm
from ossiq.adapters.package_managers.npm.constants import CATEGORIES_DEV, CATEGORIES_PEER
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.exceptions import PackageManagerExecutionError, PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import NPM
from tests.adapters.package_managers.npm.helpers import (
    make_npm_update_entry,
    make_npm_update_plan,
    read_package_json,
    write_package_json,
)


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


class TestHasPackageManager:
    """Test suite for has_package_manager() static method."""

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
# Test parse_lockfile_v3
# ============================================================================
class TestParseLockfileV3:
    """Test suite for parse_lockfile_v3() method."""

    def test_parse_lockfile_v3(self, npm_project_with_lockfile, settings):
        """v3 lockfile sets version_installed from packages section and preserves version_defined from package.json."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)
        with open(Path(npm_project_with_lockfile) / "package-lock.json", encoding="utf-8") as f:
            lockfile_data = json.load(f)

        tree = npm_manager.parse_lockfile_v3(lockfile_data)

        assert tree.dependencies["express"].version_installed == "4.18.2"
        assert tree.dependencies["lodash"].version_installed == "4.17.21"
        assert tree.optional_dependencies["jest"].version_installed == "29.7.0"
        assert tree.optional_dependencies["eslint"].version_installed == "8.56.0"
        assert tree.dependencies["express"].version_defined == "^4.18.0"
        assert tree.dependencies["lodash"].version_defined == "~4.17.21"

    @pytest.mark.parametrize(
        "fixture_name",
        ["npm_project_missing_main_package", "npm_project_missing_dependency_in_lockfile"],
    )
    def test_parse_lockfile_v3_error(self, fixture_name, request, settings):
        """Missing main package or missing dependency raises PackageManagerLockfileParsingError."""
        project_dir = request.getfixturevalue(fixture_name)
        npm_manager = PackageManagerJsNpm(project_dir, settings)
        with open(Path(project_dir) / "package-lock.json", encoding="utf-8") as f:
            lockfile_data = json.load(f)
        with pytest.raises(PackageManagerLockfileParsingError, match="Could not parse NPM lockfile"):
            npm_manager.parse_lockfile_v3(lockfile_data)


# ============================================================================
# Test parse_lockfile_v2
# ============================================================================
class TestParseLockfileV2:
    """Test suite for parse_lockfile_v2() method."""

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

    @pytest.mark.parametrize(
        "version,expected_method",
        [(2, "parse_lockfile_v2"), (3, "parse_lockfile_v3")],
    )
    def test_returns_correct_parser(self, version, expected_method, npm_project_with_lockfile, settings):
        """Supported lockfile versions return the corresponding parser method."""
        npm_manager = PackageManagerJsNpm(npm_project_with_lockfile, settings)
        assert npm_manager.get_lockfile_parser(version) == getattr(npm_manager, expected_method)

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
        assert project.package_registry == ProjectPackagesRegistry.NPM
        assert project.installed_package_version("express") == "4.18.2"
        assert project.installed_package_version("jest") == "29.7.0"
        assert project.has_lockfile is True
        assert project.declares_esm is False

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
        assert project.has_lockfile is False

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

    def test_project_info_declares_esm_when_type_module(self, temp_project_dir, settings):
        """Project.declares_esm reflects package.json's own "type": "module", not any dependency's."""
        package_json_path = Path(temp_project_dir) / "package.json"
        package_json_path.write_text(json.dumps({"name": "esm-project", "version": "1.0.0", "type": "module"}))

        npm_manager = PackageManagerJsNpm(temp_project_dir, settings)
        project = npm_manager.project_info()

        assert project.declares_esm is True

    def test_project_info_declares_esm_false_without_type(self, temp_project_dir, settings):
        package_json_path = Path(temp_project_dir) / "package.json"
        package_json_path.write_text(json.dumps({"name": "cjs-project", "version": "1.0.0"}))

        npm_manager = PackageManagerJsNpm(temp_project_dir, settings)
        project = npm_manager.project_info()

        assert project.declares_esm is False

    def test_project_info_engine_constraints_node_reduced_to_concrete_version(self, temp_project_dir, settings):
        """Regression: engines.node must be reduced to a concrete floor, never the raw range.

        Feeding the raw range ">=18.0.0" straight into Project.engine_constraints used to make
        has_engine_mismatch silently fail open for every npm project (see
        tests/solver/test_version_matchers.py's
        test_engine_version_satisfies_requirement_raw_node_range_fails_open).
        """
        package_json_path = Path(temp_project_dir) / "package.json"
        package_json_path.write_text(
            json.dumps({"name": "engine-project", "version": "1.0.0", "engines": {"node": ">=18.0.0"}})
        )

        npm_manager = PackageManagerJsNpm(temp_project_dir, settings)
        project = npm_manager.project_info()

        assert project.engine_constraints == {"node": "18.0.0"}

    def test_project_info_unsupported_lockfile_version(self, npm_project_unsupported_lockfile, settings):
        """Test error when lockfile version is unsupported."""
        npm_manager = PackageManagerJsNpm(npm_project_unsupported_lockfile, settings)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            npm_manager.project_info()

        assert "There's no parser for NPM lockfile version `99`" in str(excinfo.value)


# ============================================================================
# Test execute_update
# ============================================================================
class TestExecuteUpdate:
    """Tests for execute_update() — writes final package.json then runs npm install."""

    @pytest.fixture
    def npm(self, settings, temp_project_dir):
        return PackageManagerJsNpm(temp_project_dir, settings)

    def test_calls_npm_install_with_ignore_scripts(self, npm, temp_project_dir):
        write_package_json(
            temp_project_dir, {"name": "app", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}
        )
        plan = make_npm_update_plan(
            direct=[make_npm_update_entry("express", "4.18.0", "4.19.0", version_defined="^4.18.0")],
            project_path=temp_project_dir,
        )
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run") as mock_run:
            npm.execute_update(plan)
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0] == ["npm", "install", "--ignore-scripts"]

    def test_direct_dep_specifier_relaxed_before_install(self, npm, temp_project_dir):
        write_package_json(
            temp_project_dir, {"name": "app", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}
        )
        plan = make_npm_update_plan(
            direct=[make_npm_update_entry("express", "4.18.0", "4.19.0", version_defined="^4.18.0")],
            project_path=temp_project_dir,
        )
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run"):
            npm.execute_update(plan)
        pkg = read_package_json(temp_project_dir)
        assert pkg["dependencies"]["express"] == "^4.19.0"

    def test_pin_all_writes_exact_specifier(self, npm, temp_project_dir):
        write_package_json(
            temp_project_dir, {"name": "app", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}
        )
        plan = make_npm_update_plan(
            direct=[make_npm_update_entry("express", "4.18.0", "4.19.0", version_defined="^4.18.0")],
            project_path=temp_project_dir,
            pin_all=True,
        )
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run"):
            npm.execute_update(plan)
        pkg = read_package_json(temp_project_dir)
        assert pkg["dependencies"]["express"] == "4.19.0"

    def test_forced_direct_dep_pinned_exact(self, npm, temp_project_dir):
        write_package_json(
            temp_project_dir, {"name": "app", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}
        )
        plan = make_npm_update_plan(
            direct=[make_npm_update_entry("express", "4.18.0", "4.19.2", version_defined="^4.18.0", is_forced=True)],
            project_path=temp_project_dir,
        )
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run"):
            npm.execute_update(plan)
        pkg = read_package_json(temp_project_dir)
        assert pkg["dependencies"]["express"] == "4.19.2"

    def test_transitive_update_persists_in_overrides(self, npm, temp_project_dir):
        write_package_json(
            temp_project_dir, {"name": "app", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}
        )
        plan = make_npm_update_plan(
            transitive=[make_npm_update_entry("ms", "2.1.2", "2.1.3", is_direct=False)],
            project_path=temp_project_dir,
        )
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run"):
            npm.execute_update(plan)
        pkg = read_package_json(temp_project_dir)
        assert pkg["overrides"] == {"ms@2.1.2": "2.1.3"}

    def test_existing_overrides_merged_not_replaced(self, npm, temp_project_dir):
        write_package_json(
            temp_project_dir,
            {
                "name": "app",
                "version": "1.0.0",
                "dependencies": {"express": "^4.18.0"},
                "overrides": {"lodash": "4.17.0"},
            },
        )
        plan = make_npm_update_plan(
            transitive=[make_npm_update_entry("ms", "2.1.2", "2.1.3", is_direct=False)],
            project_path=temp_project_dir,
        )
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run"):
            npm.execute_update(plan)
        pkg = read_package_json(temp_project_dir)
        assert pkg["overrides"] == {"lodash": "4.17.0", "ms@2.1.2": "2.1.3"}

    def test_bump_replaces_the_rule_that_produced_the_current_version(self, npm, temp_project_dir):
        """A second bump of the same copy leaves one rule, not a trail of stale ones."""
        write_package_json(
            temp_project_dir,
            {
                "name": "app",
                "version": "1.0.0",
                "dependencies": {"express": "^4.18.0"},
                "overrides": {"ms@2.1.2": "2.1.3"},
                "ossiq:metadata": {"overrides": {"ms@2.1.2": "2.1.3"}},
            },
        )
        plan = make_npm_update_plan(
            transitive=[make_npm_update_entry("ms", "2.1.3", "2.1.5", is_direct=False)],
            project_path=temp_project_dir,
        )
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run"):
            npm.execute_update(plan)
        pkg = read_package_json(temp_project_dir)
        assert pkg["overrides"] == {"ms@2.1.3": "2.1.5"}
        assert pkg["ossiq:metadata"]["overrides"] == {"ms@2.1.3": "2.1.5"}

    def test_bump_replaces_a_plain_override_oss_iq_wrote_earlier(self, npm, temp_project_dir):
        """The pre-keyed format forced every copy; the keyed rule takes over from it."""
        write_package_json(
            temp_project_dir,
            {
                "name": "app",
                "version": "1.0.0",
                "dependencies": {"express": "^4.18.0"},
                "overrides": {"ms": "2.1.3"},
                "ossiq:metadata": {"overrides": {"ms": "2.1.3"}},
            },
        )
        plan = make_npm_update_plan(
            transitive=[make_npm_update_entry("ms", "2.1.3", "2.1.5", is_direct=False)],
            project_path=temp_project_dir,
        )
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run"):
            npm.execute_update(plan)
        pkg = read_package_json(temp_project_dir)
        assert pkg["overrides"] == {"ms@2.1.3": "2.1.5"}

    def test_rules_for_other_copies_of_the_name_are_left_alone(self, npm, temp_project_dir):
        """Bumping one copy must not rewrite the rule that governs another copy of the same name."""
        write_package_json(
            temp_project_dir,
            {
                "name": "app",
                "version": "1.0.0",
                "dependencies": {"express": "^4.18.0"},
                "overrides": {"ms@1.0.0": "1.0.1"},
                "ossiq:metadata": {"overrides": {"ms@1.0.0": "1.0.1"}},
            },
        )
        plan = make_npm_update_plan(
            transitive=[make_npm_update_entry("ms", "2.1.2", "2.1.3", is_direct=False)],
            project_path=temp_project_dir,
        )
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run"):
            npm.execute_update(plan)
        pkg = read_package_json(temp_project_dir)
        assert pkg["overrides"] == {"ms@1.0.0": "1.0.1", "ms@2.1.2": "2.1.3"}

    def test_user_rule_governing_the_copy_blocks_the_write(self, npm, temp_project_dir):
        """A rule the user wrote for this copy wins; OSS IQ adds nothing beside it."""
        write_package_json(
            temp_project_dir,
            {
                "name": "app",
                "version": "1.0.0",
                "dependencies": {"express": "^4.18.0"},
                "overrides": {"ms": "2.1.2"},
            },
        )
        plan = make_npm_update_plan(
            transitive=[make_npm_update_entry("ms", "2.1.2", "2.1.3", is_direct=False)],
            project_path=temp_project_dir,
        )
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run"):
            npm.execute_update(plan)
        pkg = read_package_json(temp_project_dir)
        assert pkg["overrides"] == {"ms": "2.1.2"}
        assert "ossiq:metadata" not in pkg

    def test_no_overrides_key_when_no_transitive_updates(self, npm, temp_project_dir):
        write_package_json(
            temp_project_dir, {"name": "app", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}
        )
        plan = make_npm_update_plan(
            direct=[make_npm_update_entry("express", "4.18.0", "4.19.0", version_defined="^4.18.0")],
            project_path=temp_project_dir,
        )
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run"):
            npm.execute_update(plan)
        pkg = read_package_json(temp_project_dir)
        assert "overrides" not in pkg

    def test_restores_original_on_install_failure(self, npm, temp_project_dir):
        write_package_json(
            temp_project_dir, {"name": "app", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}
        )
        plan = make_npm_update_plan(
            direct=[make_npm_update_entry("express", "4.18.0", "4.19.0", version_defined="^4.18.0")],
            project_path=temp_project_dir,
        )
        failure = subprocess.CalledProcessError(1, ["npm", "install"])
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run", side_effect=failure):
            with pytest.raises(PackageManagerExecutionError):
                npm.execute_update(plan)
        pkg = read_package_json(temp_project_dir)
        assert pkg["dependencies"]["express"] == "^4.18.0"

    def test_multi_section_dep_updated_in_all_sections(self, npm, temp_project_dir):
        write_package_json(
            temp_project_dir,
            {
                "name": "app",
                "version": "1.0.0",
                "devDependencies": {"react": "^17.0.0"},
                "peerDependencies": {"react": "^17.0.0"},
            },
        )
        plan = make_npm_update_plan(
            direct=[make_npm_update_entry("react", "17.0.0", "18.2.0", version_defined="^17.0.0")],
            project_path=temp_project_dir,
        )
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run"):
            npm.execute_update(plan)
        pkg = read_package_json(temp_project_dir)
        assert pkg["devDependencies"]["react"] == "^18.2.0"
        assert pkg["peerDependencies"]["react"] == "^18.2.0"

    def test_malformed_package_json_raises_clean_error(self, npm, temp_project_dir):
        """A syntactically broken package.json must raise a titled ApplicationError, not a raw
        json.JSONDecodeError that falls through to the CLI's generic 'unexpected error' handler —
        mirrors uv's tomllib.TOMLDecodeError guard for pyproject.toml."""
        manifest_path = Path(temp_project_dir) / "package.json"
        manifest_path.write_text("{not valid json", encoding="utf-8")
        plan = make_npm_update_plan(
            direct=[make_npm_update_entry("express", "4.18.0", "4.19.0", version_defined="^4.18.0")],
            project_path=temp_project_dir,
        )
        with pytest.raises(PackageManagerExecutionError):
            npm.execute_update(plan)
        assert manifest_path.read_text(encoding="utf-8") == "{not valid json"


class TestInstallPackage:
    """Tests for install_package() — runs `npm install <spec>`, which edits package.json itself."""

    @pytest.fixture
    def npm(self, settings, temp_project_dir):
        return PackageManagerJsNpm(temp_project_dir, settings)

    def test_returns_zero_on_success(self, npm, temp_project_dir):
        write_package_json(temp_project_dir, {"name": "app", "version": "1.0.0", "dependencies": {}})
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            result = npm.install_package("express", "4.19.0")
        assert result == 0

    def test_install_scripts_are_not_run(self, npm, temp_project_dir):
        """Same posture as execute_update: lifecycle scripts of what gets installed stay off."""
        write_package_json(temp_project_dir, {"name": "app", "version": "1.0.0", "dependencies": {}})
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run") as mock_run:
            npm.install_package("express", "4.19.0")
        assert mock_run.call_args[0][0] == ["npm", "install", "--ignore-scripts", "express@4.19.0"]

    def test_restores_original_on_install_failure(self, npm, temp_project_dir):
        write_package_json(temp_project_dir, {"name": "app", "version": "1.0.0", "dependencies": {}})
        manifest_path = Path(temp_project_dir) / "package.json"
        original_content = manifest_path.read_text(encoding="utf-8")

        failure = subprocess.CalledProcessError(1, ["npm", "install"])
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run", side_effect=failure):
            with pytest.raises(PackageManagerExecutionError):
                npm.install_package("express", "4.19.0")
        assert manifest_path.read_text(encoding="utf-8") == original_content
