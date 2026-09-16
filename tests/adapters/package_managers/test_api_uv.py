# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for PackageManagerPythonUv adapter.

Tests focus on:
1. API sanity checks (static methods, initialization)
2. Lockfile parsing for UV version 1 revision 3
3. Parser selection logic
4. Project info extraction
5. Error handling
"""

import os
import subprocess
import tempfile
import tomllib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from packaging.requirements import Requirement

from ossiq.adapters.package_managers.api_uv import (
    PackageManagerPythonUv,
    find_pyproject_direct_specifiers,
    upsert_uv_override_dependencies,
)
from ossiq.domain.common import ConstraintType, ProjectPackagesRegistry
from ossiq.domain.exceptions import PackageManagerExecutionError, PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import UV
from ossiq.service.update import UpdateEntry, UpdatePlan
from ossiq.settings import Settings

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def settings():
    """Create Settings instance for testing."""
    return Settings(skip_pypi_enrichment=True)


@pytest.fixture
def temp_project_dir():
    """Create a temporary directory for test projects."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def uv_project_with_lockfile(temp_project_dir):
    """
    Create a temporary UV project with pyproject.toml and uv.lock files.

    Returns a project with:
    - Main dependencies: requests, click
    - Optional dependencies: pytest (in 'dev' category), black (in 'dev' category)
    """
    pyproject_path = Path(temp_project_dir) / "pyproject.toml"
    lockfile_path = Path(temp_project_dir) / "uv.lock"

    # Create pyproject.toml
    pyproject_content = """
[project]
name = "test-project"
version = "1.0.0"
dependencies = [
    "requests>=2.31.0",
    "click>=8.1.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "black>=23.0.0",
]
"""
    pyproject_path.write_text(pyproject_content)

    # Create uv.lock with version 1 revision 3
    # Real uv.lock stores version specifiers from pyproject.toml in the root package's
    # [package.metadata].requires-dist block, not in the dependencies entries themselves.
    lockfile_content = """
version = 1
revision = 3

[[package]]
name = "test-project"
version = "1.0.0"
dependencies = [
    { name = "requests" },
    { name = "click" },
]

[package.optional-dependencies]
dev = [
    { name = "pytest" },
    { name = "black" },
]

[package.metadata]
requires-dist = [
    { name = "requests", specifier = ">=2.31.0" },
    { name = "click", specifier = ">=8.1.0" },
]

[package.metadata.requires-dev]
dev = [
    { name = "pytest", specifier = ">=7.4.0" },
    { name = "black", specifier = ">=23.0.0" },
]

[[package]]
name = "requests"
version = "2.31.0"
dependencies = [
    { name = "urllib3" },
    { name = "certifi" },
]

[[package]]
name = "urllib3"
version = "2.0.4"

[[package]]
name = "certifi"
version = "2023.7.22"

[[package]]
name = "click"
version = "8.1.7"

[[package]]
name = "pytest"
version = "7.4.3"
dependencies = [
    { name = "pluggy" },
]

[[package]]
name = "pluggy"
version = "1.3.0"

[[package]]
name = "black"
version = "23.12.1"
"""
    lockfile_path.write_text(lockfile_content)

    return temp_project_dir


@pytest.fixture
def uv_project_with_dual_category_deps(temp_project_dir):
    """
    Create a UV project where a dependency appears in multiple categories.

    This tests the edge case where one package is both a main dependency
    and an optional dependency in multiple categories.
    """
    pyproject_path = Path(temp_project_dir) / "pyproject.toml"
    lockfile_path = Path(temp_project_dir) / "uv.lock"

    pyproject_content = """
[project]
name = "multi-category-project"
version = "1.0.0"
dependencies = [
    "requests>=2.31.0",
]

[project.optional-dependencies]
dev = [
    "requests>=2.31.0",
    "pytest>=7.4.0",
]
test = [
    "pytest>=7.4.0",
]
"""
    pyproject_path.write_text(pyproject_content)

    lockfile_content = """
version = 1
revision = 3

[[package]]
name = "multi-category-project"
version = "1.0.0"
dependencies = [
    { name = "requests" },
]

[package.optional-dependencies]
dev = [
    { name = "requests" },
    { name = "pytest" },
]
test = [
    { name = "pytest" },
]

[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "pytest"
version = "7.4.3"
"""
    lockfile_path.write_text(lockfile_content)

    return temp_project_dir


@pytest.fixture
def uv_project_without_lockfile(temp_project_dir):
    """Create a project with only pyproject.toml (no uv.lock)."""
    pyproject_path = Path(temp_project_dir) / "pyproject.toml"

    pyproject_content = """
[project]
name = "no-lockfile-project"
version = "1.0.0"
dependencies = ["requests>=2.31.0"]
"""
    pyproject_path.write_text(pyproject_content)

    return temp_project_dir


@pytest.fixture
def uv_project_unsupported_version(temp_project_dir):
    """Create a project with an unsupported lockfile version."""
    pyproject_path = Path(temp_project_dir) / "pyproject.toml"
    lockfile_path = Path(temp_project_dir) / "uv.lock"

    pyproject_content = """
[project]
name = "unsupported-version-project"
version = "1.0.0"
"""
    pyproject_path.write_text(pyproject_content)

    # Lockfile with unsupported version
    lockfile_content = """
version = 99
revision = 99

[[package]]
name = "unsupported-version-project"
version = "1.0.0"
"""
    lockfile_path.write_text(lockfile_content)

    return temp_project_dir


@pytest.fixture
def uv_project_missing_main_package(temp_project_dir):
    """Create a lockfile that doesn't contain the main project package."""
    pyproject_path = Path(temp_project_dir) / "pyproject.toml"
    lockfile_path = Path(temp_project_dir) / "uv.lock"

    pyproject_content = """
[project]
name = "missing-main-project"
version = "1.0.0"
"""
    pyproject_path.write_text(pyproject_content)

    # Lockfile without the main package
    lockfile_content = """
version = 1
revision = 3

[[package]]
name = "some-other-package"
version = "1.0.0"
"""
    lockfile_path.write_text(lockfile_content)

    return temp_project_dir


# ============================================================================
# Test Static Methods
# ============================================================================


class TestProjectFiles:
    """Test suite for project_files() static method."""

    def test_project_files_paths(self, temp_project_dir):
        """Test that project_files returns correct file paths."""
        uv_project = PackageManagerPythonUv.project_files(temp_project_dir)

        assert uv_project.manifest == os.path.join(temp_project_dir, "pyproject.toml")
        assert uv_project.lockfile == os.path.join(temp_project_dir, "uv.lock")

    def test_project_files_namedtuple_fields(self, temp_project_dir):
        """Test that UvProject namedtuple has correct fields."""
        uv_project = PackageManagerPythonUv.project_files(temp_project_dir)

        # Test namedtuple field access
        assert hasattr(uv_project, "manifest")
        assert hasattr(uv_project, "lockfile")


class TestHasPackageManager:
    """Test suite for has_package_manager() static method."""

    def test_has_package_manager_with_both_files(self, uv_project_with_lockfile):
        """Test detection when both pyproject.toml and uv.lock exist."""
        assert PackageManagerPythonUv.has_package_manager(uv_project_with_lockfile) is True

    def test_has_package_manager_without_lockfile(self, uv_project_without_lockfile):
        """Test detection fails when uv.lock is missing."""
        assert PackageManagerPythonUv.has_package_manager(uv_project_without_lockfile) is False

    def test_has_package_manager_empty_directory(self, temp_project_dir):
        """Test detection fails in empty directory."""
        assert PackageManagerPythonUv.has_package_manager(temp_project_dir) is False

    def test_has_package_manager_only_lockfile(self, temp_project_dir):
        """Test detection fails when only uv.lock exists (no pyproject.toml)."""
        lockfile_path = Path(temp_project_dir) / "uv.lock"
        lockfile_path.write_text("version = 1\nrevision = 3")

        assert PackageManagerPythonUv.has_package_manager(temp_project_dir) is False


# ============================================================================
# Test Initialization
# ============================================================================


class TestInitialization:
    """Test suite for PackageManagerPythonUv initialization."""

    def test_initialization_success(self, uv_project_with_lockfile, settings):
        """Test successful initialization with valid project."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        assert uv_manager.project_path == uv_project_with_lockfile
        assert uv_manager.settings == settings
        assert uv_manager.package_manager_type == UV

    def test_initialization_validates_handlers(self, uv_project_with_lockfile, settings):
        """Test that initialization validates handler methods exist."""
        # This should not raise an error
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        # Verify handler exists
        assert hasattr(uv_manager, "parse_lockfile_v1_r3")
        assert callable(uv_manager.parse_lockfile_v1_r3)

    def test_repr_method(self, uv_project_with_lockfile, settings):
        """Test string representation of UV manager."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        assert repr(uv_manager) == "uv Package Manager"


# ============================================================================
# Test parse_lockfile_v1_r3
# ============================================================================


class TestParseLockfileV1R3:
    """Test suite for parse_lockfile_v1_r3() method."""

    def test_parse_basic_dependencies(self, uv_project_with_lockfile, settings):
        """Test parsing main dependencies from lockfile."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        # Read lockfile manually for testing

        lockfile_path = Path(uv_project_with_lockfile) / "uv.lock"
        with open(lockfile_path, "rb") as f:
            uv_lock_data = tomllib.load(f)

        dependency_tree, _ = uv_manager.parse_lockfile_v1_r3("test-project", uv_lock_data)

        # Main dependencies should contain requests and click
        assert "requests" in dependency_tree.dependencies
        assert "click" in dependency_tree.dependencies

        assert dependency_tree.dependencies["requests"].version_installed == "2.31.0"
        assert dependency_tree.dependencies["click"].version_installed == "8.1.7"

        # Should NOT include the project itself
        assert "test-project" not in dependency_tree.dependencies

    def test_parse_optional_dependencies(self, uv_project_with_lockfile, settings):
        """Test parsing optional dependencies with categories."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        lockfile_path = Path(uv_project_with_lockfile) / "uv.lock"
        with open(lockfile_path, "rb") as f:
            uv_lock_data = tomllib.load(f)

        dependency_tree, _ = uv_manager.parse_lockfile_v1_r3("test-project", uv_lock_data)

        # Optional dependencies should contain pytest and black
        assert "pytest" in dependency_tree.optional_dependencies
        assert "black" in dependency_tree.optional_dependencies

        assert dependency_tree.optional_dependencies["pytest"].version_installed == "7.4.3"
        assert dependency_tree.optional_dependencies["black"].version_installed == "23.12.1"

        # Verify categories are assigned
        assert "dev" in dependency_tree.optional_dependencies["pytest"].categories
        assert "dev" in dependency_tree.optional_dependencies["black"].categories

    def test_parse_transitive_dependencies_ignored(self, uv_project_with_lockfile, settings):
        """
        Test that transitive dependencies are not included.

        Transitive dependencies (like urllib3, certifi, pluggy) should not
        be in either dependencies or optional_dependencies.
        """
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        lockfile_path = Path(uv_project_with_lockfile) / "uv.lock"
        with open(lockfile_path, "rb") as f:
            uv_lock_data = tomllib.load(f)

        dependency_tree, _ = uv_manager.parse_lockfile_v1_r3("test-project", uv_lock_data)

        # Transitive dependencies should NOT be included
        for dep in ["urllib3", "certifi", "pluggy"]:
            assert dep not in dependency_tree.dependencies

        for dep in ["urllib3", "certifi", "pluggy"]:
            assert dep not in dependency_tree.optional_dependencies

    def test_parse_dual_category_dependencies(self, uv_project_with_dual_category_deps, settings):
        """
        Test dependencies that appear in multiple categories.

        Tests the edge case where a package is both a main dependency
        and in multiple optional dependency categories.
        """
        uv_manager = PackageManagerPythonUv(uv_project_with_dual_category_deps, settings)

        lockfile_path = Path(uv_project_with_dual_category_deps) / "uv.lock"
        with open(lockfile_path, "rb") as f:
            uv_lock_data = tomllib.load(f)

        dependency_tree, _ = uv_manager.parse_lockfile_v1_r3("multi-category-project", uv_lock_data)

        # requests should be in both main dependencies and optional
        assert "requests" in dependency_tree.dependencies
        assert "requests" in dependency_tree.optional_dependencies

        # requests should have 'dev' category
        assert "dev" in dependency_tree.dependencies["requests"].categories

        # pytest should be in multiple categories
        # Pytest is not in production dependencies
        assert "pytest" not in dependency_tree.dependencies
        # but it is in two optional categories
        assert "pytest" in dependency_tree.optional_dependencies
        assert "dev" in dependency_tree.optional_dependencies["pytest"].categories
        assert "test" in dependency_tree.optional_dependencies["pytest"].categories

    def test_parse_lockfile_sets_version_defined_from_specifier(self, uv_project_with_lockfile, settings):
        """Test that version_defined is populated from [package.metadata].requires-dist.

        AAA Pattern:
        - Arrange: Load lockfile where specifiers are in metadata.requires-dist (real UV format)
        - Act: Parse lockfile via parse_lockfile_v1_r3
        - Assert: version_defined reflects the specifier string, not None
        """
        # Arrange
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)
        lockfile_path = Path(uv_project_with_lockfile) / "uv.lock"
        with open(lockfile_path, "rb") as f:
            uv_lock_data = tomllib.load(f)

        # Act
        dependency_tree, _ = uv_manager.parse_lockfile_v1_r3("test-project", uv_lock_data)

        # Assert — direct production deps pick up the specifier from the root's entry
        requests_dep = dependency_tree.dependencies["requests"]
        click_dep = dependency_tree.dependencies["click"]
        assert requests_dep.version_defined == ">=2.31.0"
        assert click_dep.version_defined == ">=8.1.0"

        # Assert — optional deps also pick up their specifiers
        pytest_dep = dependency_tree.optional_dependencies["pytest"]
        black_dep = dependency_tree.optional_dependencies["black"]
        assert pytest_dep.version_defined == ">=7.4.0"
        assert black_dep.version_defined == ">=23.0.0"

        # Assert — transitive deps without a specifier remain None
        assert dependency_tree.dependencies["requests"].version_installed == "2.31.0"
        urllib3 = next(
            (d for d in dependency_tree.dependencies["requests"].dependencies.values() if d.name == "urllib3"),
            None,
        )
        assert urllib3 is not None
        assert urllib3.version_defined is None

    def test_parse_missing_main_package_error(self, uv_project_missing_main_package, settings):
        """Test error when main project package is not in lockfile."""
        uv_manager = PackageManagerPythonUv(uv_project_missing_main_package, settings)

        lockfile_path = Path(uv_project_missing_main_package) / "uv.lock"
        with open(lockfile_path, "rb") as f:
            uv_lock_data = tomllib.load(f)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            uv_manager.parse_lockfile_v1_r3("missing-main-project", uv_lock_data)

        assert "Cannot parse UV lockfile" in str(excinfo.value)

    def test_parse_empty_dependencies(self, temp_project_dir, settings):
        """Test parsing when project has no dependencies."""
        pyproject_path = Path(temp_project_dir) / "pyproject.toml"
        lockfile_path = Path(temp_project_dir) / "uv.lock"

        pyproject_path.write_text("""
[project]
name = "empty-deps-project"
version = "1.0.0"
""")

        lockfile_path.write_text("""
version = 1
revision = 3

[[package]]
name = "empty-deps-project"
version = "1.0.0"
""")

        uv_manager = PackageManagerPythonUv(temp_project_dir, settings)

        with open(lockfile_path, "rb") as f:
            uv_lock_data = tomllib.load(f)

        dependency_tree, _ = uv_manager.parse_lockfile_v1_r3("empty-deps-project", uv_lock_data)

        assert len(dependency_tree.dependencies) == 0
        assert len(dependency_tree.optional_dependencies) == 0


# ============================================================================
# Test get_lockfile_parser
# ============================================================================


class TestGetLockfileParser:
    """Test suite for get_lockfile_parser() method."""

    def test_get_parser_v1_r3(self, uv_project_with_lockfile, settings):
        """Test getting parser for version 1 revision 3."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        parser = uv_manager.get_lockfile_parser(1, 3)

        assert parser is not None
        assert parser == uv_manager.parse_lockfile_v1_r3

    def test_get_parser_v1_r4_fallback(self, uv_project_with_lockfile, settings):
        """Test that v1 r4+ falls back to v1 r3 parser (per CEL expression)."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        parser = uv_manager.get_lockfile_parser(1, 4)

        # Should still get v1_r3 parser (version == 1 && revision >= 3)
        assert parser is not None
        assert parser == uv_manager.parse_lockfile_v1_r3

    def test_get_parser_unsupported_version(self, uv_project_with_lockfile, settings):
        """Test error for unsupported lockfile version."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            uv_manager.get_lockfile_parser(99, 99)

        assert "There's no parser for UV version `99` and revision `99`" in str(excinfo.value)

    def test_get_parser_v1_r2_unsupported(self, uv_project_with_lockfile, settings):
        """Test that v1 r2 (older revision) is not supported."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            uv_manager.get_lockfile_parser(1, 2)

        assert "There's no parser for UV version `1` and revision `2`" in str(excinfo.value)

    def test_get_parser_with_none_version(self, uv_project_with_lockfile, settings):
        """Test error when version is None."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        # When version is None, CEL condition doesn't match, returns None handler
        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            uv_manager.get_lockfile_parser(None, 3)

        assert "There's no parser for UV version `None` and revision `3`" in str(excinfo.value)

    def test_get_parser_with_none_revision(self, uv_project_with_lockfile, settings):
        """Test error when revision is None."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        # CEL evaluation with None raises ValueError, not our custom exception
        with pytest.raises(TypeError) as excinfo:
            uv_manager.get_lockfile_parser(1, None)

        assert "No such overload" in str(excinfo.value)


# ============================================================================
# Test project_info
# ============================================================================


class TestProjectInfo:
    """Test suite for project_info() method."""

    def test_project_info_basic(self, uv_project_with_lockfile, settings):
        """Test extracting project info from a basic UV project."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        project = uv_manager.project_info()

        assert project.name == "test-project"
        assert project.project_path == uv_project_with_lockfile
        assert project.package_manager_type == UV

        dependency_tree = project.dependency_tree
        # Check main dependencies

        assert "requests" in dependency_tree.dependencies
        assert "click" in dependency_tree.dependencies

        assert dependency_tree.dependencies["requests"].version_installed == "2.31.0"
        assert dependency_tree.dependencies["click"].version_installed == "8.1.7"

        # Check optional dependencies
        assert "pytest" in dependency_tree.optional_dependencies
        assert "black" in dependency_tree.optional_dependencies

    def test_project_info_exposes_version_constraint_from_specifier(self, uv_project_with_lockfile, settings):
        """Test that project_info exposes version constraints via version_constraint_declared on Dependency.

        AAA Pattern:
        - Arrange: UV project with specifiers in the lockfile
        - Act: Call project_info() which runs the full adapter pipeline
        - Assert: version_constraint_declared on direct dependencies reflects pyproject.toml's own
          specifier — the value apply_pyproject_constraints reasserts from the manifest, not
          whatever Pass 2 happened to read off the lockfile.
        """
        # Arrange
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        # Act
        project = uv_manager.project_info()

        # Assert — version_constraint_declared matches the specifiers from pyproject.toml
        assert project.dependencies["requests"].version_constraint_declared == ">=2.31.0"
        assert project.dependencies["click"].version_constraint_declared == ">=8.1.0"
        assert project.optional_dependencies["pytest"].version_constraint_declared == ">=7.4.0"
        assert project.optional_dependencies["black"].version_constraint_declared == ">=23.0.0"

    def test_project_info_with_dual_category_deps(self, uv_project_with_dual_category_deps, settings):
        """Test project with dependencies in multiple categories."""
        uv_manager = PackageManagerPythonUv(uv_project_with_dual_category_deps, settings)

        project = uv_manager.project_info()

        assert project.name == "multi-category-project"

        dependency_tree = project.dependency_tree

        # requests is both main and optional
        assert "requests" in dependency_tree.dependencies
        assert "requests" in dependency_tree.optional_dependencies

        assert "pytest" in dependency_tree.optional_dependencies
        pytest_dep = dependency_tree.optional_dependencies["pytest"]
        assert "dev" in pytest_dep.categories
        assert "test" in pytest_dep.categories

    def test_project_info_fallback_name(self, temp_project_dir, settings):
        """Test that project name falls back to directory name if not in pyproject.toml."""
        pyproject_path = Path(temp_project_dir) / "pyproject.toml"
        lockfile_path = Path(temp_project_dir) / "uv.lock"

        # pyproject.toml without [project] name
        pyproject_path.write_text("""
[build-system]
requires = ["setuptools"]
""")

        # Minimal lockfile
        lockfile_path.write_text(f"""
version = 1
revision = 3

[[package]]
name = "{os.path.basename(temp_project_dir)}"
version = "0.1.0"
""")

        uv_manager = PackageManagerPythonUv(temp_project_dir, settings)

        project = uv_manager.project_info()

        # Should use directory name as fallback
        assert project.name == os.path.basename(temp_project_dir)

    def test_project_info_unsupported_lockfile_version(self, uv_project_unsupported_version, settings):
        """Test error when lockfile version is unsupported."""
        uv_manager = PackageManagerPythonUv(uv_project_unsupported_version, settings)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            uv_manager.project_info()

        assert "There's no parser for UV version `99` and revision `99`" in str(excinfo.value)

    def test_project_info_installed_package_version(self, uv_project_with_lockfile, settings):
        """Test installed_package_version() method on Project."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        project = uv_manager.project_info()

        # Test getting version from main dependencies
        assert project.installed_package_version("requests") == "2.31.0"
        assert project.installed_package_version("click") == "8.1.7"

        # Test getting version from optional dependencies
        assert project.installed_package_version("pytest") == "7.4.3"
        assert project.installed_package_version("black") == "23.12.1"

    def test_project_info_package_registry(self, uv_project_with_lockfile, settings):
        """Test that project has correct package registry."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)
        project = uv_manager.project_info()

        assert project.package_registry == ProjectPackagesRegistry.PYPI


# ============================================================================
# Integration tests against real testdata
# ============================================================================

_VERSION_CONSTRAINT_TESTDATA = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "testdata", "pypi", "version-constraint"
)


class TestVersionConstraintIntegration:
    """Integration tests against testdata/pypi/version-constraint/ real lockfile."""

    @pytest.mark.parametrize(
        "pkg_name,expected_constraint",
        [
            ("requests", "~=2.31.0"),
            ("pydantic", ">=2.0.0"),
            ("scikit-learn", "<2.0.0"),
            ("jsonschema", "<4.5.0,>=4.0.0a6"),
            ("numpy", "!=1.24.2,<2.0.0,>=1.20.0"),
        ],
    )
    def test_version_constraint_extracted_from_metadata_requires_dist(
        self, pkg_name: str, expected_constraint: str, settings: Settings
    ):
        """Test version_constraint_declared reflects pyproject.toml's own specifier text.

        AAA Pattern:
        - Arrange: Point adapter at real testdata project with diverse PEP 440 constraints
        - Act: Call project_info() to parse the real lockfile
        - Assert: version_constraint_declared on each direct dep matches pyproject.toml's declared
          specifier verbatim, even where uv.lock's own [package.metadata].requires-dist records
          the semantically-equivalent clauses in a different order (e.g. numpy, jsonschema below).
        """
        # Arrange
        uv_manager = PackageManagerPythonUv(_VERSION_CONSTRAINT_TESTDATA, settings)

        # Act
        project = uv_manager.project_info()

        # Assert
        dep = project.dependencies.get(pkg_name)
        assert dep is not None, f"{pkg_name!r} not found in project dependencies"
        assert dep.version_constraint_declared == expected_constraint


# ============================================================================
# Test constraint classification for PyPI specifiers (via UV adapter)
# ============================================================================


class TestConstraintClassificationUv:
    """Test that constraint_info.type is set correctly for PyPI/UV specifiers."""

    @pytest.mark.parametrize(
        "pkg_name,expected_type",
        [
            ("requests", ConstraintType.NARROWED),  # ~=2.31.0  → compatible release
            ("pydantic", ConstraintType.DECLARED),  # >=2.0.0   → lower bound only
            ("scikit-learn", ConstraintType.NARROWED),  # <2.0.0  → upper bound only
            ("jsonschema", ConstraintType.NARROWED),  # >=4.0.0a6,<4.5.0  → compound
            ("numpy", ConstraintType.NARROWED),  # >=1.20.0,!=1.24.2,<2.0.0  → compound
        ],
    )
    def test_constraint_type_from_specifier(self, pkg_name: str, expected_type: ConstraintType, settings: Settings):
        """constraint_info.type should reflect specifier specificity for UV packages."""
        uv_manager = PackageManagerPythonUv(_VERSION_CONSTRAINT_TESTDATA, settings)
        project = uv_manager.project_info()
        dep = project.dependencies.get(pkg_name)
        assert dep is not None, f"{pkg_name!r} not found"
        assert dep.constraint_info.type == expected_type, (
            f"{pkg_name}: expected {expected_type}, got {dep.constraint_info.type}"
        )


# ============================================================================
# Helpers for update script tests
# ============================================================================


def make_update_entry(
    name: str,
    current: str,
    recommended: str,
    version_defined: str | None = None,
    constraint_type: ConstraintType = ConstraintType.DECLARED,
    is_direct: bool = True,
    is_forced: bool = False,
) -> UpdateEntry:
    return UpdateEntry(
        package_name=name,
        current_version=current,
        recommended_version=recommended,
        is_direct=is_direct,
        reason=None,
        version_defined=version_defined,
        constraint_type=constraint_type,
        is_forced=is_forced,
    )


def make_update_plan(
    direct: list[UpdateEntry] | None = None,
    transitive: list[UpdateEntry] | None = None,
    pin_all: bool = False,
    project_path: str = "/tmp/test-project",
) -> UpdatePlan:
    return UpdatePlan(
        project_name="test-project",
        project_path=project_path,
        registry_type="PYPI",
        package_manager_name="uv",
        direct_entries=direct or [],
        transitive_entries=transitive or [],
        pin_all=pin_all,
    )


# ============================================================================
# Test resolve_direct_specifier
# ============================================================================


class TestResolveDirectSpecifier:
    """Tests for the static helper that decides sed vs lockfile-only per entry."""

    def test_pin_returns_exact_version(self):
        entry = make_update_entry("sphinx", "8.0.0", "9.0.4", "~=8.0.0", ConstraintType.NARROWED)
        assert PackageManagerPythonUv.resolve_direct_specifier(entry, pin_all=True) == "==9.0.4"

    def test_declared_specifier_unchanged(self):
        entry = make_update_entry("sphinx", "8.0.0", "9.0.4", ">=8.0.0", ConstraintType.DECLARED)
        assert PackageManagerPythonUv.resolve_direct_specifier(entry, pin_all=False) == ">=8.0.0"

    def test_narrowed_tilde_rewritten(self):
        entry = make_update_entry("sphinx", "8.0.0", "9.0.4", "~=8.0.0", ConstraintType.NARROWED)
        assert PackageManagerPythonUv.resolve_direct_specifier(entry, pin_all=False) == "~=9.0.4"

    def test_narrowed_tilde_two_part(self):
        entry = make_update_entry("sphinx", "8.0", "9.0.4", "~=8.0", ConstraintType.NARROWED)
        assert PackageManagerPythonUv.resolve_direct_specifier(entry, pin_all=False) == "~=9.0"

    def test_pinned_eq_rewritten(self):
        entry = make_update_entry("sphinx", "8.0.0", "9.0.4", "==8.0.0", ConstraintType.PINNED)
        assert PackageManagerPythonUv.resolve_direct_specifier(entry, pin_all=False) == "==9.0.4"

    def test_narrowed_compound_falls_back_to_pin(self):
        entry = make_update_entry("sphinx", "8.0.0", "9.0.4", ">=8.0,<9.0", ConstraintType.NARROWED)
        assert PackageManagerPythonUv.resolve_direct_specifier(entry, pin_all=False) == "==9.0.4"

    def test_none_version_defined_declared_stays_none(self):
        entry = make_update_entry("sphinx", "8.0.0", "9.0.4", None, ConstraintType.DECLARED)
        assert PackageManagerPythonUv.resolve_direct_specifier(entry, pin_all=False) is None

    def test_forced_returns_exact_version_regardless_of_mode(self):
        entry = make_update_entry("sphinx", "8.0.0", "9.0.4", ">=8.0.0", ConstraintType.DECLARED, is_forced=True)
        assert PackageManagerPythonUv.resolve_direct_specifier(entry, pin_all=False) == "==9.0.4"


# ============================================================================
# Test upsert_uv_override_dependencies
# ============================================================================


class TestUpsertUvOverrideDependencies:
    """Tests for the pure pyproject.toml override-dependencies merger."""

    def test_creates_tool_uv_section_when_missing(self):
        content = '[project]\nname = "app"\nversion = "1.0.0"\n'
        result = upsert_uv_override_dependencies(content, {"urllib3": "1.26.19"})
        data = tomllib.loads(result)
        assert data["tool"]["uv"]["override-dependencies"] == ["urllib3==1.26.19"]
        assert data["project"]["name"] == "app"

    def test_adds_key_to_existing_tool_uv_section(self):
        content = '[project]\nname = "app"\n\n[tool.uv]\ndev-dependencies = ["pytest"]\n'
        result = upsert_uv_override_dependencies(content, {"urllib3": "1.26.19"})
        data = tomllib.loads(result)
        assert data["tool"]["uv"]["override-dependencies"] == ["urllib3==1.26.19"]
        assert data["tool"]["uv"]["dev-dependencies"] == ["pytest"]

    def test_merges_into_existing_override_list(self):
        content = '[project]\nname = "app"\n\n[tool.uv]\noverride-dependencies = [\n    "certifi==2023.7.22",\n]\n'
        result = upsert_uv_override_dependencies(content, {"urllib3": "1.26.19"})
        data = tomllib.loads(result)
        assert sorted(data["tool"]["uv"]["override-dependencies"]) == ["certifi==2023.7.22", "urllib3==1.26.19"]

    def test_replaces_existing_entry_for_same_package(self):
        content = '[tool.uv]\noverride-dependencies = ["urllib3==1.26.0"]\n'
        result = upsert_uv_override_dependencies(content, {"urllib3": "1.26.19"})
        data = tomllib.loads(result)
        assert data["tool"]["uv"]["override-dependencies"] == ["urllib3==1.26.19"]

    def test_empty_overrides_returns_content_unchanged(self):
        content = '[project]\nname = "app"\n'
        assert upsert_uv_override_dependencies(content, {}) == content


# ============================================================================
# find_pyproject_direct_specifiers (writer-corruption investigation, item 13)
# ============================================================================


class TestFindPyprojectDirectSpecifiers:
    """Pure function: locates verbatim dependency strings by normalised-name match."""

    def test_finds_simple_match(self):
        content = '[project]\ndependencies = ["pydantic==1.10.13", "requests==2.28.1"]\n'
        assert find_pyproject_direct_specifiers(content, "pydantic") == ["pydantic==1.10.13"]

    def test_does_not_match_a_package_whose_name_is_a_prefix(self):
        """The regression this whole investigation is about: pydantic is a prefix of
        pydantic-settings, but they are different packages.
        """
        content = '[project]\ndependencies = ["pydantic==1.10.13", "pydantic-settings==2.15.0"]\n'
        assert find_pyproject_direct_specifiers(content, "pydantic") == ["pydantic==1.10.13"]
        assert find_pyproject_direct_specifiers(content, "pydantic-settings") == ["pydantic-settings==2.15.0"]

    def test_matches_across_normalised_separators(self):
        """PyPI treats '-', '_', '.' as equivalent and is case-insensitive."""
        content = '[project]\ndependencies = ["Pydantic_Settings==2.15.0"]\n'
        assert find_pyproject_direct_specifiers(content, "pydantic-settings") == ["Pydantic_Settings==2.15.0"]

    def test_finds_matches_in_optional_dependencies_too(self):
        content = (
            '[project]\ndependencies = ["pydantic==1.10.13"]\n'
            '[project.optional-dependencies]\nextra = ["pydantic>=1.9,<2"]\n'
        )
        assert find_pyproject_direct_specifiers(content, "pydantic") == ["pydantic==1.10.13", "pydantic>=1.9,<2"]

    def test_package_not_declared_returns_empty(self):
        content = '[project]\ndependencies = ["requests==2.28.1"]\n'
        assert find_pyproject_direct_specifiers(content, "pydantic") == []

    def test_invalid_toml_returns_empty_rather_than_raising(self):
        assert find_pyproject_direct_specifiers("not valid toml [[[", "pydantic") == []

    def test_unparseable_requirement_string_is_skipped(self):
        content = '[project]\ndependencies = ["not a valid requirement!!!", "pydantic==1.10.13"]\n'
        assert find_pyproject_direct_specifiers(content, "pydantic") == ["pydantic==1.10.13"]


# ============================================================================
# execute_update's direct-dependency rewrite (writer-corruption investigation)
# ============================================================================


class TestExecuteUpdateDirectRewrite:
    """execute_update's pyproject.toml rewrite must touch only the intended package's entry.

    Regression coverage for the confirmed writer-corruption bug: updating a package silently
    destroyed any other declared package whose name it was a string prefix of (pydantic /
    pydantic-settings, flask / flask-cors, ...), because the old rewrite matched
    `"{package_name}[^"]*"` - a bare prefix, not a package-name boundary. re.sub then replaced
    every match, including the unrelated package's line, with the target package's new spec.
    """

    @staticmethod
    def _write_project(tmp_path, dependencies_toml: str) -> Path:
        pyproject_path = tmp_path / "pyproject.toml"
        pyproject_path.write_text(f'[project]\nname = "demo"\nversion = "0.1.0"\n{dependencies_toml}')
        return pyproject_path

    @staticmethod
    def _run_execute_update(tmp_path, settings, package_name, version_defined, recommended_version):
        pm = PackageManagerPythonUv(project_path=str(tmp_path), settings=settings)
        entry = UpdateEntry(
            package_name=package_name,
            current_version="x",
            recommended_version=recommended_version,
            is_direct=True,
            reason=None,
            version_defined=version_defined,
            constraint_type=ConstraintType.PINNED,
        )
        plan = UpdatePlan(
            project_name="demo",
            project_path=str(tmp_path),
            registry_type="PYPI",
            package_manager_name="uv",
            direct_entries=[entry],
            transitive_entries=[],
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            pm.execute_update(plan)

    def test_updating_pydantic_does_not_corrupt_pydantic_settings(self, tmp_path, settings):
        """The exact reported corruption: updating pydantic must never touch
        pydantic-settings's declared version.
        """
        pyproject_path = self._write_project(
            tmp_path,
            "dependencies = [\n"
            '    "pydantic==1.10.13",\n'
            '    "pydantic-settings==2.15.0",\n'
            '    "requests==2.28.1",\n'
            "]\n",
        )
        self._run_execute_update(tmp_path, settings, "pydantic", "==1.10.13", "1.10.26")

        data = tomllib.loads(pyproject_path.read_text())
        deps = data["project"]["dependencies"]
        assert "pydantic==1.10.26" in deps
        assert "pydantic-settings==2.15.0" in deps
        assert "requests==2.28.1" in deps
        assert len(deps) == 3

    def test_updating_pydantic_settings_does_not_touch_pydantic(self, tmp_path, settings):
        """The reverse direction: the shorter name must not be corrupted either."""
        pyproject_path = self._write_project(
            tmp_path, 'dependencies = [\n    "pydantic==1.10.13",\n    "pydantic-settings==2.15.0",\n]\n'
        )
        self._run_execute_update(tmp_path, settings, "pydantic-settings", "==2.15.0", "2.16.0")

        data = tomllib.loads(pyproject_path.read_text())
        deps = data["project"]["dependencies"]
        assert "pydantic==1.10.13" in deps
        assert "pydantic-settings==2.16.0" in deps

    @pytest.mark.parametrize(
        "package_a,package_b",
        [
            ("flask", "flask-cors"),
            ("pytest", "pytest-cov"),
            ("click", "click-plugins"),
            ("numpy", "numpydoc"),
        ],
    )
    def test_other_common_prefix_pairs_are_not_corrupted(self, tmp_path, settings, package_a, package_b):
        pyproject_path = self._write_project(
            tmp_path, f'dependencies = [\n    "{package_a}==1.0.0",\n    "{package_b}==2.0.0",\n]\n'
        )
        self._run_execute_update(tmp_path, settings, package_a, "==1.0.0", "1.1.0")

        data = tomllib.loads(pyproject_path.read_text())
        deps = data["project"]["dependencies"]
        assert f"{package_a}==1.1.0" in deps
        assert f"{package_b}==2.0.0" in deps

    def test_round_trip_only_the_intended_specifier_changes(self, tmp_path, settings):
        """The plan's own prescribed test: every dependency present before a write is present
        after it, with only the intended specifier changed.
        """
        before_toml = (
            "dependencies = [\n"
            '    "pydantic==1.10.13",\n'
            '    "pydantic-settings==2.15.0",\n'
            '    "requests==2.28.1",\n'
            '    "click==8.1.3",\n'
            "]\n"
        )
        pyproject_path = self._write_project(tmp_path, before_toml)
        before = tomllib.loads(pyproject_path.read_text())["project"]["dependencies"]
        before_names = {Requirement(d).name for d in before}

        self._run_execute_update(tmp_path, settings, "pydantic", "==1.10.13", "1.10.26")

        after = tomllib.loads(pyproject_path.read_text())["project"]["dependencies"]
        after_by_name = {Requirement(d).name: d for d in after}
        after_names = set(after_by_name)

        assert after_names == before_names, "no dependency should appear or disappear"
        for dep_str in before:
            req = Requirement(dep_str)
            if req.name == "pydantic":
                assert after_by_name[req.name] == "pydantic==1.10.26"
            else:
                assert after_by_name[req.name] == dep_str, f"{req.name} must be byte-identical"

    def test_package_declared_in_multiple_sections_is_updated_in_both(self, tmp_path, settings):
        pyproject_path = self._write_project(
            tmp_path,
            'dependencies = ["pydantic==1.10.13"]\n[project.optional-dependencies]\nextra = ["pydantic==1.10.13"]\n',
        )
        self._run_execute_update(tmp_path, settings, "pydantic", "==1.10.13", "1.10.26")

        data = tomllib.loads(pyproject_path.read_text())
        assert data["project"]["dependencies"] == ["pydantic==1.10.26"]
        assert data["project"]["optional-dependencies"]["extra"] == ["pydantic==1.10.26"]

    def test_no_change_when_specifier_already_matches(self, tmp_path, settings):
        before_toml = 'dependencies = ["pydantic==1.10.26", "pydantic-settings==2.15.0"]\n'
        pyproject_path = self._write_project(tmp_path, before_toml)
        before_content = pyproject_path.read_text()

        self._run_execute_update(tmp_path, settings, "pydantic", "==1.10.26", "1.10.26")

        assert pyproject_path.read_text() == before_content

    def test_multiple_direct_entries_all_rewritten_in_one_pass(self, tmp_path, settings):
        """execute_update parses pyproject.toml once and buckets every dependency string by
        name up front, rather than re-parsing once per changed package - this is the scenario
        that actually exercises more than one entry per plan.
        """
        pyproject_path = self._write_project(
            tmp_path,
            "dependencies = [\n"
            '    "pydantic==1.10.13",\n'
            '    "pydantic-settings==2.15.0",\n'
            '    "requests==2.28.1",\n'
            "]\n",
        )
        pm = PackageManagerPythonUv(project_path=str(tmp_path), settings=settings)
        entries = [
            UpdateEntry(
                package_name=name,
                current_version="x",
                recommended_version=recommended,
                is_direct=True,
                reason=None,
                version_defined=version_defined,
                constraint_type=ConstraintType.PINNED,
            )
            for name, version_defined, recommended in [
                ("pydantic", "==1.10.13", "1.10.26"),
                ("pydantic-settings", "==2.15.0", "2.16.0"),
                ("requests", "==2.28.1", "2.32.0"),
            ]
        ]
        plan = UpdatePlan(
            project_name="demo",
            project_path=str(tmp_path),
            registry_type="PYPI",
            package_manager_name="uv",
            direct_entries=entries,
            transitive_entries=[],
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            pm.execute_update(plan)

        deps = tomllib.loads(pyproject_path.read_text())["project"]["dependencies"]
        assert set(deps) == {"pydantic==1.10.26", "pydantic-settings==2.16.0", "requests==2.32.0"}

    def test_invalid_manifest_raises_instead_of_silently_skipping_updates(self, tmp_path, settings):
        """A pyproject.toml that fails to parse must fail the whole update loudly - not degrade
        into silently rewriting nothing for every package, which is what happened when the
        per-package lookup re-parsed the document on each loop iteration and swallowed
        TOMLDecodeError by returning [].
        """
        pyproject_path = tmp_path / "pyproject.toml"
        pyproject_path.write_text("not valid toml [[[")
        pm = PackageManagerPythonUv(project_path=str(tmp_path), settings=settings)
        plan = UpdatePlan(
            project_name="demo",
            project_path=str(tmp_path),
            registry_type="PYPI",
            package_manager_name="uv",
            direct_entries=[
                UpdateEntry(
                    package_name="pydantic",
                    current_version="x",
                    recommended_version="1.10.26",
                    is_direct=True,
                    reason=None,
                    version_defined="==1.10.13",
                    constraint_type=ConstraintType.PINNED,
                )
            ],
            transitive_entries=[],
        )
        with pytest.raises(PackageManagerExecutionError):
            pm.execute_update(plan)

    def test_restores_original_on_subprocess_failure(self, tmp_path, settings):
        """The npm-side equivalent (test_restores_original_on_install_failure) already covers
        this; uv's execute_update had no equivalent rollback test at all."""
        pyproject_path = self._write_project(tmp_path, 'dependencies = [\n    "pydantic==1.10.13",\n]\n')
        original_content = pyproject_path.read_text()

        pm = PackageManagerPythonUv(project_path=str(tmp_path), settings=settings)
        entry = UpdateEntry(
            package_name="pydantic",
            current_version="x",
            recommended_version="1.10.26",
            is_direct=True,
            reason=None,
            version_defined="==1.10.13",
            constraint_type=ConstraintType.PINNED,
        )
        plan = UpdatePlan(
            project_name="demo",
            project_path=str(tmp_path),
            registry_type="PYPI",
            package_manager_name="uv",
            direct_entries=[entry],
            transitive_entries=[],
        )
        failure = subprocess.CalledProcessError(1, ["uv", "lock"])
        with patch("subprocess.run", side_effect=failure):
            with pytest.raises(PackageManagerExecutionError):
                pm.execute_update(plan)

        assert pyproject_path.read_text() == original_content


class TestInstallPackage:
    """Tests for install_package() — runs `uv add <spec>`, which edits pyproject.toml itself."""

    def test_returns_zero_on_success(self, tmp_path, settings):
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\nversion = "0.1.0"\n')
        pm = PackageManagerPythonUv(project_path=str(tmp_path), settings=settings)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = pm.install_package("requests", "2.31.0")
        assert result == 0
        assert mock_run.call_args[0][0] == ["uv", "add", "requests==2.31.0"]

    def test_restores_original_on_install_failure(self, tmp_path, settings):
        pyproject_path = tmp_path / "pyproject.toml"
        pyproject_path.write_text('[project]\nname = "demo"\nversion = "0.1.0"\n')
        original_content = pyproject_path.read_text()

        pm = PackageManagerPythonUv(project_path=str(tmp_path), settings=settings)
        failure = subprocess.CalledProcessError(1, ["uv", "add"])
        with patch("subprocess.run", side_effect=failure):
            with pytest.raises(PackageManagerExecutionError):
                pm.install_package("requests", "2.31.0")

        assert pyproject_path.read_text() == original_content


class TestOssiqMetadataOwnershipUv:
    """Tests for ossiq:metadata override ownership (item #14) on the uv/pyproject.toml adapter:
    execute_update records what it wrote to [tool.ossiq.metadata], project_info() compares
    against it to tell OSS IQ-authored overrides apart from user-authored ones, and a later
    execute_update never clobbers a user's hand-edit."""

    def test_write_then_read_reports_ossiq_authored(self, uv_project_with_lockfile, settings):
        pm = PackageManagerPythonUv(uv_project_with_lockfile, settings)
        plan = make_update_plan(
            transitive=[make_update_entry("urllib3", "2.0.4", "2.0.7", is_direct=False, is_forced=True)],
            project_path=uv_project_with_lockfile,
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            pm.execute_update(plan)

        pyproject_path = Path(uv_project_with_lockfile) / "pyproject.toml"
        data = tomllib.loads(pyproject_path.read_text())
        assert data["tool"]["uv"]["override-dependencies"] == ["urllib3==2.0.7"]
        assert data["tool"]["ossiq"]["metadata"]["overrides"] == ["urllib3==2.0.7"]

        project = pm.project_info()
        urllib3 = project.dependency_tree.dependencies["requests"].dependencies.get("urllib3")
        assert urllib3 is not None
        assert urllib3.constraint_info.type == ConstraintType.OVERRIDE
        assert urllib3.constraint_info.is_ossiq_authored is True

    def test_hand_edited_override_is_not_ossiq_authored(self, uv_project_with_lockfile, settings):
        pm = PackageManagerPythonUv(uv_project_with_lockfile, settings)
        plan = make_update_plan(
            transitive=[make_update_entry("urllib3", "2.0.4", "2.0.7", is_direct=False, is_forced=True)],
            project_path=uv_project_with_lockfile,
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            pm.execute_update(plan)

        # Simulate the user hand-editing the override value (only the first occurrence, i.e. the
        # [tool.uv] entry — [tool.ossiq.metadata]'s record of what we last wrote is untouched).
        pyproject_path = Path(uv_project_with_lockfile) / "pyproject.toml"
        edited = pyproject_path.read_text().replace('"urllib3==2.0.7"', '"urllib3==2.0.9"', 1)
        pyproject_path.write_text(edited)

        project = pm.project_info()
        urllib3 = project.dependency_tree.dependencies["requests"].dependencies.get("urllib3")
        assert urllib3 is not None
        assert urllib3.constraint_info.is_ossiq_authored is False

    def test_second_update_never_clobbers_hand_edited_override(self, uv_project_with_lockfile, settings):
        pm = PackageManagerPythonUv(uv_project_with_lockfile, settings)
        plan = make_update_plan(
            transitive=[make_update_entry("urllib3", "2.0.4", "2.0.7", is_direct=False, is_forced=True)],
            project_path=uv_project_with_lockfile,
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            pm.execute_update(plan)

        # User hand-edits the override to a value OSS IQ never wrote.
        pyproject_path = Path(uv_project_with_lockfile) / "pyproject.toml"
        edited = pyproject_path.read_text().replace('"urllib3==2.0.7"', '"urllib3==2.0.9"', 1)
        pyproject_path.write_text(edited)

        # A second run recommends yet another version for the same package.
        plan2 = make_update_plan(
            transitive=[make_update_entry("urllib3", "2.0.4", "2.0.11", is_direct=False, is_forced=True)],
            project_path=uv_project_with_lockfile,
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            pm.execute_update(plan2)

        data = tomllib.loads(pyproject_path.read_text())
        assert data["tool"]["uv"]["override-dependencies"] == ["urllib3==2.0.9"]
