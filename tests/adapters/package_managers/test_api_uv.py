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
import tempfile
import tomllib
from pathlib import Path

import pytest

from ossiq.adapters.package_managers.api_uv import PackageManagerPythonUv
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import UV
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

        dependency_tree = uv_manager.parse_lockfile_v1_r3("test-project", uv_lock_data)

        # Main dependencies should contain requests and click
        assert dependency_tree.has_dependency("requests")
        assert dependency_tree.has_dependency("click")

        assert dependency_tree.get_dependency("requests").version_installed == "2.31.0"
        assert dependency_tree.get_dependency("click").version_installed == "8.1.7"

        # Should NOT include the project itself
        assert dependency_tree.has_dependency("test-project") is False

    def test_parse_optional_dependencies(self, uv_project_with_lockfile, settings):
        """Test parsing optional dependencies with categories."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        lockfile_path = Path(uv_project_with_lockfile) / "uv.lock"
        with open(lockfile_path, "rb") as f:
            uv_lock_data = tomllib.load(f)

        dependency_tree = uv_manager.parse_lockfile_v1_r3("test-project", uv_lock_data)

        # Optional dependencies should contain pytest and black
        dependency_tree.has_optional("pytest")
        dependency_tree.has_optional("black")

        assert dependency_tree.get_optional("pytest").version_installed == "7.4.3"
        assert dependency_tree.get_optional("black").version_installed == "23.12.1"

        # Verify categories are assigned
        assert "dev" in dependency_tree.get_optional("pytest").categories
        assert "dev" in dependency_tree.get_optional("black").categories

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

        dependency_tree = uv_manager.parse_lockfile_v1_r3("test-project", uv_lock_data)

        # Transitive dependencies should NOT be included
        for dep in ["urllib3", "certifi", "pluggy"]:
            assert dependency_tree.has_dependency(dep) is False

        for dep in ["urllib3", "certifi", "pluggy"]:
            assert dependency_tree.has_optional(dep) is False

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

        dependency_tree = uv_manager.parse_lockfile_v1_r3("multi-category-project", uv_lock_data)

        # requests should be in both main dependencies and optional
        assert dependency_tree.has_dependency("requests") is True
        assert dependency_tree.has_optional("requests") is True

        # requests should have 'dev' category
        assert "dev" in dependency_tree.get_dependency("requests").categories

        # pytest should be in multiple categories
        assert dependency_tree.has_dependency("pytest") is False
        assert dependency_tree.has_optional("pytest") is True
        assert "dev" in dependency_tree.get_optional("pytest").categories
        assert "test" in dependency_tree.get_optional("pytest").categories

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

        dependency_tree = uv_manager.parse_lockfile_v1_r3("empty-deps-project", uv_lock_data)

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

        # Type signature says str | None, but TOML loads as int
        parser = uv_manager.get_lockfile_parser(1, 3)  # type: ignore[arg-type]

        assert parser is not None
        assert parser == uv_manager.parse_lockfile_v1_r3

    def test_get_parser_v1_r4_fallback(self, uv_project_with_lockfile, settings):
        """Test that v1 r4+ falls back to v1 r3 parser (per CEL expression)."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        parser = uv_manager.get_lockfile_parser(1, 4)  # type: ignore[arg-type]

        # Should still get v1_r3 parser (version == 1 && revision >= 3)
        assert parser is not None
        assert parser == uv_manager.parse_lockfile_v1_r3

    def test_get_parser_unsupported_version(self, uv_project_with_lockfile, settings):
        """Test error for unsupported lockfile version."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            uv_manager.get_lockfile_parser(99, 99)  # type: ignore[arg-type]

        assert "There's no parser for UV version `99` and revision `99`" in str(excinfo.value)

    def test_get_parser_v1_r2_unsupported(self, uv_project_with_lockfile, settings):
        """Test that v1 r2 (older revision) is not supported."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            uv_manager.get_lockfile_parser(1, 2)  # type: ignore[arg-type]

        assert "There's no parser for UV version `1` and revision `2`" in str(excinfo.value)

    def test_get_parser_with_none_version(self, uv_project_with_lockfile, settings):
        """Test error when version is None."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        # When version is None, CEL condition doesn't match, returns None handler
        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            uv_manager.get_lockfile_parser(None, 3)  # type: ignore[arg-type]

        assert "There's no parser for UV version `None` and revision `3`" in str(excinfo.value)

    def test_get_parser_with_none_revision(self, uv_project_with_lockfile, settings):
        """Test error when revision is None."""
        uv_manager = PackageManagerPythonUv(uv_project_with_lockfile, settings)

        # CEL evaluation with None raises ValueError, not our custom exception
        with pytest.raises(ValueError) as excinfo:
            uv_manager.get_lockfile_parser(1, None)  # type: ignore[arg-type]

        assert "CEL execution error" in str(excinfo.value)


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

        assert dependency_tree.has_dependency("requests") is True
        assert dependency_tree.has_dependency("click") is True

        assert dependency_tree.get_dependency("requests").version_installed == "2.31.0"
        assert dependency_tree.get_dependency("click").version_installed == "8.1.7"

        # Check optional dependencies
        assert dependency_tree.has_optional("pytest") is True
        assert dependency_tree.has_optional("black") is True

    def test_project_info_with_dual_category_deps(self, uv_project_with_dual_category_deps, settings):
        """Test project with dependencies in multiple categories."""
        uv_manager = PackageManagerPythonUv(uv_project_with_dual_category_deps, settings)

        project = uv_manager.project_info()

        assert project.name == "multi-category-project"

        dependency_tree = project.dependency_tree

        # requests is both main and optional
        assert dependency_tree.has_dependency("requests") is True
        assert dependency_tree.has_optional("requests") is True

        assert dependency_tree.has_optional("pytest") is True
        pytest_dep = dependency_tree.get_optional("pytest")
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
