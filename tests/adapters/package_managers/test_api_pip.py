# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for PackageManagerPythonPip adapter (pylock.toml / PEP 751).

Tests focus on:
1. API sanity checks (static methods, initialization)
2. Package name normalization (PEP 503)
3. Lockfile parsing for pylock version 1.0
4. Cross-referencing with pyproject.toml
5. Parser selection logic
6. Project info extraction
7. Error handling
"""

import os
import tempfile
import tomllib
from pathlib import Path

import pytest

from ossiq.adapters.package_managers.api_pip import PackageManagerPythonPip
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import PIP
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
def pylock_project_basic(temp_project_dir):
    """
    Create a temporary pylock project with pyproject.toml and pylock.toml.

    Returns a project with:
    - Main dependencies: requests, click
    - Optional dependencies: pytest (in 'dev' category), black (in 'dev' category)
    - Transitive dependencies: urllib3, certifi, pluggy (linked via dependency entries)
    """
    pyproject_path = Path(temp_project_dir) / "pyproject.toml"
    lockfile_path = Path(temp_project_dir) / "pylock.toml"

    # Create pyproject.toml
    pyproject_content = """
[project]
name = "test-pylock-project"
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

    # Create pylock.toml with lock-version "1.0"
    # Includes dependency relationships for proper graph building
    lockfile_content = """
lock-version = "1.0"
created-by = "test-suite"

[[packages]]
name = "requests"
version = "2.31.0"

[[packages.dependencies]]
name = "urllib3"

[[packages.dependencies]]
name = "certifi"

[[packages]]
name = "urllib3"
version = "2.0.4"

[[packages]]
name = "certifi"
version = "2023.7.22"

[[packages]]
name = "click"
version = "8.1.7"

[[packages]]
name = "pytest"
version = "7.4.3"

[[packages.dependencies]]
name = "pluggy"

[[packages]]
name = "pluggy"
version = "1.3.0"

[[packages]]
name = "black"
version = "23.12.1"
"""
    lockfile_path.write_text(lockfile_content)

    return temp_project_dir


@pytest.fixture
def pylock_project_with_name_variations(temp_project_dir):
    """
    Create a pylock project testing package name normalization edge cases.

    Tests: extras removal, case normalization, hyphen/underscore handling
    """
    pyproject_path = Path(temp_project_dir) / "pyproject.toml"
    lockfile_path = Path(temp_project_dir) / "pylock.toml"

    pyproject_content = """
[project]
name = "name-variation-project"
version = "1.0.0"
dependencies = [
    "requests[security]>=2.31.0",
    "Django>=4.2.0",
    "some_package>=1.0.0",
]
"""
    pyproject_path.write_text(pyproject_content)

    # pylock.toml has normalized names
    lockfile_content = """
lock-version = "1.0"
created-by = "test-suite"

[[packages]]
name = "requests"
version = "2.31.0"

[[packages]]
name = "django"
version = "4.2.7"

[[packages]]
name = "some-package"
version = "1.2.0"
"""
    lockfile_path.write_text(lockfile_content)

    return temp_project_dir


@pytest.fixture
def pylock_project_with_dual_category_deps(temp_project_dir):
    """
    Create a pylock project where a dependency appears in multiple categories.

    This tests the edge case where one package is both a main dependency
    and an optional dependency in multiple categories.
    """
    pyproject_path = Path(temp_project_dir) / "pyproject.toml"
    lockfile_path = Path(temp_project_dir) / "pylock.toml"

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
lock-version = "1.0"
created-by = "test-suite"

[[packages]]
name = "requests"
version = "2.31.0"

[[packages]]
name = "pytest"
version = "7.4.3"
"""
    lockfile_path.write_text(lockfile_content)

    return temp_project_dir


@pytest.fixture
def pylock_project_without_lockfile(temp_project_dir):
    """Create a project with only pyproject.toml (no pylock.toml)."""
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
def pylock_project_unsupported_version(temp_project_dir):
    """Create a project with an unsupported lockfile version."""
    pyproject_path = Path(temp_project_dir) / "pyproject.toml"
    lockfile_path = Path(temp_project_dir) / "pylock.toml"

    pyproject_content = """
[project]
name = "unsupported-version-project"
version = "1.0.0"
"""
    pyproject_path.write_text(pyproject_content)

    # Lockfile with unsupported version
    lockfile_content = """
lock-version = "99.0"
created-by = "future-tool"

[[packages]]
name = "some-package"
version = "1.0.0"
"""
    lockfile_path.write_text(lockfile_content)

    return temp_project_dir


@pytest.fixture
def pylock_project_with_vcs_packages(temp_project_dir):
    """Create a project with VCS packages (no version field)."""
    pyproject_path = Path(temp_project_dir) / "pyproject.toml"
    lockfile_path = Path(temp_project_dir) / "pylock.toml"

    pyproject_content = """
[project]
name = "vcs-project"
version = "1.0.0"
dependencies = [
    "requests>=2.31.0",
    "my-vcs-package",
]
"""
    pyproject_path.write_text(pyproject_content)

    # Lockfile with VCS package (no version)
    lockfile_content = """
lock-version = "1.0"
created-by = "test-suite"

[[packages]]
name = "requests"
version = "2.31.0"

[[packages]]
name = "my-vcs-package"

[packages.vcs]
url = "https://github.com/example/my-vcs-package.git"
commit-id = "abc123"
"""
    lockfile_path.write_text(lockfile_content)

    return temp_project_dir


@pytest.fixture
def pylock_project_with_editable_self(temp_project_dir):
    """Create a project where pylock.toml includes the project itself as a directory/editable package.

    This mirrors real-world pylock.toml generated by `uv export --format pylock.toml`
    where the project appears as a [[packages]] entry without a version field.
    """
    pyproject_path = Path(temp_project_dir) / "pyproject.toml"
    lockfile_path = Path(temp_project_dir) / "pylock.toml"

    pyproject_content = """
[project]
name = "my-app"
version = "0.1.0"
dependencies = [
    "requests>=2.31.0",
    "click>=8.1.0",
]
"""
    pyproject_path.write_text(pyproject_content)

    lockfile_content = """
lock-version = "1.0"
created-by = "uv"

[[packages]]
name = "requests"
version = "2.31.0"

[[packages]]
name = "click"
version = "8.1.7"

[[packages]]
name = "my-app"
directory = { path = ".", editable = true }
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
        pylock_project = PackageManagerPythonPip.project_files(temp_project_dir)

        assert pylock_project.manifest == os.path.join(temp_project_dir, "pyproject.toml")
        assert pylock_project.lockfile == os.path.join(temp_project_dir, "pylock.toml")

    def test_project_files_namedtuple_fields(self, temp_project_dir):
        """Test that PylockProject namedtuple has correct fields."""
        pylock_project = PackageManagerPythonPip.project_files(temp_project_dir)

        # Test namedtuple field access
        assert hasattr(pylock_project, "manifest")
        assert hasattr(pylock_project, "lockfile")


class TestHasPackageManager:
    """Test suite for has_package_manager() static method."""

    def test_has_package_manager_with_both_files(self, pylock_project_basic):
        """Test detection when both pyproject.toml and pylock.toml exist."""
        assert PackageManagerPythonPip.has_package_manager(pylock_project_basic) is True

    def test_has_package_manager_without_lockfile(self, pylock_project_without_lockfile):
        """Test detection fails when pylock.toml is missing."""
        assert PackageManagerPythonPip.has_package_manager(pylock_project_without_lockfile) is False

    def test_has_package_manager_empty_directory(self, temp_project_dir):
        """Test detection fails in empty directory."""
        assert PackageManagerPythonPip.has_package_manager(temp_project_dir) is False

    def test_has_package_manager_only_lockfile(self, temp_project_dir):
        """Test detection fails when only pylock.toml exists (no pyproject.toml)."""
        lockfile_path = Path(temp_project_dir) / "pylock.toml"
        lockfile_path.write_text('lock-version = "1.0"')

        assert PackageManagerPythonPip.has_package_manager(temp_project_dir) is False


# ============================================================================
# Test Package Name Normalization
# ============================================================================


class TestPackageNameNormalization:
    """Test suite for normalize_package_name() static method."""

    def test_normalize_extras_removal(self):
        """Test that extras are removed from package names."""
        assert PackageManagerPythonPip.normalize_package_name("requests[security]") == "requests"
        assert PackageManagerPythonPip.normalize_package_name("django[argon2,bcrypt]") == "django"
        assert PackageManagerPythonPip.normalize_package_name("package[extra1,extra2]") == "package"

    def test_normalize_case_conversion(self):
        """Test that package names are converted to lowercase."""
        assert PackageManagerPythonPip.normalize_package_name("Django") == "django"
        assert PackageManagerPythonPip.normalize_package_name("REQUESTS") == "requests"
        assert PackageManagerPythonPip.normalize_package_name("PyYAML") == "pyyaml"

    def test_normalize_underscore_to_hyphen(self):
        """Test that underscores are replaced with hyphens."""
        assert PackageManagerPythonPip.normalize_package_name("some_package") == "some-package"
        assert PackageManagerPythonPip.normalize_package_name("my_test_package") == "my-test-package"

    def test_normalize_combined_transformations(self):
        """Test normalization with multiple transformations."""
        assert PackageManagerPythonPip.normalize_package_name("Django_REST[extras]") == "django-rest"
        assert PackageManagerPythonPip.normalize_package_name("MY_Package[security,crypto]") == "my-package"
        assert PackageManagerPythonPip.normalize_package_name("Test_PACKAGE_Name") == "test-package-name"

    def test_normalize_already_normalized(self):
        """Test normalization of already normalized names."""
        assert PackageManagerPythonPip.normalize_package_name("requests") == "requests"
        assert PackageManagerPythonPip.normalize_package_name("django-rest-framework") == "django-rest-framework"

    def test_normalize_whitespace_handling(self):
        """Test that whitespace is stripped."""
        assert PackageManagerPythonPip.normalize_package_name(" requests ") == "requests"
        assert PackageManagerPythonPip.normalize_package_name("  django  ") == "django"

    def test_normalize_version_specs(self):
        """Test normalization with version specifications."""
        assert PackageManagerPythonPip.normalize_package_name("requests>=2.31.0") == "requests"
        assert PackageManagerPythonPip.normalize_package_name("Django==4.2.0") == "django"
        assert PackageManagerPythonPip.normalize_package_name("package~=1.0") == "package"
        assert PackageManagerPythonPip.normalize_package_name("test-pkg<=2.0") == "test-pkg"
        assert PackageManagerPythonPip.normalize_package_name("pkg!=1.5") == "pkg"

    def test_normalize_version_specs_with_extras(self):
        """Test normalization with both version specs and extras."""
        assert PackageManagerPythonPip.normalize_package_name("requests[security]>=2.31.0") == "requests"
        assert PackageManagerPythonPip.normalize_package_name("Django[argon2]==4.2.0") == "django"


# ============================================================================
# Test Initialization
# ============================================================================


class TestInitialization:
    """Test suite for PackageManagerPythonPip initialization."""

    def test_initialization_success(self, pylock_project_basic, settings):
        """Test successful initialization with valid project."""
        pylock_manager = PackageManagerPythonPip(pylock_project_basic, settings)

        assert pylock_manager.project_path == pylock_project_basic
        assert pylock_manager.settings == settings
        assert pylock_manager.package_manager_type == PIP

    def test_initialization_validates_handlers(self, pylock_project_basic, settings):
        """Test that initialization validates handler methods exist."""
        # This should not raise an error
        pylock_manager = PackageManagerPythonPip(pylock_project_basic, settings)

        # Verify handler exists
        assert hasattr(pylock_manager, "parse_lockfile_v1_0")
        assert callable(pylock_manager.parse_lockfile_v1_0)

    def test_repr_method(self, pylock_project_basic, settings):
        """Test string representation of pylock manager."""
        pylock_manager = PackageManagerPythonPip(pylock_project_basic, settings)

        assert repr(pylock_manager) == "pylock Package Manager"


# ============================================================================
# Test extract_pyproject_dependencies
# ============================================================================


class TestExtractPyprojectDependencies:
    """Test suite for extract_pyproject_dependencies() method."""

    def test_extract_basic_dependencies(self, pylock_project_basic, settings):
        """Test extracting direct dependencies from pyproject.toml."""
        pylock_manager = PackageManagerPythonPip(pylock_project_basic, settings)

        pyproject_path = Path(pylock_project_basic) / "pyproject.toml"
        with open(pyproject_path, "rb") as f:
            pyproject_data = tomllib.load(f)

        direct_deps, optional_deps_map = pylock_manager.extract_pyproject_dependencies(pyproject_data)

        # Direct dependencies should be normalized
        assert "requests" in direct_deps
        assert "click" in direct_deps
        assert len(direct_deps) == 2

        # Optional dependencies should be categorized
        assert "dev" in optional_deps_map
        assert "pytest" in optional_deps_map["dev"]
        assert "black" in optional_deps_map["dev"]

    def test_extract_with_extras(self, pylock_project_with_name_variations, settings):
        """Test that extras are removed during extraction."""
        pylock_manager = PackageManagerPythonPip(pylock_project_with_name_variations, settings)

        pyproject_path = Path(pylock_project_with_name_variations) / "pyproject.toml"
        with open(pyproject_path, "rb") as f:
            pyproject_data = tomllib.load(f)

        direct_deps, optional_deps_map = pylock_manager.extract_pyproject_dependencies(pyproject_data)

        # requests[security] should be normalized to requests
        assert "requests" in direct_deps
        assert "django" in direct_deps  # Django normalized to lowercase
        assert "some-package" in direct_deps  # some_package normalized to some-package

    def test_extract_empty_dependencies(self, temp_project_dir, settings):
        """Test extraction when project has no dependencies."""
        pyproject_path = Path(temp_project_dir) / "pyproject.toml"
        pyproject_path.write_text("""
[project]
name = "empty-deps-project"
version = "1.0.0"
""")

        pylock_manager = PackageManagerPythonPip(temp_project_dir, settings)

        with open(pyproject_path, "rb") as f:
            pyproject_data = tomllib.load(f)

        direct_deps, optional_deps_map = pylock_manager.extract_pyproject_dependencies(pyproject_data)

        assert len(direct_deps) == 0
        assert len(optional_deps_map) == 0

    def test_extract_multiple_optional_categories(self, pylock_project_with_dual_category_deps, settings):
        """Test extraction with multiple optional dependency categories."""
        pylock_manager = PackageManagerPythonPip(pylock_project_with_dual_category_deps, settings)

        pyproject_path = Path(pylock_project_with_dual_category_deps) / "pyproject.toml"
        with open(pyproject_path, "rb") as f:
            pyproject_data = tomllib.load(f)

        direct_deps, optional_deps_map = pylock_manager.extract_pyproject_dependencies(pyproject_data)

        assert "dev" in optional_deps_map
        assert "test" in optional_deps_map
        assert "pytest" in optional_deps_map["dev"]
        assert "pytest" in optional_deps_map["test"]


# ============================================================================
# Test parse_lockfile_v1_0
# ============================================================================


class TestParseLockfileV10:
    """Test suite for parse_lockfile_v1_0() method."""

    def test_parse_basic_dependencies(self, pylock_project_basic, settings):
        """Test parsing main dependencies from lockfile."""
        pylock_manager = PackageManagerPythonPip(pylock_project_basic, settings)

        pyproject_path = Path(pylock_project_basic) / "pyproject.toml"
        lockfile_path = Path(pylock_project_basic) / "pylock.toml"

        with open(pyproject_path, "rb") as f:
            pyproject_data = tomllib.load(f)
        with open(lockfile_path, "rb") as f:
            pylock_data = tomllib.load(f)

        # Build enriched data with synthetic root (same as project_info does)
        direct_deps, optional_deps_map = pylock_manager.extract_pyproject_dependencies(pyproject_data)
        project_name = pyproject_data["project"]["name"]
        project_version = pyproject_data["project"]["version"]
        enriched = pylock_manager._build_enriched_pylock_data(
            project_name, project_version, direct_deps, optional_deps_map, pylock_data
        )

        dependency_tree = pylock_manager.parse_lockfile_v1_0(project_name, enriched)
        dependencies = dependency_tree.dependencies

        # Main dependencies should contain requests and click
        assert "requests@2.31.0" in dependencies
        assert "click@8.1.7" in dependencies
        assert dependencies["requests@2.31.0"].version_installed == "2.31.0"
        assert dependencies["click@8.1.7"].version_installed == "8.1.7"

    def test_parse_optional_dependencies(self, pylock_project_basic, settings):
        """Test parsing optional dependencies with categories."""
        pylock_manager = PackageManagerPythonPip(pylock_project_basic, settings)

        pyproject_path = Path(pylock_project_basic) / "pyproject.toml"
        lockfile_path = Path(pylock_project_basic) / "pylock.toml"

        with open(pyproject_path, "rb") as f:
            pyproject_data = tomllib.load(f)
        with open(lockfile_path, "rb") as f:
            pylock_data = tomllib.load(f)

        direct_deps, optional_deps_map = pylock_manager.extract_pyproject_dependencies(pyproject_data)
        project_name = pyproject_data["project"]["name"]
        project_version = pyproject_data["project"]["version"]
        enriched = pylock_manager._build_enriched_pylock_data(
            project_name, project_version, direct_deps, optional_deps_map, pylock_data
        )

        dependency_tree = pylock_manager.parse_lockfile_v1_0(project_name, enriched)
        optional_dependencies = dependency_tree.optional_dependencies

        # Optional dependencies should contain pytest and black
        assert "pytest@7.4.3" in optional_dependencies
        assert "black@23.12.1" in optional_dependencies
        assert optional_dependencies["pytest@7.4.3"].version_installed == "7.4.3"
        assert optional_dependencies["black@23.12.1"].version_installed == "23.12.1"

        # Verify categories are assigned
        assert "dev" in optional_dependencies["pytest@7.4.3"].categories
        assert "dev" in optional_dependencies["black@23.12.1"].categories

    def test_parse_transitive_dependencies_are_nested(self, pylock_project_basic, settings):
        """
        Test that transitive dependencies are nested under their parent,
        not directly on the root.
        """
        pylock_manager = PackageManagerPythonPip(pylock_project_basic, settings)

        pyproject_path = Path(pylock_project_basic) / "pyproject.toml"
        lockfile_path = Path(pylock_project_basic) / "pylock.toml"

        with open(pyproject_path, "rb") as f:
            pyproject_data = tomllib.load(f)
        with open(lockfile_path, "rb") as f:
            pylock_data = tomllib.load(f)

        direct_deps, optional_deps_map = pylock_manager.extract_pyproject_dependencies(pyproject_data)
        project_name = pyproject_data["project"]["name"]
        project_version = pyproject_data["project"]["version"]
        enriched = pylock_manager._build_enriched_pylock_data(
            project_name, project_version, direct_deps, optional_deps_map, pylock_data
        )

        dependency_tree = pylock_manager.parse_lockfile_v1_0(project_name, enriched)
        dependencies = dependency_tree.dependencies
        optional_dependencies = dependency_tree.optional_dependencies

        # Transitive dependencies should NOT be on root level
        assert "urllib3@2.0.4" not in dependencies
        assert "certifi@2023.7.22" not in dependencies
        assert "pluggy@1.3.0" not in dependencies
        assert "urllib3@2.0.4" not in optional_dependencies
        assert "certifi@2023.7.22" not in optional_dependencies
        assert "pluggy@1.3.0" not in optional_dependencies

        # But they should be nested under their parent
        requests_dep = dependencies["requests@2.31.0"]
        assert "urllib3@2.0.4" in requests_dep.dependencies
        assert "certifi@2023.7.22" in requests_dep.dependencies

    def test_parse_dual_category_dependencies(self, pylock_project_with_dual_category_deps, settings):
        """
        Test dependencies that appear in multiple categories.

        Tests the edge case where a package is both a main dependency
        and in multiple optional dependency categories.
        """
        pylock_manager = PackageManagerPythonPip(pylock_project_with_dual_category_deps, settings)

        pyproject_path = Path(pylock_project_with_dual_category_deps) / "pyproject.toml"
        lockfile_path = Path(pylock_project_with_dual_category_deps) / "pylock.toml"

        with open(pyproject_path, "rb") as f:
            pyproject_data = tomllib.load(f)
        with open(lockfile_path, "rb") as f:
            pylock_data = tomllib.load(f)

        direct_deps, optional_deps_map = pylock_manager.extract_pyproject_dependencies(pyproject_data)
        project_name = pyproject_data["project"]["name"]
        project_version = pyproject_data["project"]["version"]
        enriched = pylock_manager._build_enriched_pylock_data(
            project_name, project_version, direct_deps, optional_deps_map, pylock_data
        )

        dependency_tree = pylock_manager.parse_lockfile_v1_0(project_name, enriched)
        dependencies = dependency_tree.dependencies
        optional_dependencies = dependency_tree.optional_dependencies

        # requests should be in both main dependencies and optional
        assert "requests@2.31.0" in dependencies
        assert "requests@2.31.0" in optional_dependencies

        # requests should have 'dev' category
        assert "dev" in optional_dependencies["requests@2.31.0"].categories

        # pytest should be in multiple categories
        assert "pytest@7.4.3" in optional_dependencies
        assert "dev" in optional_dependencies["pytest@7.4.3"].categories
        assert "test" in optional_dependencies["pytest@7.4.3"].categories

    def test_parse_with_name_normalization(self, pylock_project_with_name_variations, settings):
        """Test that package name normalization works correctly during parsing."""
        pylock_manager = PackageManagerPythonPip(pylock_project_with_name_variations, settings)

        pyproject_path = Path(pylock_project_with_name_variations) / "pyproject.toml"
        lockfile_path = Path(pylock_project_with_name_variations) / "pylock.toml"

        with open(pyproject_path, "rb") as f:
            pyproject_data = tomllib.load(f)
        with open(lockfile_path, "rb") as f:
            pylock_data = tomllib.load(f)

        direct_deps, optional_deps_map = pylock_manager.extract_pyproject_dependencies(pyproject_data)
        project_name = pyproject_data["project"]["name"]
        project_version = pyproject_data["project"]["version"]
        enriched = pylock_manager._build_enriched_pylock_data(
            project_name, project_version, direct_deps, optional_deps_map, pylock_data
        )

        dependency_tree = pylock_manager.parse_lockfile_v1_0(project_name, enriched)
        dependencies = dependency_tree.dependencies

        # All packages should match despite name variations
        assert "requests@2.31.0" in dependencies  # requests[security] matched
        assert "django@4.2.7" in dependencies  # Django matched
        assert "some-package@1.2.0" in dependencies  # some_package matched

    def test_parse_empty_dependencies(self, temp_project_dir, settings):
        """Test parsing when project has no dependencies."""
        pyproject_path = Path(temp_project_dir) / "pyproject.toml"
        lockfile_path = Path(temp_project_dir) / "pylock.toml"

        pyproject_path.write_text("""
[project]
name = "empty-deps-project"
version = "1.0.0"
""")

        lockfile_path.write_text("""
lock-version = "1.0"
created-by = "test-suite"
""")

        pylock_manager = PackageManagerPythonPip(temp_project_dir, settings)

        with open(pyproject_path, "rb") as f:
            pyproject_data = tomllib.load(f)
        with open(lockfile_path, "rb") as f:
            pylock_data = tomllib.load(f)

        direct_deps, optional_deps_map = pylock_manager.extract_pyproject_dependencies(pyproject_data)
        enriched = pylock_manager._build_enriched_pylock_data(
            "empty-deps-project", "1.0.0", direct_deps, optional_deps_map, pylock_data
        )

        dependency_tree = pylock_manager.parse_lockfile_v1_0("empty-deps-project", enriched)
        dependencies = dependency_tree.dependencies
        optional_dependencies = dependency_tree.optional_dependencies

        assert len(dependencies) == 0
        assert len(optional_dependencies) == 0


# ============================================================================
# Test get_lockfile_parser
# ============================================================================


class TestGetLockfileParser:
    """Test suite for get_lockfile_parser() method."""

    def test_get_parser_v1_0(self, pylock_project_basic, settings):
        """Test getting parser for version 1.0."""
        pylock_manager = PackageManagerPythonPip(pylock_project_basic, settings)

        parser = pylock_manager.get_lockfile_parser("1.0")

        assert parser is not None
        assert parser == pylock_manager.parse_lockfile_v1_0

    def test_get_parser_unsupported_version(self, pylock_project_basic, settings):
        """Test error for unsupported lockfile version."""
        pylock_manager = PackageManagerPythonPip(pylock_project_basic, settings)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            pylock_manager.get_lockfile_parser("99.0")

        assert "There's no parser for pylock.toml lock-version `99.0`" in str(excinfo.value)

    def test_get_parser_with_none_version(self, pylock_project_basic, settings):
        """Test error when version is None."""
        pylock_manager = PackageManagerPythonPip(pylock_project_basic, settings)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            pylock_manager.get_lockfile_parser(None)

        assert "There's no parser for pylock.toml lock-version `None`" in str(excinfo.value)


# ============================================================================
# Test project_info
# ============================================================================


class TestProjectInfo:
    """Test suite for project_info() method."""

    def test_project_info_basic(self, pylock_project_basic, settings):
        """Test extracting project info from a basic pylock project."""
        pylock_manager = PackageManagerPythonPip(pylock_project_basic, settings)

        project = pylock_manager.project_info()

        assert project.name == "test-pylock-project"
        assert project.project_path == pylock_project_basic
        assert project.package_manager_type == PIP

        # Check main dependencies
        assert "requests@2.31.0" in project.dependencies
        assert "click@8.1.7" in project.dependencies
        assert project.dependencies["requests@2.31.0"].version_installed == "2.31.0"
        assert project.dependencies["click@8.1.7"].version_installed == "8.1.7"

        # Check optional dependencies
        assert "pytest@7.4.3" in project.optional_dependencies
        assert "black@23.12.1" in project.optional_dependencies

    def test_project_info_with_dual_category_deps(self, pylock_project_with_dual_category_deps, settings):
        """Test project with dependencies in multiple categories."""
        pylock_manager = PackageManagerPythonPip(pylock_project_with_dual_category_deps, settings)

        project = pylock_manager.project_info()

        assert project.name == "multi-category-project"

        # requests is both main and optional
        assert "requests@2.31.0" in project.dependencies
        assert "requests@2.31.0" in project.optional_dependencies

        # pytest is in multiple optional categories
        assert "pytest@7.4.3" in project.optional_dependencies
        pytest_dep = project.optional_dependencies["pytest@7.4.3"]
        assert "dev" in pytest_dep.categories
        assert "test" in pytest_dep.categories

    def test_project_info_fallback_name(self, temp_project_dir, settings):
        """Test that project name falls back to directory name if not in pyproject.toml."""
        pyproject_path = Path(temp_project_dir) / "pyproject.toml"
        lockfile_path = Path(temp_project_dir) / "pylock.toml"

        # pyproject.toml without [project] name
        pyproject_path.write_text("""
[build-system]
requires = ["setuptools"]
""")

        # Minimal lockfile
        lockfile_path.write_text("""
lock-version = "1.0"
created-by = "test-suite"
""")

        pylock_manager = PackageManagerPythonPip(temp_project_dir, settings)

        project = pylock_manager.project_info()

        # Should use directory name as fallback
        assert project.name == os.path.basename(temp_project_dir)

    def test_project_info_unsupported_lockfile_version(self, pylock_project_unsupported_version, settings):
        """Test error when lockfile version is unsupported."""
        pylock_manager = PackageManagerPythonPip(pylock_project_unsupported_version, settings)

        with pytest.raises(PackageManagerLockfileParsingError) as excinfo:
            pylock_manager.project_info()

        assert "There's no parser for pylock.toml lock-version `99.0`" in str(excinfo.value)

    def test_project_info_with_name_variations(self, pylock_project_with_name_variations, settings):
        """Test project info with package name normalization edge cases."""
        pylock_manager = PackageManagerPythonPip(pylock_project_with_name_variations, settings)

        project = pylock_manager.project_info()

        # All packages should match despite name variations
        assert "requests@2.31.0" in project.dependencies
        assert "django@4.2.7" in project.dependencies
        assert "some-package@1.2.0" in project.dependencies

    def test_project_info_package_registry(self, pylock_project_basic, settings):
        """Test that project has correct package registry."""
        pylock_manager = PackageManagerPythonPip(pylock_project_basic, settings)

        project = pylock_manager.project_info()

        # pylock uses PyPI ecosystem

        assert project.package_registry == ProjectPackagesRegistry.PYPI

    def test_project_info_with_editable_self_package(self, pylock_project_with_editable_self, settings):
        """Test that directory/editable packages without version are skipped.

        When pylock.toml is generated by `uv export`, the project itself appears
        as a [[packages]] entry with a `directory` field but no `version` field.
        The resolver should skip this entry and use the synthetic root instead.
        """
        pylock_manager = PackageManagerPythonPip(pylock_project_with_editable_self, settings)

        project = pylock_manager.project_info()

        assert project.name == "my-app"
        assert "requests@2.31.0" in project.dependencies
        assert "click@8.1.7" in project.dependencies

    def test_project_info_with_vcs_packages(self, pylock_project_with_vcs_packages, settings):
        """Test that VCS packages without version field are skipped.

        VCS packages in pylock.toml may not have a version field. The resolver
        should skip these entries without raising a KeyError.
        """
        pylock_manager = PackageManagerPythonPip(pylock_project_with_vcs_packages, settings)

        project = pylock_manager.project_info()

        assert project.name == "vcs-project"
        assert "requests@2.31.0" in project.dependencies
        # VCS package without version should not appear in the dependency tree
        assert not any("my-vcs-package" in key for key in project.dependencies)
