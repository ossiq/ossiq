"""
Tests for PackageManagerPythonPipClassic adapter.

Tests focus on:
1. Static methods (has_package_manager, project_files)
2. Requirements.txt parsing for various edge cases
3. Project info extraction
4. Error handling
"""

import os
import tempfile
from pathlib import Path

import pytest

from ossiq.adapters.package_managers.api_pip_classic import PackageManagerPythonPipClassic
from ossiq.domain.ecosystem import PIP_CLASSIC
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
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
def pip_classic_project_basic(temp_project_dir):
    """
    Create a temporary classic pip project with requirements.txt.

    Returns a project with:
    - Main dependencies: requests==2.31.0, click==8.1.7
    """
    requirements_path = Path(temp_project_dir) / "requirements.txt"

    requirements_content = """# Production dependencies
requests==2.31.0
click==8.1.7
"""
    requirements_path.write_text(requirements_content)

    return temp_project_dir


@pytest.fixture
def pip_classic_project_complex(temp_project_dir):
    """
    Create a requirements.txt with various edge cases.

    Includes:
    - Pinned versions
    - Extras
    - Comments
    - Blank lines
    - Editable installs (should be skipped)
    - VCS dependencies (should be skipped)
    - Range specifiers (should be skipped)
    """
    requirements_path = Path(temp_project_dir) / "requirements.txt"

    requirements_content = """# Test requirements.txt with edge cases

# Basic pinned dependency
requests==2.31.0

# Dependency with extras
pydantic[email]==2.5.0

# Inline comment
click==8.1.7  # CLI framework

# Blank lines above and below


# Editable install (should be skipped)
-e file:///Users/max/Projects/my-project

# VCS dependency (should be skipped)
git+https://github.com/user/repo.git@v1.0#egg=package

# URL dependency (should be skipped)
https://files.pythonhosted.org/packages/some-package-1.0.tar.gz

# Range specifier (should be skipped)
numpy>=1.20.0

# Another range specifier
pandas~=2.0.0

# Valid pinned with underscore
some_package==1.2.3

# Valid pinned with hyphen
django-rest-framework==3.14.0

# Environment marker (version should be extracted)
certifi==2023.11.17; python_version >= "3.8"
"""
    requirements_path.write_text(requirements_content)

    return temp_project_dir


# ============================================================================
# Test Static Methods
# ============================================================================


class TestStaticMethods:
    """Test static methods of PackageManagerPythonPipClassic."""

    def test_project_files(self, temp_project_dir):
        """Test project_files returns correct file path."""
        project_files = PackageManagerPythonPipClassic.project_files(temp_project_dir)

        expected_manifest = os.path.join(temp_project_dir, "requirements.txt")
        assert project_files.manifest == expected_manifest

    def test_has_package_manager_with_requirements_txt(self, pip_classic_project_basic):
        """Test has_package_manager returns True when requirements.txt exists."""
        result = PackageManagerPythonPipClassic.has_package_manager(pip_classic_project_basic)
        assert result is True

    def test_has_package_manager_without_requirements_txt(self, temp_project_dir):
        """Test has_package_manager returns False when requirements.txt doesn't exist."""
        result = PackageManagerPythonPipClassic.has_package_manager(temp_project_dir)
        assert result is False


# ============================================================================
# Test Package Name Normalization
# ============================================================================


class TestPackageNameNormalization:
    """Test package name normalization according to PEP 503."""

    def test_normalize_simple_name(self):
        """Test normalization of simple package name."""
        result = PackageManagerPythonPipClassic.normalize_package_name("Requests")
        assert result == "requests"

    def test_normalize_with_extras(self):
        """Test normalization removes extras."""
        result = PackageManagerPythonPipClassic.normalize_package_name("requests[security]")
        assert result == "requests"

    def test_normalize_with_hyphens(self):
        """Test normalization preserves hyphens."""
        result = PackageManagerPythonPipClassic.normalize_package_name("Django-REST-Framework")
        assert result == "django-rest-framework"

    def test_normalize_with_underscores(self):
        """Test normalization converts underscores to hyphens."""
        result = PackageManagerPythonPipClassic.normalize_package_name("some_package")
        assert result == "some-package"

    def test_normalize_mixed_case_with_extras(self):
        """Test normalization handles mixed case and extras."""
        result = PackageManagerPythonPipClassic.normalize_package_name("PyDantic[email]")
        assert result == "pydantic"


# ============================================================================
# Test Requirements.txt Parsing
# ============================================================================


class TestRequirementsParsing:
    """Test parsing of requirements.txt file."""

    def test_parse_basic_requirements(self, pip_classic_project_basic, settings):
        """Test parsing simple requirements.txt with pinned versions."""
        adapter = PackageManagerPythonPipClassic(pip_classic_project_basic, settings)
        dependencies = adapter.parse_requirements_txt()

        # Should have 2 dependencies
        assert len(dependencies) == 2

        # Check requests
        assert "requests" in dependencies
        assert dependencies["requests"].name == "requests"
        assert dependencies["requests"].version_installed == "2.31.0"
        assert dependencies["requests"].version_defined == "==2.31.0"
        assert dependencies["requests"].categories == []

        # Check click
        assert "click" in dependencies
        assert dependencies["click"].version_installed == "8.1.7"

    def test_parse_complex_requirements(self, pip_classic_project_complex, settings):
        """Test parsing requirements.txt with edge cases."""
        adapter = PackageManagerPythonPipClassic(pip_classic_project_complex, settings)
        dependencies = adapter.parse_requirements_txt()

        # Should parse only pinned dependencies
        # Expected: requests, pydantic, click, some-package, django-rest-framework, certifi
        assert len(dependencies) == 6

        # Check basic pinned
        assert "requests" in dependencies
        assert dependencies["requests"].version_installed == "2.31.0"

        # Check extras (extras should be in name but not in key)
        assert "pydantic" in dependencies
        assert dependencies["pydantic"].name == "pydantic[email]"
        assert dependencies["pydantic"].version_installed == "2.5.0"

        # Check inline comment handled
        assert "click" in dependencies
        assert dependencies["click"].version_installed == "8.1.7"

        # Check underscore normalization
        assert "some-package" in dependencies  # Normalized from some_package
        assert dependencies["some-package"].version_installed == "1.2.3"

        # Check hyphen preserved
        assert "django-rest-framework" in dependencies
        assert dependencies["django-rest-framework"].version_installed == "3.14.0"

        # Check environment marker handled (version extracted, marker ignored)
        assert "certifi" in dependencies
        assert dependencies["certifi"].version_installed == "2023.11.17"

        # Ensure skipped entries are NOT present
        assert "numpy" not in dependencies  # Range specifier
        assert "pandas" not in dependencies  # Range specifier

    def test_parse_missing_file(self, temp_project_dir, settings):
        """Test parsing raises error when requirements.txt doesn't exist."""
        adapter = PackageManagerPythonPipClassic(temp_project_dir, settings)

        with pytest.raises(PackageManagerLockfileParsingError, match="requirements.txt not found"):
            adapter.parse_requirements_txt()

    def test_parse_empty_file(self, temp_project_dir, settings):
        """Test parsing empty requirements.txt returns empty dict."""
        requirements_path = Path(temp_project_dir) / "requirements.txt"
        requirements_path.write_text("")

        adapter = PackageManagerPythonPipClassic(temp_project_dir, settings)
        dependencies = adapter.parse_requirements_txt()

        assert dependencies == {}

    def test_parse_comments_only(self, temp_project_dir, settings):
        """Test parsing requirements.txt with only comments."""
        requirements_path = Path(temp_project_dir) / "requirements.txt"
        requirements_path.write_text("# Only comments\n# No actual dependencies\n")

        adapter = PackageManagerPythonPipClassic(temp_project_dir, settings)
        dependencies = adapter.parse_requirements_txt()

        assert dependencies == {}


# ============================================================================
# Test Project Info Extraction
# ============================================================================


class TestProjectInfo:
    """Test project_info method."""

    def test_project_info_basic(self, pip_classic_project_basic, settings):
        """Test project_info extraction from basic requirements.txt."""
        adapter = PackageManagerPythonPipClassic(pip_classic_project_basic, settings)
        project = adapter.project_info()

        # Check project metadata
        assert project.package_manager == PIP_CLASSIC
        assert project.name == os.path.basename(pip_classic_project_basic)
        assert project.project_path == pip_classic_project_basic

        # Check dependencies
        assert len(project.dependencies) == 2
        assert "requests" in project.dependencies
        assert "click" in project.dependencies

        # Check no optional dependencies
        assert len(project.optional_dependencies) == 0

    def test_project_info_complex(self, pip_classic_project_complex, settings):
        """Test project_info extraction from complex requirements.txt."""
        adapter = PackageManagerPythonPipClassic(pip_classic_project_complex, settings)
        project = adapter.project_info()

        # Should have 6 valid dependencies
        assert len(project.dependencies) == 6

        # Check no optional dependencies
        assert len(project.optional_dependencies) == 0


# ============================================================================
# Test Integration with Existing Test Data
# ============================================================================


class TestRealTestData:
    """Test against actual testdata/pypi/pip-classic/requirements.txt."""

    def test_parse_real_testdata(self, settings):
        """Test parsing the real requirements.txt from testdata."""
        testdata_path = "/Users/max/Projects/ossiq/ossiq-cli/testdata/pypi/pip-classic"

        # Verify test data exists
        requirements_file = os.path.join(testdata_path, "requirements.txt")
        if not os.path.exists(requirements_file):
            pytest.skip("Test data not available")

        adapter = PackageManagerPythonPipClassic(testdata_path, settings)

        # Should detect the package manager
        assert PackageManagerPythonPipClassic.has_package_manager(testdata_path)

        # Parse dependencies
        dependencies = adapter.parse_requirements_txt()

        # Should have many dependencies (based on the file we saw)
        assert len(dependencies) >= 80  # Most should be pinned

        # Verify specific known packages
        assert "annotated-types" in dependencies
        assert dependencies["annotated-types"].version_installed == "0.7.0"

        assert "anyio" in dependencies
        assert dependencies["anyio"].version_installed == "4.11.0"

        # Get project info
        project = adapter.project_info()
        assert project.name == "pip-classic"
        assert len(project.dependencies) >= 80
        assert len(project.optional_dependencies) == 0
