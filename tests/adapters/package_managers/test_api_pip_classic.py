# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
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
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import PIP_CLASSIC
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
# Test Internal Helper Methods
# ============================================================================


class TestInternalHelpers:
    """Test internal helper methods and module-level patterns."""

    def test_read_requirements_lines_success(self, pip_classic_project_basic, settings):
        """Test _read_requirements_lines successfully reads file."""
        adapter = PackageManagerPythonPipClassic(pip_classic_project_basic, settings)
        manifest_path = adapter.project_files(pip_classic_project_basic).manifest

        lines = adapter._read_requirements_lines(manifest_path)

        assert isinstance(lines, list)
        assert len(lines) > 0
        assert any("requests" in line for line in lines)

    def test_read_requirements_lines_file_not_found(self, temp_project_dir, settings):
        """Test _read_requirements_lines raises error for missing file."""
        adapter = PackageManagerPythonPipClassic(temp_project_dir, settings)
        nonexistent_path = os.path.join(temp_project_dir, "nonexistent.txt")

        with pytest.raises(PackageManagerLockfileParsingError, match="requirements.txt not found"):
            adapter._read_requirements_lines(nonexistent_path)

    def test_parse_pinned_requirement_success(self):
        """Test _parse_pinned_requirement extracts package and version."""
        result = PackageManagerPythonPipClassic._parse_pinned_requirement("requests==2.31.0")
        assert result == ("requests", "2.31.0")

    def test_parse_pinned_requirement_with_extras(self):
        """Test _parse_pinned_requirement handles extras."""
        result = PackageManagerPythonPipClassic._parse_pinned_requirement("pydantic[email]==2.5.0")
        assert result == ("pydantic[email]", "2.5.0")

    def test_parse_pinned_requirement_with_environment_marker(self):
        """Test _parse_pinned_requirement handles environment markers."""
        line = 'certifi==2023.11.17; python_version >= "3.8"'
        result = PackageManagerPythonPipClassic._parse_pinned_requirement(line)
        assert result == ("certifi", "2023.11.17")

    def test_parse_pinned_requirement_range_specifier(self):
        """Test _parse_pinned_requirement returns None for range specifiers."""
        assert PackageManagerPythonPipClassic._parse_pinned_requirement("numpy>=1.20.0") is None
        assert PackageManagerPythonPipClassic._parse_pinned_requirement("pandas~=2.0.0") is None
        assert PackageManagerPythonPipClassic._parse_pinned_requirement("flask>2.0") is None

    def test_parse_pinned_requirement_empty_line(self):
        """Test _parse_pinned_requirement returns None for empty line."""
        assert PackageManagerPythonPipClassic._parse_pinned_requirement("") is None

    def test_skip_line_pattern_pip_options(self):
        """Test module-level _SKIP_LINE_PATTERN matches pip options."""
        from ossiq.adapters.package_managers.api_pip_classic import _SKIP_LINE_PATTERN

        # Should match various pip options
        assert _SKIP_LINE_PATTERN.match("-e file:///path/to/package")
        assert _SKIP_LINE_PATTERN.match("--editable file:///path/to/package")
        assert _SKIP_LINE_PATTERN.match("-r other-requirements.txt")
        assert _SKIP_LINE_PATTERN.match("--requirement other-requirements.txt")
        assert _SKIP_LINE_PATTERN.match("-c constraints.txt")

    def test_skip_line_pattern_vcs_dependencies(self):
        """Test module-level _SKIP_LINE_PATTERN matches VCS dependencies."""
        from ossiq.adapters.package_managers.api_pip_classic import _SKIP_LINE_PATTERN

        assert _SKIP_LINE_PATTERN.match("git+https://github.com/user/repo.git")
        assert _SKIP_LINE_PATTERN.match("hg+https://hg.example.com/repo")
        assert _SKIP_LINE_PATTERN.match("svn+https://svn.example.com/repo")
        assert _SKIP_LINE_PATTERN.match("bzr+https://bzr.example.com/repo")

    def test_skip_line_pattern_url_dependencies(self):
        """Test module-level _SKIP_LINE_PATTERN matches URL dependencies."""
        from ossiq.adapters.package_managers.api_pip_classic import _SKIP_LINE_PATTERN

        assert _SKIP_LINE_PATTERN.match("https://files.pythonhosted.org/packages/package.tar.gz")
        assert _SKIP_LINE_PATTERN.match("http://example.com/package.whl")
        assert _SKIP_LINE_PATTERN.match("file:///local/path/to/package.tar.gz")

    def test_skip_line_pattern_normal_packages(self):
        """Test module-level _SKIP_LINE_PATTERN does NOT match normal packages."""
        from ossiq.adapters.package_managers.api_pip_classic import _SKIP_LINE_PATTERN

        # Should NOT match normal package specifications
        assert not _SKIP_LINE_PATTERN.match("requests==2.31.0")
        assert not _SKIP_LINE_PATTERN.match("Django>=3.2")
        assert not _SKIP_LINE_PATTERN.match("pydantic[email]~=2.0")

    def test_pinned_dependency_pattern_valid(self):
        """Test module-level _PINNED_DEPENDENCY_PATTERN matches pinned deps."""
        from ossiq.adapters.package_managers.api_pip_classic import _PINNED_DEPENDENCY_PATTERN

        match = _PINNED_DEPENDENCY_PATTERN.match("requests==2.31.0")
        assert match is not None
        assert match.group(1) == "requests"
        assert match.group(2) == "2.31.0"

        # With extras
        match = _PINNED_DEPENDENCY_PATTERN.match("pydantic[email]==2.5.0")
        assert match is not None
        assert match.group(1) == "pydantic[email]"
        assert match.group(2) == "2.5.0"

    def test_pinned_dependency_pattern_invalid(self):
        """Test module-level _PINNED_DEPENDENCY_PATTERN doesn't match invalid."""
        from ossiq.adapters.package_managers.api_pip_classic import _PINNED_DEPENDENCY_PATTERN

        assert not _PINNED_DEPENDENCY_PATTERN.match("requests>=2.31.0")
        assert not _PINNED_DEPENDENCY_PATTERN.match("requests~=2.31.0")
        assert not _PINNED_DEPENDENCY_PATTERN.match("requests")

    def test_extras_pattern(self):
        """Test module-level _EXTRAS_PATTERN removes extras."""
        from ossiq.adapters.package_managers.api_pip_classic import _EXTRAS_PATTERN

        assert _EXTRAS_PATTERN.sub("", "requests[security]") == "requests"
        assert _EXTRAS_PATTERN.sub("", "pydantic[email,dotenv]") == "pydantic"
        assert _EXTRAS_PATTERN.sub("", "package") == "package"


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
        assert project.package_manager_type == PIP_CLASSIC
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
