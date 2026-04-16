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
from ossiq.domain.common import ConstraintType
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.packages_manager import PIP_CLASSIC
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
    - Pinned (==) versions
    - Range specifiers (>=, ~=, compound)
    - Extras
    - Comments and blank lines
    - Editable installs (skipped)
    - VCS dependencies (skipped)
    - URL dependencies (skipped)
    - Bare names without version (skipped)
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


# Editable install (skipped)
-e file:///Users/max/Projects/my-project

# VCS dependency (skipped)
git+https://github.com/user/repo.git@v1.0#egg=package

# URL dependency (skipped)
https://files.pythonhosted.org/packages/some-package-1.0.tar.gz

# Range specifier — now parsed as NARROWED
numpy>=1.20.0

# Compatible-release specifier — NARROWED
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

        lines = adapter.read_requirements_lines(manifest_path)

        assert isinstance(lines, list)
        assert len(lines) > 0
        assert any("requests" in line for line in lines)

    def test_read_requirements_lines_file_not_found(self, temp_project_dir, settings):
        """Test _read_requirements_lines raises error for missing file."""
        adapter = PackageManagerPythonPipClassic(temp_project_dir, settings)
        nonexistent_path = os.path.join(temp_project_dir, "nonexistent.txt")

        with pytest.raises(PackageManagerLockfileParsingError, match="requirements.txt not found"):
            adapter.read_requirements_lines(nonexistent_path)

    def test_parse_requirement_exact_pin(self):
        """Test _parse_requirement extracts package, no extras, and == specifier."""
        result = PackageManagerPythonPipClassic.parse_requirement("requests==2.31.0")
        assert result == ("requests", None, "==2.31.0")

    def test_parse_requirement_with_extras(self):
        """Test _parse_requirement parses extras as a list."""
        result = PackageManagerPythonPipClassic.parse_requirement("pydantic[email]==2.5.0")
        assert result == ("pydantic[email]", ["email"], "==2.5.0")

    def test_parse_requirement_multiple_extras(self):
        """Test _parse_requirement handles multiple extras."""
        result = PackageManagerPythonPipClassic.parse_requirement("requests[security,tests]>=2.28.0")
        assert result == ("requests[security,tests]", ["security", "tests"], ">=2.28.0")

    def test_parse_requirement_range_specifier(self):
        """Test _parse_requirement handles range specifiers."""
        result = PackageManagerPythonPipClassic.parse_requirement("numpy>=1.20.0")
        assert result == ("numpy", None, ">=1.20.0")

        result = PackageManagerPythonPipClassic.parse_requirement("pandas~=2.0.0")
        assert result == ("pandas", None, "~=2.0.0")

    def test_parse_requirement_compound_specifier(self):
        """Test _parse_requirement captures compound specifiers as a single string."""
        result = PackageManagerPythonPipClassic.parse_requirement("django>=4.0,<5.0")
        assert result == ("django", None, ">=4.0,<5.0")

    def test_parse_requirement_bare_name(self):
        """Test _parse_requirement returns (name, None, None) for bare package names."""
        result = PackageManagerPythonPipClassic.parse_requirement("requests")
        assert result == ("requests", None, None)

    def test_parse_requirement_environment_marker(self):
        """Test _parse_requirement handles environment markers (ignores after ;)."""
        result = PackageManagerPythonPipClassic.parse_requirement('certifi==2023.11.17; python_version >= "3.8"')
        assert result == ("certifi", None, "==2023.11.17")

    def test_parse_requirement_empty_line(self):
        """Test _parse_requirement returns None for empty line."""
        assert PackageManagerPythonPipClassic.parse_requirement("") is None

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

    def test_requirement_pattern_exact_pin(self):
        """Test _REQUIREMENT_PATTERN matches exact pinned deps."""
        from ossiq.adapters.package_managers.api_pip_classic import _REQUIREMENT_PATTERN

        match = _REQUIREMENT_PATTERN.match("requests==2.31.0")
        assert match is not None
        assert match.group(1) == "requests"
        assert match.group(2) is None
        assert match.group(3) == "==2.31.0"

    def test_requirement_pattern_extras(self):
        """Test _REQUIREMENT_PATTERN captures extras."""
        from ossiq.adapters.package_managers.api_pip_classic import _REQUIREMENT_PATTERN

        match = _REQUIREMENT_PATTERN.match("pydantic[email]==2.5.0")
        assert match is not None
        assert match.group(1) == "pydantic"
        assert match.group(2) == "[email]"
        assert match.group(3) == "==2.5.0"

    def test_requirement_pattern_range_specifier(self):
        """Test _REQUIREMENT_PATTERN matches range specifiers."""
        from ossiq.adapters.package_managers.api_pip_classic import _REQUIREMENT_PATTERN

        match = _REQUIREMENT_PATTERN.match("numpy>=1.20.0")
        assert match is not None
        assert match.group(3) == ">=1.20.0"

    def test_requirement_pattern_bare_name(self):
        """Test _REQUIREMENT_PATTERN matches bare package name (no version)."""
        from ossiq.adapters.package_managers.api_pip_classic import _REQUIREMENT_PATTERN

        match = _REQUIREMENT_PATTERN.match("requests")
        assert match is not None
        assert match.group(1) == "requests"
        assert match.group(3) is None

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

        # Expected: requests, pydantic, click, numpy, pandas, some-package,
        #           django-rest-framework, certifi  (range specifiers now parsed too)
        assert len(dependencies) == 8

        # Check basic pinned — should be PINNED
        assert "requests" in dependencies
        assert dependencies["requests"].version_installed == "2.31.0"
        assert dependencies["requests"].version_defined == "==2.31.0"
        assert dependencies["requests"].constraint_info.type == ConstraintType.PINNED

        # Check extras stored in structured field
        assert "pydantic" in dependencies
        assert dependencies["pydantic"].name == "pydantic[email]"
        assert dependencies["pydantic"].version_installed == "2.5.0"
        assert dependencies["pydantic"].extras == ["email"]
        assert dependencies["pydantic"].constraint_info.type == ConstraintType.PINNED

        # Check inline comment handled
        assert "click" in dependencies
        assert dependencies["click"].version_installed == "8.1.7"

        # Range specifier — NARROWED, not skipped
        assert "numpy" in dependencies
        assert dependencies["numpy"].version_defined == ">=1.20.0"
        assert dependencies["numpy"].constraint_info.type == ConstraintType.DECLARED  # single lower-bound

        # Compatible-release — NARROWED
        assert "pandas" in dependencies
        assert dependencies["pandas"].version_defined == "~=2.0.0"
        assert dependencies["pandas"].constraint_info.type == ConstraintType.NARROWED

        # Check underscore normalization
        assert "some-package" in dependencies  # Normalized from some_package
        assert dependencies["some-package"].version_installed == "1.2.3"

        # Check hyphen preserved
        assert "django-rest-framework" in dependencies
        assert dependencies["django-rest-framework"].version_installed == "3.14.0"

        # Check environment marker handled (version extracted, marker ignored)
        assert "certifi" in dependencies
        assert dependencies["certifi"].version_installed == "2023.11.17"

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

        # 8 deps: pinned + range specifiers (numpy, pandas now parsed)
        assert len(project.dependencies) == 8

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
