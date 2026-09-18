# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for PackageManagerPythonPep621 adapter.

Tests focus on:
1. has_package_manager detection (matches only a bare pyproject.toml with [project].dependencies)
2. project_info() parsing of [project].dependencies / [project.optional-dependencies]
3. Interaction with the uv/pylock/pip-classic fixtures that must NOT match this adapter
"""

import tempfile
from pathlib import Path

import pytest

from ossiq.adapters.package_managers.api import create_package_managers
from ossiq.adapters.package_managers.api_pep621 import PackageManagerPythonPep621
from ossiq.adapters.package_managers.api_uv import PackageManagerPythonUv
from ossiq.domain.common import ConstraintType, ProjectPackagesRegistry
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
def pep621_project_no_lockfile(temp_project_dir):
    """A fresh `uv init`-style project: PEP 621 dependencies declared, no lockfile yet."""
    pyproject_path = Path(temp_project_dir) / "pyproject.toml"
    pyproject_path.write_text(
        """
[project]
name = "no-lockfile-project"
version = "0.1.0"
dependencies = [
    "requests>=2.31.0",
    "click>=8.1.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
]
"""
    )
    return temp_project_dir


# ============================================================================
# Test has_package_manager
# ============================================================================


class TestHasPackageManager:
    def test_matches_bare_pyproject_with_dependencies(self, pep621_project_no_lockfile):
        assert PackageManagerPythonPep621.has_package_manager(pep621_project_no_lockfile) is True

    def test_no_pyproject_toml_does_not_match(self, temp_project_dir):
        assert PackageManagerPythonPep621.has_package_manager(temp_project_dir) is False

    def test_empty_dependencies_list_does_not_match(self, temp_project_dir):
        """An empty [project].dependencies must not match - it's indistinguishable from a
        project that simply has no dependencies yet, and matching it risks false-positiving
        on a pure-Poetry manifest whose [project] table (if any) never lists dependencies."""
        pyproject_path = Path(temp_project_dir) / "pyproject.toml"
        pyproject_path.write_text('[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = []\n')
        assert PackageManagerPythonPep621.has_package_manager(temp_project_dir) is False

    def test_absent_project_table_does_not_match(self, temp_project_dir):
        """A pure-Poetry pyproject.toml (no [project] table at all) must not match."""
        pyproject_path = Path(temp_project_dir) / "pyproject.toml"
        pyproject_path.write_text(
            '[tool.poetry]\nname = "demo"\nversion = "0.1.0"\n\n'
            '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "^2.31.0"\n'
        )
        assert PackageManagerPythonPep621.has_package_manager(temp_project_dir) is False

    def test_malformed_toml_does_not_match(self, temp_project_dir):
        pyproject_path = Path(temp_project_dir) / "pyproject.toml"
        pyproject_path.write_text("not valid toml [[[")
        assert PackageManagerPythonPep621.has_package_manager(temp_project_dir) is False

    def test_a_uv_project_also_matches_this_predicate(self, temp_project_dir):
        """has_package_manager answers only "does this tree look like mine?". A uv project does
        look like a PEP 621 project - it has a pyproject.toml with dependencies - and saying so is
        correct. Which adapter actually drives the scan is the registry's call, not this one's;
        the predicate used to call its two siblings' checks to break that tie itself.
        """
        pyproject_path = Path(temp_project_dir) / "pyproject.toml"
        pyproject_path.write_text('[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["requests"]\n')
        (Path(temp_project_dir) / "uv.lock").write_text("version = 1\nrevision = 3\n")

        assert PackageManagerPythonUv.has_package_manager(temp_project_dir) is True
        assert PackageManagerPythonPep621.has_package_manager(temp_project_dir) is True


class TestCreatePackageManagers:
    """create_package_managers() is what ProjectSources.__enter__() actually calls; these
    exercise api.py's PACKAGE_MANAGERS registration and ordering directly."""

    def test_selects_pep621_for_lockfile_less_pyproject(self, pep621_project_no_lockfile, settings):
        managers = list(create_package_managers(pep621_project_no_lockfile, settings))
        assert len(managers) == 1
        assert isinstance(managers[0], PackageManagerPythonPep621)

    def test_uv_wins_over_pep621_when_a_lockfile_is_present(self, temp_project_dir, settings):
        """Both adapters' predicates match this tree; PACKAGE_MANAGERS' order decides. Yielding
        both would hand ProjectSources two PyPI adapters and spuriously trip its "multiple
        registry types" ambiguity warning."""
        pyproject_path = Path(temp_project_dir) / "pyproject.toml"
        pyproject_path.write_text('[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["requests>=2.31.0"]\n')
        lockfile_path = Path(temp_project_dir) / "uv.lock"
        lockfile_path.write_text('version = 1\nrevision = 3\n\n[[package]]\nname = "demo"\nversion = "0.1.0"\n')
        managers = list(create_package_managers(temp_project_dir, settings))
        assert len(managers) == 1
        assert isinstance(managers[0], PackageManagerPythonUv)

    def test_requirements_txt_beside_pyproject_yields_one_pypi_adapter(self, temp_project_dir, settings):
        """Regression: pip-classic and pep621 both match this tree, and both are PyPI. Before
        precedence moved into the registry, create_package_managers yielded both and every scan of
        such a project warned about "multiple registry types" that were in fact one registry.
        """
        (Path(temp_project_dir) / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["requests>=2.31.0"]\n'
        )
        (Path(temp_project_dir) / "requirements.txt").write_text("requests>=2.31.0\n")

        managers = list(create_package_managers(temp_project_dir, settings))

        assert len(managers) == 1
        assert isinstance(managers[0], PackageManagerPythonPep621)

    def test_mixed_tree_still_yields_one_adapter_per_registry(self, settings):
        """The genuine multi-ecosystem case must keep yielding both - first-match-wins is per
        registry, not global."""
        managers = list(create_package_managers("testdata/mixed", settings))

        registries = {m.package_manager_type.package_registry for m in managers}
        assert len(managers) == 2
        assert registries == {ProjectPackagesRegistry.NPM, ProjectPackagesRegistry.PYPI}


# ============================================================================
# Test project_info
# ============================================================================


class TestProjectInfo:
    def test_has_lockfile_is_false(self, pep621_project_no_lockfile, settings):
        pm = PackageManagerPythonPep621(pep621_project_no_lockfile, settings)
        project = pm.project_info()
        assert project.has_lockfile is False

    def test_project_name_from_pyproject(self, pep621_project_no_lockfile, settings):
        pm = PackageManagerPythonPep621(pep621_project_no_lockfile, settings)
        project = pm.project_info()
        assert project.name == "no-lockfile-project"

    def test_main_dependencies_parsed(self, pep621_project_no_lockfile, settings):
        pm = PackageManagerPythonPep621(pep621_project_no_lockfile, settings)
        project = pm.project_info()
        assert "requests" in project.dependencies
        assert "click" in project.dependencies
        assert "pytest" not in project.dependencies

    def test_optional_dependencies_parsed_with_category(self, pep621_project_no_lockfile, settings):
        pm = PackageManagerPythonPep621(pep621_project_no_lockfile, settings)
        project = pm.project_info()
        assert "pytest" in project.optional_dependencies
        assert "dev" in project.optional_dependencies["pytest"].categories

    def test_version_defined_and_declared_reflect_the_manifest_specifier(self, pep621_project_no_lockfile, settings):
        """The whole point of item #15's fix applied from day one here: since this adapter IS
        the root manifest, version_constraint_declared must be populated directly, not left None
        pending some later Pass-2 write that never happens (there's no BaseDependencyResolver
        graph construction for this adapter at all)."""
        pm = PackageManagerPythonPep621(pep621_project_no_lockfile, settings)
        project = pm.project_info()
        requests_dep = project.dependencies["requests"]
        assert requests_dep.version_defined == ">=2.31.0"
        assert requests_dep.version_constraint_declared == ">=2.31.0"

    def test_version_installed_is_best_effort_from_specifier(self, pep621_project_no_lockfile, settings):
        """No lockfile exists, so version_installed is a best-effort lower bound read off the
        specifier - the same approximation api_pip_classic.py uses for requirements.txt."""
        pm = PackageManagerPythonPep621(pep621_project_no_lockfile, settings)
        project = pm.project_info()
        assert project.dependencies["requests"].version_installed == "2.31.0"

    def test_constraint_info_source_file_is_pyproject_toml(self, pep621_project_no_lockfile, settings):
        pm = PackageManagerPythonPep621(pep621_project_no_lockfile, settings)
        project = pm.project_info()
        requests_dep = project.dependencies["requests"]
        assert requests_dep.constraint_info.source_file == "pyproject.toml"
        assert requests_dep.constraint_info.type == ConstraintType.DECLARED

    def test_bare_dependency_without_specifier_is_skipped(self, temp_project_dir, settings):
        """A bare 'requests' entry (no version operator at all) gives no way to derive even a
        best-effort installed version, so it's skipped - matching parse_requirements_txt."""
        pyproject_path = Path(temp_project_dir) / "pyproject.toml"
        pyproject_path.write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["requests", "click>=8.0.0"]\n'
        )
        pm = PackageManagerPythonPep621(temp_project_dir, settings)
        project = pm.project_info()
        assert "requests" not in project.dependencies
        assert "click" in project.dependencies

    def test_extras_are_captured(self, temp_project_dir, settings):
        pyproject_path = Path(temp_project_dir) / "pyproject.toml"
        pyproject_path.write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["requests[security]>=2.31.0"]\n'
        )
        pm = PackageManagerPythonPep621(temp_project_dir, settings)
        project = pm.project_info()
        assert project.dependencies["requests"].extras == ["security"]
