"""
Tests for library_scan service module.

Covers:
1. latest_version_for_constraint — npm constraint → latest matching version
2. resolve_library_constraints — enriches no-lockfile Project with registry data
3. compute_upgrade_paths — cross-constraint widening opportunities for library projects
"""

from unittest.mock import MagicMock

from ossiq.adapters.api_npm import PackageRegistryApiNpm
from ossiq.domain.common import ConstraintType
from ossiq.domain.packages_manager import NPM
from ossiq.domain.project import ConstraintSource, Dependency, Project
from ossiq.domain.version import PackageVersion
from ossiq.service.library_scan import (
    UpgradePath,
    compute_upgrade_paths,
    latest_version_for_constraint,
    resolve_library_constraints,
)

# ============================================================================
# Helpers
# ============================================================================


def make_package_version(version: str, is_prerelease: bool = False) -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url=f"https://www.npmjs.com/package/x/v/{version}",
        declared_dependencies={},
        is_prerelease=is_prerelease,
    )


def make_dep(name: str, version_defined: str, version_installed: str) -> Dependency:
    return Dependency(
        name=name,
        canonical_name=name,
        version_installed=version_installed,
        version_defined=version_defined,
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
    )


def make_project(deps: dict[str, Dependency], has_lockfile: bool = False) -> Project:
    root = Dependency(
        name="test-lib",
        canonical_name="test-lib",
        version_installed="1.0.0",
        dependencies=deps,
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
    )
    return Project(
        package_manager_type=NPM,
        name="test-lib",
        project_path="/tmp/test-lib",
        dependency_tree=root,
        has_lockfile=has_lockfile,
    )


def make_registry(versions_by_name: dict[str, list[PackageVersion]]) -> MagicMock:
    registry = MagicMock()
    registry.packages_info_batch.return_value = {name: MagicMock() for name in versions_by_name}
    registry.package_versions.side_effect = lambda name: versions_by_name.get(name, [])
    return registry


# ============================================================================
# TestLatestVersionForConstraint
# ============================================================================


class TestLatestVersionForConstraint:
    """Tests for latest_version_for_constraint()."""

    def test_caret_returns_latest_in_same_major(self):
        versions = ["4.18.0", "4.21.2", "5.0.0"]
        assert latest_version_for_constraint(versions, "^4.18.0") == "4.21.2"

    def test_caret_excludes_higher_major(self):
        versions = ["4.18.0", "4.21.2", "5.3.1"]
        assert latest_version_for_constraint(versions, "^4.18.0") == "4.21.2"

    def test_caret_no_candidates_returns_base_version(self):
        versions = ["5.0.0", "5.1.0"]
        assert latest_version_for_constraint(versions, "^4.18.0") == "4.18.0"

    def test_tilde_returns_latest_in_same_minor(self):
        versions = ["4.17.0", "4.17.21", "4.18.0"]
        assert latest_version_for_constraint(versions, "~4.17.0") == "4.17.21"

    def test_tilde_excludes_higher_minor(self):
        versions = ["4.17.0", "4.17.5", "4.18.0", "4.19.0"]
        assert latest_version_for_constraint(versions, "~4.17.0") == "4.17.5"

    def test_tilde_no_candidates_returns_base_version(self):
        versions = ["4.18.0", "4.18.1"]
        assert latest_version_for_constraint(versions, "~4.17.0") == "4.17.0"

    def test_wildcard_returns_max_stable(self):
        versions = ["4.18.0", "5.0.0", "5.1.0-alpha"]
        result = latest_version_for_constraint(versions, "*")
        assert result == "5.0.0"

    def test_latest_keyword_returns_max_stable(self):
        versions = ["4.18.0", "5.0.0"]
        assert latest_version_for_constraint(versions, "latest") == "5.0.0"

    def test_empty_constraint_returns_max_stable(self):
        versions = ["1.0.0", "2.0.0"]
        assert latest_version_for_constraint(versions, "") == "2.0.0"

    def test_bare_semver_passes_through(self):
        versions = ["4.18.0", "4.21.2"]
        assert latest_version_for_constraint(versions, "4.18.2") == "4.18.2"

    def test_complex_range_falls_back_to_normalize(self):
        versions = ["4.18.0", "4.21.2"]
        result = latest_version_for_constraint(versions, ">=4.0.0 <5.0.0")
        assert result == "4.0.0"

    def test_empty_versions_list_falls_back(self):
        result = latest_version_for_constraint([], "^4.18.0")
        assert result == "4.18.0"

    def test_prerelease_excluded_by_stable_filter(self):
        versions = ["4.17.0", "4.17.21"]
        result = latest_version_for_constraint(versions, "~4.17.0")
        assert result == "4.17.21"


# ============================================================================
# TestLatestVersionForConstraintPEP440
# ============================================================================


class TestLatestVersionForConstraintPEP440:
    """Tests for PEP 440 specifier handling in latest_version_for_constraint()."""

    def test_exact_pin_present(self):
        versions = ["2.30.0", "2.31.0", "2.32.0"]
        assert latest_version_for_constraint(versions, "==2.31.0") == "2.31.0"

    def test_exact_pin_absent_falls_back_to_normalize(self):
        versions = ["2.30.0", "2.32.0"]
        assert latest_version_for_constraint(versions, "==2.31.0") == "2.31.0"

    def test_lower_bound_only_returns_highest(self):
        versions = ["2.0.0", "2.5.0", "3.1.0", "4.0.0"]
        assert latest_version_for_constraint(versions, ">=2.0") == "4.0.0"

    def test_compound_range_respects_upper_bound(self):
        versions = ["2.0.0", "2.9.9", "3.0.0", "4.0.0"]
        assert latest_version_for_constraint(versions, ">=2.0,<3.0") == "2.9.9"

    def test_compatible_release_two_parts(self):
        versions = ["1.1.0", "1.9.5", "2.0.0", "3.0.0"]
        assert latest_version_for_constraint(versions, "~=1.2") == "1.9.5"

    def test_compatible_release_three_parts(self):
        versions = ["1.2.0", "1.2.9", "1.3.0", "2.0.0"]
        assert latest_version_for_constraint(versions, "~=1.2.0") == "1.2.9"

    def test_compatible_release_no_match_falls_back_to_normalize(self):
        versions = ["1.0.0", "2.0.0", "3.0.0"]
        assert latest_version_for_constraint(versions, "~=5.0") == "5.0"

    def test_empty_versions_falls_back_to_normalize(self):
        assert latest_version_for_constraint([], ">=2.0") == "2.0"

    def test_prereleases_excluded(self):
        versions = ["2.0.0", "2.9.0", "3.0.0a1"]
        assert latest_version_for_constraint(versions, ">=2.0,<3.0") == "2.9.0"


# ============================================================================
# TestResolveLibraryConstraints
# ============================================================================


class TestResolveLibraryConstraints:
    """Tests for resolve_library_constraints()."""

    def test_no_lockfile_project_versions_enriched(self):
        """version_installed is replaced with registry-resolved latest-in-range."""
        express = make_dep("express", "^4.18.0", "4.18.0")
        project = make_project({"express": express}, has_lockfile=False)

        registry = make_registry(
            {
                "express": [
                    make_package_version("4.18.0"),
                    make_package_version("4.21.2"),
                    make_package_version("5.0.0"),
                ]
            }
        )

        result = resolve_library_constraints(project, registry)

        assert result.dependency_tree.dependencies["express"].version_installed == "4.21.2"

    def test_lockfile_project_returned_unchanged(self):
        """Projects with a lockfile are not enriched."""
        express = make_dep("express", "^4.18.0", "4.18.2")
        project = make_project({"express": express}, has_lockfile=True)
        registry = MagicMock()

        result = resolve_library_constraints(project, registry)

        registry.packages_info_batch.assert_not_called()
        assert result.dependency_tree.dependencies["express"].version_installed == "4.18.2"

    def test_registry_error_returns_project_unchanged(self):
        """When the registry call fails, the original version_installed is preserved."""
        express = make_dep("express", "^4.18.0", "4.18.0")
        project = make_project({"express": express}, has_lockfile=False)

        registry = MagicMock()
        registry.packages_info_batch.side_effect = Exception("registry unavailable")

        result = resolve_library_constraints(project, registry)

        assert result.dependency_tree.dependencies["express"].version_installed == "4.18.0"

    def test_empty_project_returned_unchanged(self):
        """Projects with no deps are passed through without registry calls."""
        project = make_project({}, has_lockfile=False)
        registry = MagicMock()

        result = resolve_library_constraints(project, registry)

        registry.packages_info_batch.assert_not_called()
        assert result is project

    def test_dep_without_version_defined_skipped(self):
        """Deps without a declared constraint are left unchanged."""
        dep = Dependency(
            name="unknown",
            canonical_name="unknown",
            version_installed="1.0.0",
            version_defined=None,
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
        )
        project = make_project({"unknown": dep}, has_lockfile=False)

        registry = make_registry({"unknown": [make_package_version("2.0.0")]})

        resolve_library_constraints(project, registry)

        assert project.dependency_tree.dependencies["unknown"].version_installed == "1.0.0"

    def test_optional_dependencies_also_enriched(self):
        """Optional (dev/peer) deps are enriched the same as production deps."""
        jest = make_dep("jest", ">=29.0.0", "29.0.0")
        root = Dependency(
            name="test-lib",
            canonical_name="test-lib",
            version_installed="1.0.0",
            optional_dependencies={"jest": jest},
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
        )
        project = Project(
            package_manager_type=NPM,
            name="test-lib",
            project_path="/tmp/test-lib",
            dependency_tree=root,
            has_lockfile=False,
        )

        registry = make_registry({"jest": [make_package_version("29.0.0"), make_package_version("29.7.0")]})

        resolve_library_constraints(project, registry)

        assert project.dependency_tree.optional_dependencies["jest"].version_installed == "29.7.0"

    def test_package_versions_error_skips_that_dep(self):
        """If fetching versions for one dep fails, other deps are still processed."""
        express = make_dep("express", "^4.18.0", "4.18.0")
        lodash = make_dep("lodash", "~4.17.0", "4.17.0")
        project = make_project({"express": express, "lodash": lodash}, has_lockfile=False)

        registry = MagicMock()
        registry.packages_info_batch.return_value = {"express": MagicMock(), "lodash": MagicMock()}

        def versions_side_effect(name):
            if name == "express":
                raise Exception("fetch error")
            return [make_package_version("4.17.21")]

        registry.package_versions.side_effect = versions_side_effect

        resolve_library_constraints(project, registry)

        assert project.dependency_tree.dependencies["express"].version_installed == "4.18.0"
        assert project.dependency_tree.dependencies["lodash"].version_installed == "4.17.21"


# ============================================================================
# TestComputeUpgradePaths
# ============================================================================


def make_pkg_mock(latest_version: str | None) -> MagicMock:
    pkg = MagicMock()
    pkg.latest_version = latest_version
    return pkg


def make_upgrade_registry(packages: dict[str, str | None]) -> MagicMock:
    """Registry mock where packages maps name → latest_version string (or None)."""
    registry = MagicMock()
    registry.packages_info_batch.return_value = {name: make_pkg_mock(ver) for name, ver in packages.items()}
    registry.rewrite_specifier.side_effect = lambda spec, ver, **kw: PackageRegistryApiNpm.rewrite_specifier(spec, ver)
    return registry


class TestComputeUpgradePaths:
    """Tests for compute_upgrade_paths()."""

    def test_lockfile_project_returns_empty(self):
        """No upgrade paths computed for projects that have a lockfile."""
        project = make_project({"express": make_dep("express", "^4.18.0", "4.21.2")}, has_lockfile=True)
        registry = MagicMock()

        result = compute_upgrade_paths(project, registry)

        registry.packages_info_batch.assert_not_called()
        assert result == []

    def test_all_deps_within_range_returns_empty(self):
        """When latest available is the same major as the constraint, no paths emitted."""
        # ^4.18.0 with latest 4.21.2 — rewrite_specifier returns "^4.18.0" (unchanged)
        express = make_dep("express", "^4.18.0", "4.21.2")
        project = make_project({"express": express}, has_lockfile=False)
        registry = make_upgrade_registry({"express": "4.21.2"})

        result = compute_upgrade_paths(project, registry)

        assert result == []

    def test_major_widening_opportunity_returned(self):
        """When latest available is a new major, an UpgradePath is emitted."""
        express = make_dep("express", "^4.18.0", "4.21.2")
        project = make_project({"express": express}, has_lockfile=False)
        registry = make_upgrade_registry({"express": "5.3.1"})

        result = compute_upgrade_paths(project, registry)

        assert len(result) == 1
        path = result[0]
        assert path.package_name == "express"
        assert path.current_constraint == "^4.18.0"
        assert path.latest_in_range == "4.21.2"
        assert path.latest_available == "5.3.1"
        assert path.suggested_constraint == "^5.0.0"

    def test_tilde_minor_widening_opportunity_returned(self):
        """Tilde constraint with a newer minor emits an UpgradePath with updated tilde."""
        lodash = make_dep("lodash", "~4.17.0", "4.17.21")
        project = make_project({"lodash": lodash}, has_lockfile=False)
        registry = make_upgrade_registry({"lodash": "4.18.5"})

        result = compute_upgrade_paths(project, registry)

        assert len(result) == 1
        path = result[0]
        assert path.package_name == "lodash"
        assert path.current_constraint == "~4.17.0"
        assert path.latest_in_range == "4.17.21"
        assert path.latest_available == "4.18.5"
        assert path.suggested_constraint == "~4.18.0"

    def test_dep_without_version_defined_skipped(self):
        """Deps with no declared constraint are excluded from results."""
        dep = Dependency(
            name="unknown",
            canonical_name="unknown",
            version_installed="1.0.0",
            version_defined=None,
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
        )
        project = make_project({"unknown": dep}, has_lockfile=False)
        registry = make_upgrade_registry({})

        result = compute_upgrade_paths(project, registry)

        assert result == []

    def test_packages_info_batch_error_returns_empty(self):
        """Registry batch fetch failure degrades gracefully."""
        express = make_dep("express", "^4.18.0", "4.21.2")
        project = make_project({"express": express}, has_lockfile=False)

        registry = MagicMock()
        registry.packages_info_batch.side_effect = Exception("registry unavailable")

        result = compute_upgrade_paths(project, registry)

        assert result == []

    def test_missing_dep_in_batch_result_skipped(self):
        """If a dep is absent from batch result, it is skipped; others still processed."""
        express = make_dep("express", "^4.18.0", "4.21.2")
        react = make_dep("react", "^17.0.0", "17.0.2")
        project = make_project({"express": express, "react": react}, has_lockfile=False)

        registry = MagicMock()
        # express missing from result, react has a new major
        registry.packages_info_batch.return_value = {"react": make_pkg_mock("18.3.1")}
        registry.rewrite_specifier.side_effect = lambda spec, ver, **kw: PackageRegistryApiNpm.rewrite_specifier(
            spec, ver
        )

        result = compute_upgrade_paths(project, registry)

        names = [p.package_name for p in result]
        assert "express" not in names
        assert "react" in names

    def test_optional_dependencies_included(self):
        """Optional deps are processed the same as production deps."""
        jest = make_dep("jest", "^29.0.0", "29.7.0")
        root = Dependency(
            name="test-lib",
            canonical_name="test-lib",
            version_installed="1.0.0",
            optional_dependencies={"jest": jest},
            constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
        )
        project = Project(
            package_manager_type=NPM,
            name="test-lib",
            project_path="/tmp/test-lib",
            dependency_tree=root,
            has_lockfile=False,
        )
        registry = make_upgrade_registry({"jest": "30.0.0"})

        result = compute_upgrade_paths(project, registry)

        assert len(result) == 1
        assert result[0].package_name == "jest"
        assert result[0].suggested_constraint == "^30.0.0"

    def test_upgrade_path_fields_populated_correctly(self):
        """All UpgradePath fields are set from the right sources."""
        react = make_dep("react", "^17.0.0", "17.0.2")
        project = make_project({"react": react}, has_lockfile=False)
        registry = make_upgrade_registry({"react": "18.3.1"})

        result = compute_upgrade_paths(project, registry)

        assert result == [
            UpgradePath(
                package_name="react",
                current_constraint="^17.0.0",
                latest_in_range="17.0.2",
                latest_available="18.3.1",
                suggested_constraint="^18.0.0",
            )
        ]
