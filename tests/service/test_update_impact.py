"""Tests for service/update_impact.py — transitive dependency impact simulation."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

from ossiq.domain.common import ConstraintType, ProjectPackagesRegistry, RejectionDetail
from ossiq.domain.project import ConstraintSource, IncomingEdge, InstalledCopy
from ossiq.domain.release_cutoff import ReleaseCutoff
from ossiq.domain.version import PackageVersion, VersionsDifference
from ossiq.service.project.models import ScanRecord
from ossiq.service.update import entry_from_record
from ossiq.service.update_impact import (
    DirectUpdateImpact,
    ImpactKind,
    TransitiveImpact,
    assess_transitive_impact,
    find_best_satisfying_version,
    simulate_single,
    simulate_update_impacts,
)

# ============================================================================
# Test helpers
# ============================================================================

CONSTRAINT_SOURCE = ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml")
NO_DIFF = VersionsDifference("1.0.0", "1.0.0", 0, diff_name="LATEST")


def pv(
    version: str,
    *,
    yanked: bool = False,
    unpublished: bool = False,
    prerelease: bool = False,
    published: str | None = "2024-01-01T00:00:00Z",
) -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url=f"https://example.com/{version}",
        declared_dependencies={},
        published_date_iso=published,
        is_yanked=yanked,
        is_unpublished=unpublished,
        is_prerelease=prerelease,
    )


def make_scan_record(
    package_name: str,
    installed_version: str,
    all_constraints: list[str] | None = None,
    version_constraint: str | None = None,
) -> ScanRecord:
    return ScanRecord(
        package_name=package_name,
        dependency_name=package_name,
        is_optional_dependency=False,
        installed_version=installed_version,
        latest_version=None,
        versions_diff_index=NO_DIFF,
        time_lag_days=None,
        releases_lag=None,
        cve=[],
        constraint_info=CONSTRAINT_SOURCE,
        version_constraint=version_constraint,
        all_constraints=all_constraints or [],
    )


def make_registry(
    versions_by_name: dict[str, list[PackageVersion]] | None = None,
    requires_by_pkg_ver: dict[tuple[str, str], dict[str, str]] | None = None,
) -> MagicMock:
    from functools import cmp_to_key

    from ossiq.domain.common import ProjectPackagesRegistry

    registry = MagicMock()
    registry.package_registry = ProjectPackagesRegistry.PYPI
    registry.package_versions.side_effect = lambda name: (versions_by_name or {}).get(name, [])
    registry.package_version_requires.side_effect = lambda name, ver: (requires_by_pkg_ver or {}).get((name, ver), {})

    def cmp(v1: str, v2: str) -> int:
        from packaging.version import Version as PV

        p1, p2 = PV(v1), PV(v2)
        return -1 if p1 < p2 else (1 if p1 > p2 else 0)

    registry.compare_versions.side_effect = cmp

    def newest_version_impl(candidates):
        as_list = list(candidates)
        if not as_list:
            return None
        return max(as_list, key=cmp_to_key(lambda a, b: cmp(a.version, b.version)))

    registry.newest_version.side_effect = newest_version_impl
    return registry


# ============================================================================
# Tests: find_best_satisfying_version
# ============================================================================


class TestFindBestSatisfyingVersion:
    def test_returns_newest_satisfying(self):
        registry = make_registry(versions_by_name={"urllib3": [pv("2.1.0"), pv("1.26.18"), pv("1.25.0")]})
        result = find_best_satisfying_version("urllib3", [">=1.0"], registry)
        assert result == "2.1.0"

    def test_respects_upper_bound_constraint(self):
        registry = make_registry(versions_by_name={"urllib3": [pv("2.1.0"), pv("1.26.18"), pv("1.25.0")]})
        result = find_best_satisfying_version("urllib3", [">=1.0,<2.0"], registry)
        assert result == "1.26.18"

    def test_returns_none_when_no_version_satisfies(self):
        registry = make_registry(versions_by_name={"urllib3": [pv("1.26.18"), pv("1.25.0")]})
        result = find_best_satisfying_version("urllib3", [">=2.0"], registry)
        assert result is None

    def test_skips_yanked_versions(self):
        registry = make_registry(versions_by_name={"urllib3": [pv("2.1.0", yanked=True), pv("1.26.18")]})
        result = find_best_satisfying_version("urllib3", [">=1.0"], registry)
        assert result == "1.26.18"

    def test_skips_unpublished_versions(self):
        registry = make_registry(versions_by_name={"urllib3": [pv("2.1.0", unpublished=True), pv("1.26.18")]})
        result = find_best_satisfying_version("urllib3", [">=1.0"], registry)
        assert result == "1.26.18"

    def test_skips_prerelease_by_default(self):
        registry = make_registry(versions_by_name={"urllib3": [pv("3.0.0a1", prerelease=True), pv("2.1.0")]})
        result = find_best_satisfying_version("urllib3", [">=1.0"], registry)
        assert result == "2.1.0"

    def test_includes_prerelease_when_allowed(self):
        registry = make_registry(versions_by_name={"urllib3": [pv("3.0.0a1", prerelease=True), pv("2.1.0")]})
        result = find_best_satisfying_version("urllib3", [">=1.0"], registry, allow_prerelease=True)
        assert result == "3.0.0a1"

    def test_returns_none_for_unknown_package(self):
        registry = make_registry(versions_by_name={})
        result = find_best_satisfying_version("nonexistent", [">=1.0"], registry)
        assert result is None

    def test_handles_multiple_constraints(self):
        registry = make_registry(versions_by_name={"pkg": [pv("3.0.0"), pv("2.5.0"), pv("1.9.0")]})
        result = find_best_satisfying_version("pkg", [">=2.0", "<3.0"], registry)
        assert result == "2.5.0"

    def test_skips_versions_past_the_release_cutoff(self):
        registry = make_registry(
            versions_by_name={"urllib3": [pv("2.2.0", published="2024-01-20T00:00:00Z"), pv("2.1.0")]}
        )
        result = find_best_satisfying_version("urllib3", [">=2.0"], registry, release_cutoff=UV_CUTOFF)
        assert result == "2.1.0"


UV_CUTOFF = ReleaseCutoff("uv exclude-newer", default=datetime(2024, 1, 15, tzinfo=UTC))


# ============================================================================
# Tests: assess_transitive_impact
# ============================================================================


class TestAssessTransitiveImpact:
    def test_returns_none_when_current_version_satisfies_new_constraint(self):
        record = make_scan_record("urllib3", "1.26.18")
        transitive_by_name = {"urllib3": record}
        registry = make_registry()

        result = assess_transitive_impact("urllib3", ">=1.0", "requests", transitive_by_name, registry)

        assert result is None

    def test_an_unconstrained_requirement_never_cascades(self):
        """Regression: tiktoken -> `requests` (no specifier) showed up as `requests 2.34.2 -> 2.34.2`."""
        record = make_scan_record("requests", "2.34.2", all_constraints=[">=2.0"])
        registry = make_registry(versions_by_name={"requests": [pv("2.34.3"), pv("2.34.2")]})

        result = assess_transitive_impact("requests", "", "tiktoken", {"requests": record}, registry)

        assert result is None

    def test_new_dep_not_in_tree(self):
        registry = make_registry()

        result = assess_transitive_impact("h2", ">=4.0", "httpx", {}, registry)

        assert result is not None
        assert result.package_name == "h2"
        assert result.current_version is None
        assert result.projected_version is None
        assert result.has_conflict is False
        assert result.driven_by == "httpx"
        assert result.new_constraint == ">=4.0"

    def test_version_bump_required_no_conflict(self):
        record = make_scan_record("urllib3", "1.26.18", all_constraints=[">=1.0"])
        transitive_by_name = {"urllib3": record}
        registry = make_registry(versions_by_name={"urllib3": [pv("2.2.0"), pv("1.26.18")]})

        result = assess_transitive_impact("urllib3", ">=2.0", "requests", transitive_by_name, registry)

        assert result is not None
        assert result.current_version == "1.26.18"
        assert result.projected_version == "2.2.0"
        assert result.has_conflict is False
        assert result.conflict_detail is None

    def test_hard_conflict_no_satisfying_version(self):
        # existing constraint: <2.0, new constraint: >=2.0 — impossible to satisfy both
        record = make_scan_record("urllib3", "1.26.18", all_constraints=["<2.0"])
        transitive_by_name = {"urllib3": record}
        registry = make_registry(versions_by_name={"urllib3": [pv("2.2.0"), pv("1.26.18")]})

        result = assess_transitive_impact("urllib3", ">=2.0", "requests", transitive_by_name, registry)

        assert result is not None
        assert result.projected_version is None
        assert result.has_conflict is True
        assert result.conflict_detail is not None
        assert "<2.0" in result.conflict_detail
        assert ">=2.0" in result.conflict_detail

    def test_repeated_parent_specs_are_listed_once(self):
        # all_constraints carries one entry per parent, so a widely-shared dep repeated the same
        # spec a dozen times and the rendered explanation became a wall of identical versions.
        record = make_scan_record("urllib3", "1.26.18", all_constraints=["<2.0", "<2.0", "<2.0", "<1.9"])
        transitive_by_name = {"urllib3": record}
        registry = make_registry(versions_by_name={"urllib3": [pv("2.2.0"), pv("1.26.18")]})

        result = assess_transitive_impact("urllib3", ">=2.0", "requests", transitive_by_name, registry)

        assert result is not None
        assert result.conflict is not None
        assert result.conflict.items == ("<2.0", "<1.9", ">=2.0")

    def test_projected_version_violates_other_parent_constraint(self):
        # Parent A requires <3.0, parent B (new) requires >=2.0.
        # Best version satisfying >=2.0 is 3.5.0, but that violates <3.0.
        record = make_scan_record("dep", "2.9.0", all_constraints=["<3.0"])
        transitive_by_name = {"dep": record}
        # Only version >=2.0 available is 3.5.0 (violates <3.0)
        registry = make_registry(versions_by_name={"dep": [pv("3.5.0"), pv("2.0.0")]})

        # current 2.9.0 satisfies >=2.0, so no impact expected
        result = assess_transitive_impact("dep", ">=2.0", "newpkg", transitive_by_name, registry)
        assert result is None

    def test_projected_version_conflict_with_existing_parent(self):
        # current: 1.9.0, constraint from parent A: <2.0, new constraint: >=2.0
        # Merged: <2.0 AND >=2.0 — impossible
        record = make_scan_record("dep", "1.9.0", all_constraints=["<2.0"])
        transitive_by_name = {"dep": record}
        registry = make_registry(versions_by_name={"dep": [pv("3.0.0"), pv("2.5.0"), pv("1.9.0")]})

        result = assess_transitive_impact("dep", ">=2.0", "driver", transitive_by_name, registry)

        assert result is not None
        assert result.has_conflict is True
        assert result.projected_version is None  # no version satisfies both <2.0 and >=2.0

    def test_merges_all_constraints_for_projection(self):
        # Diamond: parent A requires >=1.0,<3.0; parent B (new) requires >=2.0
        # Merged: >=1.0,<3.0 AND >=2.0 → valid range >=2.0,<3.0
        record = make_scan_record("dep", "1.5.0", all_constraints=[">=1.0,<3.0"])
        transitive_by_name = {"dep": record}
        registry = make_registry(versions_by_name={"dep": [pv("3.5.0"), pv("2.8.0"), pv("1.5.0")]})

        result = assess_transitive_impact("dep", ">=2.0", "newpkg", transitive_by_name, registry)

        assert result is not None
        assert result.projected_version == "2.8.0"
        assert result.has_conflict is False


# ============================================================================
# Tests: new-dep projection (version, age, cutoff determinism)
# ============================================================================

FIXED_NOW = datetime(2024, 1, 31, 0, 0, 0, tzinfo=UTC)


class TestNewDepProjection:
    def test_new_dep_projected_version_and_age_populated(self):
        registry = make_registry(
            versions_by_name={
                "newpkg": [pv("2.0.0", published="2024-01-01T00:00:00Z"), pv("1.0.0", published="2023-01-01T00:00:00Z")]
            }
        )

        result = assess_transitive_impact("newpkg", ">=1.0", "driver", {}, registry, now=FIXED_NOW)

        assert result is not None
        assert result.current_version is None
        assert result.projected_version == "2.0.0"
        assert result.projected_age_days == 30

    def test_new_dep_no_satisfying_version_stays_none(self):
        registry = make_registry(versions_by_name={"newpkg": [pv("1.0.0")]})

        result = assess_transitive_impact("newpkg", ">=2.0", "driver", {}, registry)

        assert result is not None
        assert result.projected_version is None
        assert result.projected_age_days is None
        assert result.has_conflict is False

    def test_new_dep_cutoff_excludes_later_versions(self):
        registry = make_registry(
            versions_by_name={
                "newpkg": [pv("2.0.0", published="2024-06-01T00:00:00Z"), pv("1.0.0", published="2023-01-01T00:00:00Z")]
            }
        )

        result = assess_transitive_impact("newpkg", ">=1.0", "driver", {}, registry, now=FIXED_NOW)

        assert result is not None
        assert result.projected_version == "1.0.0"

    def test_new_dep_missing_publish_date_age_none(self):
        registry = make_registry(versions_by_name={"newpkg": [pv("1.0.0", published=None)]})

        result = assess_transitive_impact("newpkg", ">=1.0", "driver", {}, registry, now=FIXED_NOW)

        assert result is not None
        assert result.projected_version == "1.0.0"
        assert result.projected_age_days is None

    def test_existing_dep_impact_gets_projected_age(self):
        record = make_scan_record("urllib3", "1.26.0", all_constraints=[">=1.0"])
        registry = make_registry(versions_by_name={"urllib3": [pv("2.0.7", published="2024-01-01T00:00:00Z")]})

        result = assess_transitive_impact("urllib3", ">=2.0", "requests", {"urllib3": record}, registry, now=FIXED_NOW)

        assert result is not None
        assert result.projected_version == "2.0.7"
        assert result.projected_age_days == 30


# ============================================================================
# Tests: simulate_single
# ============================================================================


class TestSimulateSingle:
    def test_empty_requires(self):
        registry = make_registry(requires_by_pkg_ver={("requests", "2.32.0"): {}})

        result = simulate_single("requests", "2.32.0", {}, registry)

        assert result.package_name == "requests"
        assert result.recommended_version == "2.32.0"
        assert result.transitive_impacts == []
        assert result.is_actionable is True
        assert result.fallback_version is None

    def test_unconstrained_requirements_add_no_impact(self):
        """tiktoken 0.14.0 needs `requests` and `regex` with no specifier: nothing to cascade."""
        record = make_scan_record("requests", "2.34.2", all_constraints=[">=2.0"])
        registry = make_registry(
            versions_by_name={"requests": [pv("2.34.3"), pv("2.34.2")]},
            requires_by_pkg_ver={("tiktoken", "0.14.0"): {"requests": "", "regex": ""}},
        )

        result = simulate_single("tiktoken", "0.14.0", {"requests": record}, registry, installed_names={"regex"})

        assert result.transitive_impacts == []
        assert result.is_actionable is True

    def test_is_actionable_when_no_conflicts(self):
        record = make_scan_record("urllib3", "1.26.18", all_constraints=[">=1.0"])
        transitive_by_name = {"urllib3": record}
        registry = make_registry(
            versions_by_name={"urllib3": [pv("2.2.0"), pv("1.26.18")]},
            requires_by_pkg_ver={("requests", "2.32.0"): {"urllib3": ">=2.0"}},
        )

        result = simulate_single("requests", "2.32.0", transitive_by_name, registry)

        assert result.is_actionable is True
        assert len(result.transitive_impacts) == 1
        assert result.transitive_impacts[0].projected_version == "2.2.0"

    def test_projects_transitive_deps_inside_the_release_cutoff(self):
        """uv would never move urllib3 to 2.3.0, so neither may the projection."""
        record = make_scan_record("urllib3", "1.26.18", all_constraints=[">=1.0"])
        registry = make_registry(
            versions_by_name={"urllib3": [pv("2.3.0", published="2024-01-20T00:00:00Z"), pv("2.2.0"), pv("1.26.18")]},
            requires_by_pkg_ver={("requests", "2.32.0"): {"urllib3": ">=2.0"}},
        )

        result = simulate_single("requests", "2.32.0", {"urllib3": record}, registry, release_cutoff=UV_CUTOFF)

        assert result.transitive_impacts[0].projected_version == "2.2.0"

    def test_not_actionable_when_conflict(self):
        record = make_scan_record("urllib3", "1.26.18", all_constraints=["<2.0"])
        transitive_by_name = {"urllib3": record}
        registry = make_registry(
            versions_by_name={"urllib3": [pv("2.2.0"), pv("1.26.18")]},
            requires_by_pkg_ver={("requests", "2.32.0"): {"urllib3": ">=2.0"}},
        )

        result = simulate_single("requests", "2.32.0", transitive_by_name, registry)

        assert result.is_actionable is False
        assert result.transitive_impacts[0].has_conflict is True

    def test_new_transitive_dep_does_not_block_actionability(self):
        # h2 is a brand-new transitive dep — should not make is_actionable=False
        registry = make_registry(
            requires_by_pkg_ver={("httpx", "0.27.0"): {"h2": ">=4.0"}},
        )

        result = simulate_single("httpx", "0.27.0", {}, registry)

        assert result.is_actionable is True
        assert len(result.transitive_impacts) == 1
        assert result.transitive_impacts[0].current_version is None

    def test_satisfied_constraint_produces_no_impact(self):
        # urllib3 1.26.18 already satisfies >=1.0 — no impact entry expected
        record = make_scan_record("urllib3", "1.26.18")
        transitive_by_name = {"urllib3": record}
        registry = make_registry(
            requires_by_pkg_ver={("requests", "2.32.0"): {"urllib3": ">=1.0"}},
        )

        result = simulate_single("requests", "2.32.0", transitive_by_name, registry)

        assert result.transitive_impacts == []
        assert result.is_actionable is True

    def test_stale_exact_pin_from_installed_version_does_not_block(self):
        # Regression: vite 8.0.7 pins rolldown to "==1.0.0rc1" exactly. After vite bumps to
        # 8.0.15, rolldown is pinned to "==1.0.0rc3". The old exact constraint from vite 8.0.7
        # is in rolldown's all_constraints. Without the fix, merged constraints
        # ["==1.0.0rc1", "==1.0.0rc3"] are impossible, hence is_actionable=False. With the fix,
        # the stale old constraint is removed and rolldown 1.0.0rc3 is resolvable, hence
        # is_actionable=True and the impact is flagged as a co-update (not a hard conflict).
        rolldown_record = make_scan_record(
            "rolldown",
            "1.0.0rc1",
            all_constraints=["==1.0.0rc1"],
        )
        transitive_by_name = {"rolldown": rolldown_record}
        registry = make_registry(
            versions_by_name={"rolldown": [pv("1.0.0rc3"), pv("1.0.0rc1")]},
            requires_by_pkg_ver={
                ("vite", "8.0.7"): {"rolldown": "==1.0.0rc1"},
                ("vite", "8.0.15"): {"rolldown": "==1.0.0rc3"},
            },
        )

        result_with_installed = simulate_single(
            "vite", "8.0.15", transitive_by_name, registry, installed_version="8.0.7"
        )
        assert result_with_installed.is_actionable is True
        assert result_with_installed.transitive_impacts[0].projected_version == "1.0.0rc3"
        assert result_with_installed.transitive_impacts[0].has_conflict is False

        # Without installed_version the old stale pin creates a false conflict (documents old behaviour).
        result_without_installed = simulate_single("vite", "8.0.15", transitive_by_name, registry)
        assert result_without_installed.is_actionable is False


# ============================================================================
# Tests: simulate_update_impacts
# ============================================================================


class TestSimulateUpdateImpacts:
    def test_returns_impact_per_recommendation(self):
        urllib3_record = make_scan_record("urllib3", "1.26.18", all_constraints=[">=1.0"])
        certifi_record = make_scan_record("certifi", "2023.1.1")
        transitive_records = [urllib3_record, certifi_record]

        registry = make_registry(
            versions_by_name={
                "urllib3": [pv("2.2.0"), pv("1.26.18")],
                "certifi": [pv("2024.2.2"), pv("2023.1.1")],
            },
            requires_by_pkg_ver={
                ("requests", "2.32.0"): {"urllib3": ">=2.0"},
                ("boto3", "1.35.0"): {"certifi": ">=2024.0"},
            },
        )

        result = simulate_update_impacts(
            {"requests": "2.32.0", "boto3": "1.35.0"},
            transitive_records,
            registry,
        )

        assert set(result.keys()) == {"requests", "boto3"}
        assert isinstance(result["requests"], DirectUpdateImpact)
        assert isinstance(result["boto3"], DirectUpdateImpact)

    def test_empty_recommendations(self):
        result = simulate_update_impacts({}, [], make_registry())
        assert result == {}

    def test_independent_impacts_per_package(self):
        # Two recommendations that each affect different transitive deps
        urllib3_record = make_scan_record("urllib3", "1.26.18", all_constraints=["<2.0"])
        certifi_record = make_scan_record("certifi", "2023.1.1")
        transitive_records = [urllib3_record, certifi_record]

        registry = make_registry(
            versions_by_name={
                "urllib3": [pv("2.2.0"), pv("1.26.18")],
                "certifi": [pv("2024.2.2"), pv("2023.1.1")],
            },
            requires_by_pkg_ver={
                ("requests", "2.32.0"): {"urllib3": ">=2.0"},  # conflict: urllib3 has <2.0
                ("boto3", "1.35.0"): {"certifi": ">=2024.0"},  # no conflict
            },
        )

        result = simulate_update_impacts(
            {"requests": "2.32.0", "boto3": "1.35.0"},
            transitive_records,
            registry,
        )

        assert result["requests"].is_actionable is False
        assert result["boto3"].is_actionable is True

    def test_installed_versions_strips_stale_constraint(self):
        rolldown_record = make_scan_record("rolldown", "1.0.0rc1", all_constraints=["==1.0.0rc1"])
        registry = make_registry(
            versions_by_name={"rolldown": [pv("1.0.3"), pv("1.0.0rc1")]},
            requires_by_pkg_ver={
                ("vite", "8.0.7"): {"rolldown": "==1.0.0rc1"},
                ("vite", "8.0.16"): {"rolldown": "==1.0.3"},
            },
        )

        result = simulate_update_impacts(
            {"vite": "8.0.16"},
            [rolldown_record],
            registry,
            installed_versions={"vite": "8.0.7"},
        )

        assert result["vite"].is_actionable is True
        assert result["vite"].transitive_impacts[0].projected_version == "1.0.3"
        assert result["vite"].transitive_impacts[0].has_conflict is False

    def test_without_installed_versions_still_false_negative(self):
        rolldown_record = make_scan_record("rolldown", "1.0.0rc1", all_constraints=["==1.0.0rc1"])
        registry = make_registry(
            versions_by_name={"rolldown": [pv("1.0.3"), pv("1.0.0rc1")]},
            requires_by_pkg_ver={
                ("vite", "8.0.7"): {"rolldown": "==1.0.0rc1"},
                ("vite", "8.0.16"): {"rolldown": "==1.0.3"},
            },
        )

        result = simulate_update_impacts({"vite": "8.0.16"}, [rolldown_record], registry)

        assert result["vite"].is_actionable is False


# ============================================================================
# Tests: a package manager that nests copies (npm)
# ============================================================================


def make_npm_registry(
    versions_by_name: dict[str, list[PackageVersion]] | None = None,
    requires_by_pkg_ver: dict[tuple[str, str], dict[str, str]] | None = None,
) -> MagicMock:
    registry = make_registry(versions_by_name, requires_by_pkg_ver)
    registry.package_registry = ProjectPackagesRegistry.NPM
    registry.one_copy_per_name = False
    return registry


def edge(requirer: str, version: str, spec: str) -> IncomingEdge:
    return IncomingEdge(requirer_name=requirer, requirer_version=version, spec=spec)


def override(value: str, *, ossiq: bool, key: str | None = None, scope: list[str] | None = None) -> ConstraintSource:
    return ConstraintSource(
        type=ConstraintType.OVERRIDE,
        source_file="package.json",
        scope_path=scope,
        is_ossiq_authored=ossiq,
        override_key=key,
        override_value=value,
    )


def copy_of(version: str, *edges: IncomingEdge, governed_by: ConstraintSource | None = None) -> InstalledCopy:
    return InstalledCopy(version=version, edges=tuple(edges), constraint_info=governed_by or CONSTRAINT_SOURCE)


def make_nested_record(name: str, *copies: InstalledCopy) -> ScanRecord:
    """A record whose installed_version is the first copy, as the scan reports the primary."""
    record = make_scan_record(name, copies[0].version)
    record.installed_copies = list(copies)
    return record


class TestNestedCopies:
    def test_a_range_some_installed_copy_satisfies_is_no_impact(self):
        """eslint's minimatch ^10 is installed beside editorconfig's ^9 copy, so nothing has to move.

        The record stands for the 9.x copy here on purpose: a check that judged eslint against that
        copy alone, merging every parent's range, would reject this update.
        """
        minimatch = make_nested_record(
            "minimatch",
            copy_of("9.0.9", edge("editorconfig", "1.0.7", "^9.0.1")),
            copy_of("10.2.5", edge("eslint", "10.2.0", "^10.2.4")),
        )
        registry = make_npm_registry(
            versions_by_name={"minimatch": [pv("10.2.5"), pv("9.0.9")]},
            requires_by_pkg_ver={("eslint", "10.2.1"): {"minimatch": "^10.2.4"}},
        )

        result = simulate_single("eslint", "10.2.1", {"minimatch": minimatch}, registry, installed_version="10.2.0")

        assert result.transitive_impacts == []
        assert result.is_actionable is True

    def test_a_range_no_installed_copy_satisfies_installs_a_further_copy(self):
        minimatch = make_nested_record("minimatch", copy_of("10.2.5", edge("eslint", "10.2.0", "^10.2.4")))
        registry = make_npm_registry(
            versions_by_name={"minimatch": [pv("11.1.0"), pv("10.2.5")]},
            requires_by_pkg_ver={("eslint", "11.0.0"): {"minimatch": "^11.0.0"}},
        )

        result = simulate_single("eslint", "11.0.0", {"minimatch": minimatch}, registry, installed_version="10.2.0")

        (impact,) = result.transitive_impacts
        assert impact.kind == ImpactKind.NEW_COPY
        assert (impact.current_version, impact.projected_version) == ("10.2.5", "11.1.0")
        assert impact.has_conflict is False
        assert result.is_actionable is True

    def test_a_range_nobody_published_cannot_be_installed(self):
        minimatch = make_nested_record("minimatch", copy_of("10.2.5"))
        registry = make_npm_registry(
            versions_by_name={"minimatch": [pv("10.2.5")]},
            requires_by_pkg_ver={("eslint", "12.0.0"): {"minimatch": "^12.0.0"}},
        )

        result = simulate_single("eslint", "12.0.0", {"minimatch": minimatch}, registry)

        (impact,) = result.transitive_impacts
        assert impact.projected_version is None
        assert impact.has_conflict is True
        assert impact.conflict == RejectionDetail("no version satisfies", ("^12.0.0",))
        assert result.is_actionable is False

    def test_a_record_without_graph_data_is_one_copy_at_its_installed_version(self):
        shared = make_scan_record("@vue/shared", "3.5.42")
        registry = make_npm_registry(
            versions_by_name={"@vue/shared": [pv("3.5.43"), pv("3.5.42")]},
            requires_by_pkg_ver={("vue", "3.5.43"): {"@vue/shared": "3.5.43"}},
        )

        result = simulate_single("vue", "3.5.43", {"@vue/shared": shared}, registry)

        assert [i.kind for i in result.transitive_impacts] == [ImpactKind.NEW_COPY]
        assert result.is_actionable is True

    def test_a_family_pinned_in_lockstep_moves_without_conflict(self):
        """vue 3.5.43 pins @vue/shared 3.5.43 while the installed @vue/* all pin 3.5.42."""
        shared = make_nested_record(
            "@vue/shared",
            copy_of("3.5.42", edge("vue", "3.5.42", "3.5.42"), edge("@vue/compiler-dom", "3.5.42", "3.5.42")),
        )
        compiler_dom = make_nested_record("@vue/compiler-dom", copy_of("3.5.42", edge("vue", "3.5.42", "3.5.42")))
        registry = make_npm_registry(
            versions_by_name={
                "@vue/shared": [pv("3.5.43"), pv("3.5.42")],
                "@vue/compiler-dom": [pv("3.5.43"), pv("3.5.42")],
            },
            requires_by_pkg_ver={("vue", "3.5.43"): {"@vue/compiler-dom": "3.5.43", "@vue/shared": "3.5.43"}},
        )

        result = simulate_single(
            "vue",
            "3.5.43",
            {"@vue/shared": shared, "@vue/compiler-dom": compiler_dom},
            registry,
            installed_version="3.5.42",
        )

        assert {i.package_name: i.kind for i in result.transitive_impacts} == {
            "@vue/shared": ImpactKind.NEW_COPY,
            "@vue/compiler-dom": ImpactKind.NEW_COPY,
        }
        assert result.is_actionable is True

    def test_an_override_the_user_wrote_holds_the_dependency(self):
        shared = make_nested_record("@vue/shared", copy_of("3.5.42", governed_by=override("3.5.42", ossiq=False)))
        registry = make_npm_registry(
            versions_by_name={"@vue/shared": [pv("3.5.43"), pv("3.5.42")]},
            requires_by_pkg_ver={("vue", "3.5.43"): {"@vue/shared": "3.5.43"}},
        )

        result = simulate_single("vue", "3.5.43", {"@vue/shared": shared}, registry)

        (impact,) = result.transitive_impacts
        assert impact.has_conflict is True
        assert impact.held_by_override is not None and impact.held_by_override.is_ossiq_authored is False
        assert impact.conflict == RejectionDetail("forced to 3.5.42, wanted", ("3.5.43",))
        assert result.is_actionable is False

    def test_an_override_that_already_satisfies_the_requirement_is_no_impact(self):
        shared = make_nested_record("@vue/shared", copy_of("3.5.43", governed_by=override("3.5.43", ossiq=False)))
        registry = make_npm_registry(
            versions_by_name={"@vue/shared": [pv("3.5.43")]},
            requires_by_pkg_ver={("vue", "3.5.43"): {"@vue/shared": "^3.5.0"}},
        )

        result = simulate_single("vue", "3.5.43", {"@vue/shared": shared}, registry)

        assert result.transitive_impacts == []

    def test_a_reference_override_follows_the_root_spec_and_never_conflicts(self):
        vite = make_nested_record("vite", copy_of("8.2.2", governed_by=override("$vite", ossiq=False)))
        registry = make_npm_registry(
            versions_by_name={"vite": [pv("8.2.2")]},
            requires_by_pkg_ver={("plugin", "2.0.0"): {"vite": "^9.0.0"}},
        )

        result = simulate_single("plugin", "2.0.0", {"vite": vite}, registry)

        assert result.transitive_impacts == []

    def test_a_rule_keyed_to_another_range_does_not_apply(self):
        """`minimatch@^9` governs the 9.x copy; eslint's ^10 edge never reaches it."""
        minimatch = make_nested_record(
            "minimatch",
            copy_of("9.0.9", governed_by=override("9.0.9", ossiq=False, key="^9.0.0")),
            copy_of("10.2.5"),
        )
        registry = make_npm_registry(
            versions_by_name={"minimatch": [pv("10.2.5"), pv("9.0.9")]},
            requires_by_pkg_ver={("eslint", "10.2.1"): {"minimatch": "^10.2.4"}},
        )

        result = simulate_single("eslint", "10.2.1", {"minimatch": minimatch}, registry)

        assert result.transitive_impacts == []
        assert result.is_actionable is True

    def test_a_keyed_rule_is_judged_only_against_ranges_it_overlaps(self):
        minimatch = make_nested_record(
            "minimatch", copy_of("9.0.9", governed_by=override("9.0.9", ossiq=False, key="^9.0.0"))
        )
        registry = make_npm_registry(
            versions_by_name={"minimatch": [pv("10.2.5"), pv("9.0.9")]},
            requires_by_pkg_ver={("eslint", "10.2.1"): {"minimatch": "^9.0.5 || ^10.0.0"}},
        )

        # ^9.0.5 overlaps the key and 9.0.9 satisfies it, so the rule has nothing to object to
        assert simulate_single("eslint", "10.2.1", {"minimatch": minimatch}, registry).transitive_impacts == []

        registry.package_version_requires.side_effect = lambda name, ver: {"minimatch": "^10.0.0"}
        # a range clear of the key never reaches the rule; the dependency simply gains a copy
        impacts = simulate_single("eslint", "10.2.1", {"minimatch": minimatch}, registry).transitive_impacts
        assert [i.kind for i in impacts] == [ImpactKind.NEW_COPY]

    def test_a_scoped_rule_applies_only_beneath_its_scope(self):
        shared = make_nested_record(
            "@vue/shared", copy_of("3.5.42", governed_by=override("3.5.42", ossiq=False, scope=["vue"]))
        )
        registry = make_npm_registry(
            versions_by_name={"@vue/shared": [pv("3.5.43"), pv("3.5.42")]},
            requires_by_pkg_ver={
                ("vue", "3.5.43"): {"@vue/shared": "3.5.43"},
                ("other", "1.0.0"): {"@vue/shared": "3.5.43"},
            },
        )

        beneath = simulate_single("vue", "3.5.43", {"@vue/shared": shared}, registry)
        elsewhere = simulate_single("other", "1.0.0", {"@vue/shared": shared}, registry)

        assert beneath.transitive_impacts[0].has_conflict is True
        assert [i.kind for i in elsewhere.transitive_impacts] == [ImpactKind.NEW_COPY]

    def test_an_ossiq_override_moves_with_the_family(self):
        """Every @vue/* package pins the next, so the override on each has to bump together."""
        pinned = override("3.5.42", ossiq=True)
        shared = make_nested_record(
            "@vue/shared",
            copy_of(
                "3.5.42",
                edge("vue", "3.5.42", "3.5.42"),
                edge("@vue/compiler-dom", "3.5.42", "3.5.42"),
                edge("@vue/compiler-core", "3.5.42", "3.5.42"),
                governed_by=pinned,
            ),
        )
        compiler_dom = make_nested_record(
            "@vue/compiler-dom", copy_of("3.5.42", edge("vue", "3.5.42", "3.5.42"), governed_by=pinned)
        )
        compiler_core = make_nested_record(
            "@vue/compiler-core", copy_of("3.5.42", edge("@vue/compiler-dom", "3.5.42", "3.5.42"), governed_by=pinned)
        )
        both = [pv("3.5.43"), pv("3.5.42")]
        registry = make_npm_registry(
            versions_by_name={"@vue/shared": both, "@vue/compiler-dom": both, "@vue/compiler-core": both},
            requires_by_pkg_ver={
                ("vue", "3.5.43"): {"@vue/compiler-dom": "3.5.43", "@vue/shared": "3.5.43"},
                ("@vue/compiler-dom", "3.5.43"): {"@vue/compiler-core": "3.5.43", "@vue/shared": "3.5.43"},
                ("@vue/compiler-core", "3.5.43"): {"@vue/shared": "3.5.43"},
            },
        )

        result = simulate_single(
            "vue",
            "3.5.43",
            {"@vue/shared": shared, "@vue/compiler-dom": compiler_dom, "@vue/compiler-core": compiler_core},
            registry,
            installed_version="3.5.42",
        )

        assert {(i.package_name, i.kind, i.projected_version) for i in result.transitive_impacts} == {
            ("@vue/shared", ImpactKind.OVERRIDE_BUMP, "3.5.43"),
            ("@vue/compiler-dom", ImpactKind.OVERRIDE_BUMP, "3.5.43"),
            ("@vue/compiler-core", ImpactKind.OVERRIDE_BUMP, "3.5.43"),
        }
        assert result.is_actionable is True

    def test_a_requirer_that_does_not_move_blocks_the_override_bump(self):
        pinned = override("3.5.42", ossiq=True)
        shared = make_nested_record(
            "@vue/shared",
            copy_of(
                "3.5.42",
                edge("vue", "3.5.42", "3.5.42"),
                edge("@vue/devtools", "7.0.0", "3.5.42"),
                governed_by=pinned,
            ),
        )
        registry = make_npm_registry(
            versions_by_name={"@vue/shared": [pv("3.5.43"), pv("3.5.42")]},
            requires_by_pkg_ver={("vue", "3.5.43"): {"@vue/shared": "3.5.43"}},
        )

        result = simulate_single("vue", "3.5.43", {"@vue/shared": shared}, registry, installed_version="3.5.42")

        (impact,) = result.transitive_impacts
        assert impact.kind == ImpactKind.OVERRIDE_BUMP
        assert impact.has_conflict is True
        assert impact.conflict == RejectionDetail("no version satisfies", ("3.5.42", "3.5.43"))
        assert result.is_actionable is False

    def test_an_edge_the_override_already_breaches_does_not_block_its_bump(self):
        """The override was written to get past picomatch ^2 edges; bumping it must not need them."""
        pinned = override("4.0.7", ossiq=True)
        picomatch = make_nested_record(
            "picomatch",
            copy_of(
                "4.0.7", edge("micromatch", "4.0.8", "^2.3.1"), edge("vite", "8.2.2", "^4.0.4"), governed_by=pinned
            ),
        )
        registry = make_npm_registry(
            versions_by_name={"picomatch": [pv("4.0.9"), pv("4.0.7")]},
            requires_by_pkg_ver={("vite", "8.3.2"): {"picomatch": "^4.0.9"}},
        )

        result = simulate_single("vite", "8.3.2", {"picomatch": picomatch}, registry, installed_version="8.2.2")

        (impact,) = result.transitive_impacts
        assert (impact.kind, impact.projected_version) == (ImpactKind.OVERRIDE_BUMP, "4.0.9")
        assert result.is_actionable is True

    def test_a_one_copy_registry_still_merges_every_parent(self):
        """The copies on a record change nothing for pip and uv: a diamond still conflicts."""
        urllib3 = make_nested_record("urllib3", copy_of("1.26.18", edge("requests", "2.31.0", "<2.0")))
        urllib3.all_constraints = ["<2.0"]
        registry = make_registry(
            versions_by_name={"urllib3": [pv("2.2.0"), pv("1.26.18")]},
            requires_by_pkg_ver={("requests", "2.32.0"): {"urllib3": ">=2.0"}},
        )

        result = simulate_single("requests", "2.32.0", {"urllib3": urllib3}, registry)

        assert result.is_actionable is False
        assert result.transitive_impacts[0].has_conflict is True
        assert result.transitive_impacts[0].kind == ImpactKind.UPGRADE


# ============================================================================
# Tests: entry_from_record — Phase 4c UpdateEntry propagation
# ============================================================================


def make_scan_record_with_recommendation(
    package_name: str,
    installed_version: str,
    recommended_version: str,
    impacts: list[TransitiveImpact] | None = None,
) -> ScanRecord:
    record = make_scan_record(package_name, installed_version)
    record.recommended_version = recommended_version
    record.update_transitive_impacts = impacts or []
    return record


def make_transitive_impact(*, has_conflict: bool) -> TransitiveImpact:
    return TransitiveImpact(
        package_name="urllib3",
        current_version="1.26.18",
        projected_version=None if has_conflict else "2.2.0",
        new_constraint=">=2.0",
        driven_by="requests",
        has_conflict=has_conflict,
        conflict=RejectionDetail("conflict", ()) if has_conflict else None,
    )


class TestEntryFromRecordPropagation:
    def test_is_actionable_true_when_no_impacts(self):
        record = make_scan_record_with_recommendation("requests", "2.28.0", "2.32.0")
        entry = entry_from_record(record, is_direct=True)
        assert entry.is_actionable is True
        assert entry.transitive_impacts == []

    def test_is_actionable_true_when_no_conflicts(self):
        impact = make_transitive_impact(has_conflict=False)
        record = make_scan_record_with_recommendation("requests", "2.28.0", "2.32.0", impacts=[impact])
        entry = entry_from_record(record, is_direct=True)
        assert entry.is_actionable is True
        assert len(entry.transitive_impacts) == 1

    def test_is_actionable_false_when_conflict_present(self):
        impact = make_transitive_impact(has_conflict=True)
        record = make_scan_record_with_recommendation("requests", "2.28.0", "2.32.0", impacts=[impact])
        entry = entry_from_record(record, is_direct=True)
        assert entry.is_actionable is False
        assert entry.transitive_impacts[0].has_conflict is True

    def test_impacts_copied_not_shared(self):
        impact = make_transitive_impact(has_conflict=False)
        record = make_scan_record_with_recommendation("requests", "2.28.0", "2.32.0", impacts=[impact])
        entry = entry_from_record(record, is_direct=True)
        assert entry.transitive_impacts is not record.update_transitive_impacts

    def test_version_defined_propagated(self):
        record = make_scan_record_with_recommendation("requests", "2.28.0", "2.32.0")
        record.version_constraint = "~=2.28.0"
        entry = entry_from_record(record, is_direct=True)
        assert entry.version_defined == "~=2.28.0"

    def test_version_defined_none_when_not_set(self):
        record = make_scan_record_with_recommendation("requests", "2.28.0", "2.32.0")
        entry = entry_from_record(record, is_direct=True)
        assert entry.version_defined is None

    def test_constraint_type_propagated(self):
        record = make_scan_record_with_recommendation("requests", "2.28.0", "2.32.0")
        record.constraint_info = ConstraintSource(type=ConstraintType.NARROWED, source_file="pyproject.toml")
        entry = entry_from_record(record, is_direct=True)
        assert entry.constraint_type == ConstraintType.NARROWED
