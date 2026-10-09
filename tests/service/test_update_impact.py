"""Tests for service/update_impact.py — transitive dependency impact simulation."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

from ossiq.domain.common import ConstraintType, ProjectPackagesRegistry, RejectionDetail
from ossiq.domain.project import ConstraintSource, IncomingEdge, InstalledCopy
from ossiq.domain.release_cutoff import ReleaseCutoff
from ossiq.domain.version import PackageVersion, PeerDependency, VersionsDifference
from ossiq.service.project.models import ScanRecord
from ossiq.service.update import entry_from_record
from ossiq.service.update_impact import (
    DirectUpdateImpact,
    ImpactKind,
    TransitiveImpact,
    assess_transitive_impact,
    copy_to_move,
    find_best_satisfying_version,
    incoming_peer_edges,
    moves_with_candidate,
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
    peers_by_pkg_ver: dict[tuple[str, str], dict[str, PeerDependency]] | None = None,
) -> MagicMock:
    from functools import cmp_to_key

    from ossiq.domain.common import ProjectPackagesRegistry

    registry = MagicMock()
    registry.package_registry = ProjectPackagesRegistry.PYPI
    registry.package_versions.side_effect = lambda name: (versions_by_name or {}).get(name, [])
    registry.package_version_requires.side_effect = lambda name, ver: (requires_by_pkg_ver or {}).get((name, ver), {})
    registry.package_version_peers.side_effect = lambda name, ver: (peers_by_pkg_ver or {}).get((name, ver), {})

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
    peers_by_pkg_ver: dict[tuple[str, str], dict[str, PeerDependency]] | None = None,
) -> MagicMock:
    registry = make_registry(versions_by_name, requires_by_pkg_ver, peers_by_pkg_ver)
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

        # The family moves in place: nesting 3.5.43 under vue would leave the 3.5.42 copies hoisted.
        assert {
            i.package_name: (i.kind, i.current_version, i.projected_version) for i in result.transitive_impacts
        } == {
            "@vue/shared": (ImpactKind.OVERRIDE_BUMP, "3.5.42", "3.5.43"),
            "@vue/compiler-dom": (ImpactKind.OVERRIDE_BUMP, "3.5.42", "3.5.43"),
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


def peer_edge(requirer: str, version: str, spec: str) -> IncomingEdge:
    return IncomingEdge(requirer_name=requirer, requirer_version=version, spec=spec, is_peer=True)


TS_PEER_RANGE = ">=4.8.4 <6.1.0"


class TestIncomingPeers:
    """A peer binds the one instance its requirer resolves, so npm cannot nest around it."""

    def typescript_registry(self) -> MagicMock:
        return make_npm_registry(versions_by_name={"typescript": [pv("7.0.2"), pv("6.0.5"), pv("6.0.3")]})

    def ts_eslint(self) -> dict[str, ScanRecord]:
        record = make_nested_record("typescript-eslint", copy_of("8.0.0", edge("eslint-config", "1.0.0", "^8")))
        return {"typescript-eslint": record}

    def test_candidate_outside_a_transitive_requirers_peer_range_is_not_actionable(self):
        """typescript 6.0.3 -> 7.0.2 is refused: typescript-eslint peer-requires <6.1.0."""
        result = simulate_single(
            "typescript",
            "7.0.2",
            self.ts_eslint(),
            self.typescript_registry(),
            installed_version="6.0.3",
            incoming_peers=(peer_edge("typescript-eslint", "8.0.0", TS_PEER_RANGE),),
        )

        (impact,) = result.transitive_impacts
        assert result.is_actionable is False
        assert (impact.kind, impact.package_name, impact.driven_by) == (
            ImpactKind.PEER,
            "typescript-eslint",
            "typescript",
        )
        assert impact.has_conflict is True
        assert impact.conflict == RejectionDetail("7.0.2 violates", (TS_PEER_RANGE,))

    def test_candidate_inside_the_peer_range_is_actionable(self):
        result = simulate_single(
            "typescript",
            "6.0.5",
            self.ts_eslint(),
            self.typescript_registry(),
            installed_version="6.0.3",
            incoming_peers=(peer_edge("typescript-eslint", "8.0.0", TS_PEER_RANGE),),
        )

        assert result.transitive_impacts == []
        assert result.is_actionable is True

    def test_range_the_installed_version_already_violates_does_not_gate(self):
        """Existing drift is reported elsewhere; it must not also block (or force) an upgrade."""
        result = simulate_single(
            "typescript",
            "7.0.2",
            self.ts_eslint(),
            self.typescript_registry(),
            installed_version="7.0.0",
            incoming_peers=(peer_edge("typescript-eslint", "8.0.0", TS_PEER_RANGE),),
        )

        assert result.transitive_impacts == []
        assert result.is_actionable is True

    def test_one_conflict_per_requirer_carries_every_range_it_breaks(self):
        result = simulate_single(
            "typescript",
            "7.0.2",
            self.ts_eslint(),
            self.typescript_registry(),
            installed_version="6.0.3",
            incoming_peers=(
                peer_edge("typescript-eslint", "8.0.0", TS_PEER_RANGE),
                peer_edge("typescript-eslint", "8.0.0", TS_PEER_RANGE),
                peer_edge("typescript-eslint", "8.0.0", "^6"),
            ),
        )

        (impact,) = result.transitive_impacts
        assert impact.conflict == RejectionDetail("7.0.2 violates", (TS_PEER_RANGE, "^6"))

    def test_a_direct_requirer_is_left_to_the_solver(self):
        """Not in transitive_by_name means direct: whether it moves jointly is not a single-candidate question."""
        result = simulate_single(
            "typescript",
            "7.0.2",
            {},
            self.typescript_registry(),
            installed_version="6.0.3",
            incoming_peers=(peer_edge("@vue/eslint-config-typescript", "14.0.0", TS_PEER_RANGE),),
        )

        assert result.is_actionable is True

    def test_python_registry_without_peers_is_untouched(self):
        registry = make_registry(versions_by_name={"typescript": [pv("7.0.2")]})

        result = simulate_single("typescript", "7.0.2", {}, registry, installed_version="6.0.3")

        assert result.transitive_impacts == []
        assert result.is_actionable is True


class TestLockstepFamily:
    """vue peer-pins nothing, but @vue/server-renderer peer-pins vue exactly and vue pins it back."""

    def family(self, *, server_renderer_peer: str = "3.5.44", other_requirer: str | None = None) -> tuple:
        owners = [edge("vue", "3.5.43", "3.5.43")]
        if other_requirer is not None:
            owners.append(edge("other-host", "1.0.0", other_requirer))
        renderer = make_nested_record("@vue/server-renderer", copy_of("3.5.43", *owners))
        registry = make_npm_registry(
            versions_by_name={
                "@vue/server-renderer": [pv("3.5.44"), pv("3.5.43")],
                "vue": [pv("3.5.44"), pv("3.5.43")],
            },
            requires_by_pkg_ver={("vue", "3.5.44"): {"@vue/server-renderer": "3.5.44"}},
            peers_by_pkg_ver={
                ("@vue/server-renderer", "3.5.43"): {"vue": PeerDependency("3.5.43")},
                ("@vue/server-renderer", "3.5.44"): {"vue": PeerDependency(server_renderer_peer)},
            },
        )
        return {"@vue/server-renderer": renderer}, registry

    def bump_vue(self, transitive: dict[str, ScanRecord], registry: MagicMock):
        return simulate_single(
            "vue",
            "3.5.44",
            transitive,
            registry,
            installed_version="3.5.43",
            incoming_peers=(peer_edge("@vue/server-renderer", "3.5.43", "3.5.43"),),
        )

    def test_the_requirer_that_moves_with_the_candidate_is_judged_at_its_new_peers(self):
        transitive, registry = self.family()

        result = self.bump_vue(transitive, registry)

        assert result.is_actionable is True
        assert [(i.kind, i.projected_version) for i in result.transitive_impacts] == [
            (ImpactKind.OVERRIDE_BUMP, "3.5.44")
        ]

    def test_a_pair_that_would_still_mismatch_after_moving_is_refused(self):
        """No mismatched pair, ever: the moved server-renderer would demand a vue nobody ships."""
        transitive, registry = self.family(server_renderer_peer="3.5.45")

        result = self.bump_vue(transitive, registry)

        assert result.is_actionable is False
        (conflict,) = [i for i in result.transitive_impacts if i.kind == ImpactKind.PEER]
        assert conflict.conflict == RejectionDetail("3.5.44 violates", ("3.5.45",))

    def test_another_user_that_accepts_the_new_version_moves_with_the_copy(self):
        """The keyed override rewrites other-host's ^3 edge too, so the shared copy moves as one."""
        transitive, registry = self.family(other_requirer="^3")

        result = self.bump_vue(transitive, registry)

        assert result.is_actionable is True
        assert [(i.kind, i.projected_version) for i in result.transitive_impacts] == [
            (ImpactKind.OVERRIDE_BUMP, "3.5.44")
        ]

    def test_another_user_that_cannot_follow_refuses_the_bump(self):
        """Splitting the family is not the fallback: the candidate is refused, with the specs that hold it."""
        transitive, registry = self.family(other_requirer="3.5.43")

        result = self.bump_vue(transitive, registry)

        assert result.is_actionable is False
        (conflict,) = [i for i in result.transitive_impacts if i.has_conflict and i.kind == ImpactKind.OVERRIDE_BUMP]
        assert conflict.conflict == RejectionDetail("no version satisfies", ("3.5.43", "3.5.44"))


class TestCopyLeftHoldingOnlyPeers:
    """vue 3.5.42 -> 3.5.43 strands the hoisted server-renderer that @vue/test-utils optionally peers on."""

    def bump(self, *, peer_range: str = "3.x") -> DirectUpdateImpact:
        renderer = make_nested_record(
            "@vue/server-renderer",
            copy_of(
                "3.5.42",
                edge("vue", "3.5.42", "^3.5.42"),
                IncomingEdge("@vue/test-utils", "2.5.1", peer_range, is_peer=True, optional=True),
            ),
        )
        registry = make_npm_registry(
            versions_by_name={"@vue/server-renderer": [pv("3.5.43"), pv("3.5.42")]},
            requires_by_pkg_ver={("vue", "3.5.43"): {"@vue/server-renderer": ">=3.5.43"}},
        )
        return simulate_single(
            "vue", "3.5.43", {"@vue/server-renderer": renderer}, registry, installed_version="3.5.42"
        )

    def test_the_copy_moves_instead_of_nesting_out_of_the_peers_reach(self):
        result = self.bump()

        assert result.is_actionable is True
        assert [(i.kind, i.current_version, i.projected_version) for i in result.transitive_impacts] == [
            (ImpactKind.OVERRIDE_BUMP, "3.5.42", "3.5.43")
        ]

    def test_a_peer_range_the_new_version_misses_refuses_the_bump(self):
        """The peer edge moves with the copy's other edges, so it has to accept the new version too."""
        result = self.bump(peer_range="3.5.42")

        assert result.is_actionable is False


class TestCopyToMove:
    def test_a_ranged_requirement_with_other_owners_still_nests(self):
        """Ordinary npm nesting is left alone: nothing pinned, and someone else keeps the old copy."""
        copies = [copy_of("1.0.0", edge("a", "1.0.0", "^1"), edge("b", "1.0.0", "^1"))]

        assert copy_to_move(copies, "^2", "a", {"a"}) is None

    def test_an_exact_pin_moving_to_another_exact_pin_moves(self):
        copies = [copy_of("1.0.0", edge("a", "1.0.0", "1.0.0"), edge("b", "1.0.0", "^1"))]

        assert copy_to_move(copies, "1.1.0", "a", {"a"}) is copies[0]

    def test_only_the_copy_the_requirer_resolves_is_considered(self):
        copies = [copy_of("2.0.0", edge("z", "1.0.0", "2.0.0")), copy_of("1.0.0", edge("a", "1.0.0", "1.0.0"))]

        assert copy_to_move(copies, "1.1.0", "a", {"a"}) is copies[1]


class TestMovesWithCandidate:
    def test_every_requirer_of_the_copy_is_moving(self):
        record = make_nested_record("b", copy_of("1.0.0", edge("a", "1.0.0", "1.0.0"), edge("c", "1.0.0", "^1")))
        assert moves_with_candidate(record, "1.0.0", {"a", "c"}) is True

    def test_one_requirer_staying_put_holds_the_copy(self):
        record = make_nested_record("b", copy_of("1.0.0", edge("a", "1.0.0", "1.0.0"), edge("c", "1.0.0", "^1")))
        assert moves_with_candidate(record, "1.0.0", {"a"}) is False

    def test_peer_edges_onto_the_copy_do_not_hold_it(self):
        record = make_nested_record("b", copy_of("1.0.0", edge("a", "1.0.0", "1.0.0"), peer_edge("z", "1.0.0", "^1")))
        assert moves_with_candidate(record, "1.0.0", {"a"}) is True

    def test_a_copy_nobody_is_known_to_ask_for_is_not_assumed_to_move(self):
        assert moves_with_candidate(make_nested_record("b", copy_of("1.0.0")), "1.0.0", {"a"}) is False
        assert moves_with_candidate(make_nested_record("b", copy_of("1.0.0")), "9.9.9", {"a"}) is False


class TestIncomingPeerEdges:
    def test_only_peer_edges_on_the_copy_being_replaced(self):
        copies = [
            copy_of("2.0.0", edge("a", "1.0.0", "^2"), peer_edge("p", "1.0.0", "^2")),
            copy_of("1.0.0", peer_edge("q", "1.0.0", "^1")),
        ]
        assert incoming_peer_edges(copies, "2.0.0") == (peer_edge("p", "1.0.0", "^2"),)


class TestCandidatePeers:
    """The peers a candidate declares: an absent optional one binds nothing, a present one does."""

    def registry(self, *, optional: bool, host_versions: list[PackageVersion]) -> MagicMock:
        return make_npm_registry(
            versions_by_name={"host": host_versions},
            peers_by_pkg_ver={("plugin", "2.0.0"): {"host": PeerDependency("^9", optional=optional)}},
        )

    def test_optional_peer_absent_from_the_tree_does_not_constrain(self):
        result = simulate_single(
            "plugin", "2.0.0", {}, self.registry(optional=True, host_versions=[]), installed_names={"plugin"}
        )

        assert result.transitive_impacts == []
        assert result.is_actionable is True

    def test_optional_peer_present_in_the_tree_is_enforced(self):
        host = make_nested_record("host", copy_of("1.0.0"))

        result = simulate_single(
            "plugin",
            "2.0.0",
            {"host": host},
            self.registry(optional=True, host_versions=[pv("1.0.0")]),
            installed_names={"plugin", "host"},
        )

        assert result.is_actionable is False
        (impact,) = result.transitive_impacts
        assert (impact.package_name, impact.has_conflict) == ("host", True)

    def test_required_peer_absent_from_the_tree_is_installed_alongside(self):
        registry = self.registry(optional=False, host_versions=[pv("9.1.0")])

        result = simulate_single("plugin", "2.0.0", {}, registry, installed_names={"plugin"})

        (impact,) = result.transitive_impacts
        assert (impact.kind, impact.projected_version, impact.has_conflict) == (ImpactKind.NEW_DEP, "9.1.0", False)
        assert result.is_actionable is True

    def test_peer_range_the_installed_release_already_missed_is_not_new_breakage(self):
        host = make_nested_record("host", copy_of("1.0.0"))
        registry = make_npm_registry(
            versions_by_name={"host": [pv("1.0.0")]},
            peers_by_pkg_ver={
                ("plugin", "1.0.0"): {"host": PeerDependency("^9")},
                ("plugin", "2.0.0"): {"host": PeerDependency("^9")},
            },
        )

        result = simulate_single(
            "plugin", "2.0.0", {"host": host}, registry, installed_names={"plugin", "host"}, installed_version="1.0.0"
        )

        assert result.transitive_impacts == []
        assert result.is_actionable is True


class TestPeerSet:
    """npm resolves a candidate's peers, and their peers, as one set; so does the simulation."""

    def test_a_required_peer_nobody_publishes_blocks(self):
        registry = make_npm_registry(
            versions_by_name={"host": [pv("1.0.0")]},
            peers_by_pkg_ver={("plugin", "2.0.0"): {"host": PeerDependency("^9")}},
        )

        result = simulate_single("plugin", "2.0.0", {}, registry, installed_names={"plugin"})

        assert result.is_actionable is False
        (impact,) = result.transitive_impacts
        assert (impact.kind, impact.current_version, impact.has_conflict) == (ImpactKind.PEER, None, True)
        assert impact.conflict == RejectionDetail("no version satisfies", ("^9",))

    def test_the_peers_of_an_auto_installed_peer_are_checked_against_the_tree(self):
        """plugin 2 newly needs eslint-ts-parser, which peer-requires typescript <6.1 while 7.0.2 is installed."""
        typescript = make_nested_record("typescript", copy_of("7.0.2"))
        registry = make_npm_registry(
            versions_by_name={"ts-parser": [pv("8.71.0")], "typescript": [pv("7.0.2")]},
            peers_by_pkg_ver={
                ("plugin", "2.0.0"): {"ts-parser": PeerDependency("^8")},
                ("ts-parser", "8.71.0"): {"typescript": PeerDependency(">=4.8.4 <6.1.0")},
            },
        )

        result = simulate_single("plugin", "2.0.0", {"typescript": typescript}, registry, installed_names={"plugin"})

        assert result.is_actionable is False
        assert [(i.package_name, i.kind) for i in result.transitive_impacts] == [
            ("ts-parser", ImpactKind.NEW_DEP),
            ("typescript", ImpactKind.PEER),
        ]

    def test_an_auto_installed_peers_peer_on_a_direct_dependency_is_checked(self):
        registry = make_npm_registry(
            versions_by_name={"ts-parser": [pv("8.71.0")]},
            peers_by_pkg_ver={
                ("plugin", "2.0.0"): {"ts-parser": PeerDependency("^8")},
                ("ts-parser", "8.71.0"): {"typescript": PeerDependency(">=4.8.4 <6.1.0")},
            },
        )

        result = simulate_single(
            "plugin", "2.0.0", {}, registry, installed_names={"plugin"}, direct_versions={"typescript": "7.0.2"}
        )

        assert result.is_actionable is False

    def test_the_candidates_own_peer_on_a_direct_dependency_is_left_to_the_solver(self):
        registry = make_npm_registry(peers_by_pkg_ver={("plugin", "2.0.0"): {"typescript": PeerDependency("<6.1.0")}})

        result = simulate_single("plugin", "2.0.0", {}, registry, direct_versions={"typescript": "7.0.2"})

        assert result.is_actionable is True

    def test_a_peer_cycle_terminates(self):
        registry = make_npm_registry(
            versions_by_name={"a": [pv("1.0.0")], "b": [pv("1.0.0")]},
            peers_by_pkg_ver={
                ("plugin", "2.0.0"): {"a": PeerDependency("^1")},
                ("a", "1.0.0"): {"b": PeerDependency("^1")},
                ("b", "1.0.0"): {"a": PeerDependency("^1")},
            },
        )

        result = simulate_single("plugin", "2.0.0", {}, registry, installed_names={"plugin"})

        assert result.is_actionable is True
        assert [i.package_name for i in result.transitive_impacts] == ["a", "b"]

    def test_a_new_peer_that_peer_requires_the_candidate_is_held_to_the_candidates_version(self):
        registry = make_npm_registry(
            versions_by_name={"helper": [pv("1.0.0")]},
            peers_by_pkg_ver={
                ("plugin", "2.0.0"): {"helper": PeerDependency("^1")},
                ("helper", "1.0.0"): {"plugin": PeerDependency("^1")},
            },
        )

        result = simulate_single("plugin", "2.0.0", {}, registry, installed_names={"plugin"})

        assert result.is_actionable is False
        assert result.transitive_impacts[-1].conflict == RejectionDetail("2.0.0 violates", ("^1",))

    def test_a_present_peer_out_of_range_moves_its_copy(self):
        host = make_nested_record("host", copy_of("1.0.0", edge("other", "1.0.0", "^1 || ^2")))
        registry = make_npm_registry(
            versions_by_name={"host": [pv("1.0.0"), pv("2.1.0")]},
            peers_by_pkg_ver={("plugin", "2.0.0"): {"host": PeerDependency("^2")}},
        )

        result = simulate_single("plugin", "2.0.0", {"host": host}, registry, installed_names={"plugin", "host"})

        assert result.is_actionable is True
        (impact,) = result.transitive_impacts
        assert (impact.kind, impact.current_version, impact.projected_version) == (
            ImpactKind.OVERRIDE_BUMP,
            "1.0.0",
            "2.1.0",
        )

    def test_an_override_the_user_wrote_holds_the_peer_target(self):
        """The declared range binds: an override never stands in for satisfying it."""
        host = make_nested_record("host", copy_of("1.0.0", governed_by=override("1.0.0", ossiq=False)))
        registry = make_npm_registry(
            versions_by_name={"host": [pv("1.0.0"), pv("2.1.0")]},
            peers_by_pkg_ver={("plugin", "2.0.0"): {"host": PeerDependency("^2")}},
        )

        result = simulate_single("plugin", "2.0.0", {"host": host}, registry, installed_names={"plugin", "host"})

        assert result.is_actionable is False
        (impact,) = result.transitive_impacts
        assert impact.held_by_override is not None and impact.held_by_override.is_ossiq_authored is False


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
