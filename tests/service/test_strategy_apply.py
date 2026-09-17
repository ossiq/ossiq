"""Tests for service/project/strategy.py — the impure wiring around the pure selector."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from packaging.version import Version

from ossiq.domain.common import (
    ConstraintType,
    EngineContextSource,
    ModuleSystem,
    ProjectPackagesRegistry,
    RecommendationRung,
)
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion, VersionsDifference
from ossiq.service.project.ladder import compute_version_ladder
from ossiq.service.project.models import ScanRecord
from ossiq.service.project.strategy import apply_update_strategy, build_candidates
from ossiq.service.update_impact import DirectUpdateImpact, TransitiveImpact
from ossiq.strategy.overrides import StrategyPlan
from ossiq.strategy.pyramid import UpdateStrategy

CONSTRAINT_SOURCE = ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml")
NO_DIFF = VersionsDifference("1.0.0", "1.0.0", 0, diff_name="LATEST")
NOW = datetime(2024, 6, 1, tzinfo=UTC)
STANDARD_PLAN = StrategyPlan(default=UpdateStrategy.STANDARD)


def pv(
    version: str,
    published: str = "2024-01-01T00:00:00Z",
    module_system: ModuleSystem | None = None,
    runtime_requirements: dict[str, str] | None = None,
) -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url=f"https://example.com/{version}",
        declared_dependencies={},
        published_date_iso=published,
        module_system=module_system,
        runtime_requirements=runtime_requirements,
    )


def make_registry(versions_by_name: dict[str, list[PackageVersion]]) -> MagicMock:
    registry = MagicMock()
    registry.package_registry = ProjectPackagesRegistry.PYPI
    registry.package_versions.side_effect = lambda name: versions_by_name.get(name, [])
    registry.difference_versions.return_value = NO_DIFF

    def compare(v1: str, v2: str) -> int:
        p1, p2 = Version(v1), Version(v2)
        return -1 if p1 < p2 else (1 if p1 > p2 else 0)

    def newest(candidates):
        as_list = list(candidates)
        return max(as_list, key=lambda p: Version(p.version)) if as_list else None

    registry.compare_versions.side_effect = compare
    registry.newest_version.side_effect = newest
    return registry


def make_npm_registry(versions_by_name: dict[str, list[PackageVersion]]) -> MagicMock:
    registry = make_registry(versions_by_name)
    registry.package_registry = ProjectPackagesRegistry.NPM
    return registry


def make_record(name: str, installed: str, version_constraint: str | None = None) -> ScanRecord:
    return ScanRecord(
        package_name=name,
        dependency_name=name,
        is_optional_dependency=False,
        installed_version=installed,
        latest_version=None,
        versions_diff_index=NO_DIFF,
        time_lag_days=None,
        releases_lag=0,
        cve=[],
        constraint_info=CONSTRAINT_SOURCE,
        version_constraint=version_constraint,
    )


class TestBuildCandidates:
    def test_rungs_agree_with_compute_version_ladder(self) -> None:
        registry = make_registry({"pkg": [pv("1.1.0"), pv("1.9.0"), pv("2.0.0")]})
        record = make_record("pkg", "1.0.0", version_constraint="<2.0.0")
        releases = list(registry.package_versions("pkg"))

        ladder = compute_version_ladder(releases, "1.0.0", "<2.0.0", registry, now=NOW)
        candidates = build_candidates(record, releases, registry, now=NOW).candidates

        in_range = [c for c in candidates if c.rung == RecommendationRung.IN_RANGE]
        assert max(in_range, key=lambda c: Version(c.version)).version == ladder.latest_in_range

        same_major = [c for c in candidates if c.rung in (RecommendationRung.IN_RANGE, RecommendationRung.IN_MAJOR)]
        assert max(same_major, key=lambda c: Version(c.version)).version == ladder.latest_in_major

    def test_installed_version_itself_excluded(self) -> None:
        registry = make_registry({"pkg": [pv("1.0.0"), pv("1.1.0")]})
        record = make_record("pkg", "1.0.0")
        candidates = build_candidates(record, list(registry.package_versions("pkg")), registry, now=NOW).candidates
        assert "1.0.0" not in {c.version for c in candidates}

    def test_qualifying_cve_flags_affected_candidate(self) -> None:
        from ossiq.domain.common import CveDatabase
        from ossiq.domain.cve import CVE, Severity

        registry = make_registry({"pkg": [pv("1.1.0"), pv("1.2.0")]})
        record = make_record("pkg", "1.0.0")
        record.cve = [
            CVE(
                id="CVE-1",
                cve_ids=("CVE-1",),
                source=CveDatabase.OSV,
                package_name="pkg",
                package_registry=ProjectPackagesRegistry.PYPI,
                summary="bad",
                severity=Severity.HIGH,
                affected_versions=("1.1.0",),
                published=None,
                link="https://example.test",
                epss=0.5,
            )
        ]
        candidates = build_candidates(record, list(registry.package_versions("pkg")), registry, now=NOW).candidates
        by_version = {c.version: c for c in candidates}
        assert by_version["1.1.0"].has_cve is True
        assert by_version["1.2.0"].has_cve is False


class TestBuildCandidatesRejections:
    """A release that clears the structural pre-filter but fails validator is recorded as a
    RejectedCandidate instead of silently disappearing (item #6)."""

    def test_rejected_candidate_ossiq_authored_override_reason(self) -> None:
        registry = make_registry({"pkg": [pv("1.1.0")]})
        record = make_record("pkg", "1.0.0")
        blocking_record = make_record("blocked-dep", "2.0.0")
        blocking_record.constraint_info = ConstraintSource(
            type=ConstraintType.OVERRIDE, source_file="package.json", is_ossiq_authored=True
        )
        impact = DirectUpdateImpact(
            package_name="pkg",
            recommended_version="1.1.0",
            transitive_impacts=[
                TransitiveImpact(
                    package_name="blocked-dep",
                    current_version="2.0.0",
                    projected_version=None,
                    new_constraint=">=3.0.0",
                    driven_by="pkg",
                    has_conflict=True,
                    conflict_detail="no version satisfies: >=3.0.0, ==2.0.0",
                )
            ],
            is_actionable=False,
            fallback_version=None,
        )

        built = build_candidates(
            record,
            list(registry.package_versions("pkg")),
            registry,
            now=NOW,
            validator=lambda _pkg, _ver: impact,
            transitive_by_name={"blocked-dep": blocking_record},
        )

        assert built.candidates == ()
        assert len(built.rejected) == 1
        assert built.rejected[0].version == "1.1.0"
        assert built.rejected[0].reason == (
            "blocked-dep is held by an OSS IQ-authored override (no version satisfies: >=3.0.0, ==2.0.0)"
        )

    def test_rejected_candidate_user_authored_override_reason(self) -> None:
        registry = make_registry({"pkg": [pv("1.1.0")]})
        record = make_record("pkg", "1.0.0")
        blocking_record = make_record("blocked-dep", "2.0.0")
        blocking_record.constraint_info = ConstraintSource(
            type=ConstraintType.OVERRIDE, source_file="pyproject.toml", is_ossiq_authored=False
        )
        impact = DirectUpdateImpact(
            package_name="pkg",
            recommended_version="1.1.0",
            transitive_impacts=[
                TransitiveImpact(
                    package_name="blocked-dep",
                    current_version="2.0.0",
                    projected_version=None,
                    new_constraint=">=3.0.0",
                    driven_by="pkg",
                    has_conflict=True,
                    conflict_detail=None,
                )
            ],
            is_actionable=False,
            fallback_version=None,
        )

        built = build_candidates(
            record,
            list(registry.package_versions("pkg")),
            registry,
            now=NOW,
            validator=lambda _pkg, _ver: impact,
            transitive_by_name={"blocked-dep": blocking_record},
        )

        assert built.rejected[0].reason == "blocked-dep is held by an override in pyproject.toml"

    def test_rejected_candidate_generic_reason_without_override(self) -> None:
        registry = make_registry({"pkg": [pv("1.1.0")]})
        record = make_record("pkg", "1.0.0")
        blocking_record = make_record("blocked-dep", "2.0.0")  # DECLARED, not OVERRIDE
        impact = DirectUpdateImpact(
            package_name="pkg",
            recommended_version="1.1.0",
            transitive_impacts=[
                TransitiveImpact(
                    package_name="blocked-dep",
                    current_version="2.0.0",
                    projected_version=None,
                    new_constraint=">=3.0.0",
                    driven_by="pkg",
                    has_conflict=True,
                    conflict_detail=None,
                )
            ],
            is_actionable=False,
            fallback_version=None,
        )

        built = build_candidates(
            record,
            list(registry.package_versions("pkg")),
            registry,
            now=NOW,
            validator=lambda _pkg, _ver: impact,
            transitive_by_name={"blocked-dep": blocking_record},
        )

        assert built.rejected[0].reason == "blocked-dep requires >=3.0.0"

    def test_rejected_candidates_capped_one_per_rung_keeps_newest(self) -> None:
        """Multiple rejected releases at the same rung collapse to the newest; rejections at
        different rungs each surface."""
        registry = make_registry({"pkg": [pv("1.1.0"), pv("1.2.0"), pv("3.0.0")]})
        record = make_record("pkg", "1.0.0", version_constraint="<2.0.0")

        def validator(_pkg: str, ver: str) -> DirectUpdateImpact:
            return DirectUpdateImpact(
                package_name="pkg",
                recommended_version=ver,
                transitive_impacts=[],
                is_actionable=False,
                fallback_version=None,
            )

        built = build_candidates(
            record,
            list(registry.package_versions("pkg")),
            registry,
            now=NOW,
            validator=validator,
            transitive_by_name={},
        )

        assert built.candidates == ()
        # 1.1.0/1.2.0 both satisfy <2.0.0 (IN_RANGE) - only the newest (1.2.0) survives; 3.0.0 is
        # its own rung (LATEST) and always surfaces.
        assert [r.version for r in built.rejected] == ["1.2.0", "3.0.0"]


class TestApplyUpdateStrategy:
    def test_only_given_records_are_touched(self) -> None:
        registry = make_registry({"a": [pv("1.1.0")], "b": [pv("2.1.0")]})
        record_a = make_record("a", "1.0.0")
        record_b = make_record("b", "2.0.0")

        apply_update_strategy(
            [record_a],
            registry,
            STANDARD_PLAN,
            versions_since={("a", "1.0.0"): list(registry.package_versions("a"))},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
        )

        assert record_a.recommended_version == "1.1.0"
        assert record_b.strategy_selection is None
        assert record_b.recommended_version is None

    def test_no_target_clears_any_prior_recommendation(self) -> None:
        registry = make_registry({"pkg": []})
        record = make_record("pkg", "1.0.0")
        record.recommended_version = "1.0.0"  # something stale from an earlier phase

        apply_update_strategy(
            [record],
            registry,
            STANDARD_PLAN,
            versions_since={("pkg", "1.0.0"): []},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
        )

        assert record.recommended_version is None
        assert record.strategy_selection is not None

    def test_resimulates_impacts_when_target_changes(self) -> None:
        registry = make_registry({"pkg": [pv("1.1.0")]})
        record = make_record("pkg", "1.0.0")
        impact = DirectUpdateImpact(
            package_name="pkg",
            recommended_version="1.1.0",
            transitive_impacts=[],
            is_actionable=True,
            fallback_version=None,
        )

        with patch("ossiq.service.project.strategy.simulate_single", return_value=impact) as mocked:
            apply_update_strategy(
                [record],
                registry,
                STANDARD_PLAN,
                versions_since={("pkg", "1.0.0"): list(registry.package_versions("pkg"))},
                transitive_by_name={},
                installed_names=set(),
                allow_prerelease=False,
                now=NOW,
            )

        assert mocked.called
        assert record.recommended_version == "1.1.0"
        assert record.update_transitive_impacts == []

    def test_clears_transitive_impacts_when_resimulation_not_actionable(self) -> None:
        registry = make_registry({"pkg": [pv("1.1.0")]})
        record = make_record("pkg", "1.0.0")
        record.update_transitive_impacts = [
            TransitiveImpact(
                package_name="stale-dep",
                current_version="1.0.0",
                projected_version="1.0.0",
                new_constraint=">=1.0.0",
                driven_by="pkg",
                has_conflict=False,
                conflict_detail=None,
            )
        ]
        impact = DirectUpdateImpact(
            package_name="pkg",
            recommended_version="1.1.0",
            transitive_impacts=[],
            is_actionable=False,
            fallback_version=None,
        )

        with patch("ossiq.service.project.strategy.simulate_single", return_value=impact):
            apply_update_strategy(
                [record],
                registry,
                STANDARD_PLAN,
                versions_since={("pkg", "1.0.0"): list(registry.package_versions("pkg"))},
                transitive_by_name={},
                installed_names=set(),
                allow_prerelease=False,
                now=NOW,
            )

        assert record.update_transitive_impacts == []

    def test_fresh_minimal_diff_pick_carries_accurate_age(self) -> None:
        """A minimal-diff (security) pick's age must be accurate so is_held_for_cooldown
        downstream can still hold it — a fresh pick is not exempt just because it fixes a CVE
        unless the record itself carries the CVE."""
        from ossiq.domain.common import CveDatabase
        from ossiq.domain.cve import CVE, Severity

        registry = make_registry({"pkg": [pv("1.1.0", published="2024-05-30T00:00:00Z")]})
        record = make_record("pkg", "1.0.0")
        record.cve = [
            CVE(
                id="CVE-1",
                cve_ids=("CVE-1",),
                source=CveDatabase.OSV,
                package_name="pkg",
                package_registry=ProjectPackagesRegistry.PYPI,
                summary="bad",
                severity=Severity.HIGH,
                affected_versions=("1.0.0",),
                published=None,
                link="https://example.test",
                epss=0.5,
            )
        ]
        plan = StrategyPlan(default=UpdateStrategy.SECURITY)

        apply_update_strategy(
            [record],
            registry,
            plan,
            versions_since={("pkg", "1.0.0"): list(registry.package_versions("pkg"))},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
        )

        assert record.recommended_version == "1.1.0"
        assert record.recommended_version_reason is not None
        assert record.recommended_version_reason.age_days == 2  # published 2 days before NOW


class TestApplyUpdateStrategyRejectedCandidates:
    """apply_update_strategy is the single writer of rejected_candidates for direct records."""

    def test_written_even_when_no_target_is_selected(self) -> None:
        registry = make_registry({"pkg": [pv("1.1.0")]})
        record = make_record("pkg", "1.0.0")

        def validator(_pkg: str, ver: str) -> DirectUpdateImpact:
            return DirectUpdateImpact(
                package_name="pkg",
                recommended_version=ver,
                transitive_impacts=[],
                is_actionable=False,
                fallback_version=None,
            )

        apply_update_strategy(
            [record],
            registry,
            STANDARD_PLAN,
            versions_since={("pkg", "1.0.0"): list(registry.package_versions("pkg"))},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
            validator=validator,
        )

        assert record.recommended_version is None
        assert len(record.rejected_candidates) == 1
        assert record.rejected_candidates[0].version == "1.1.0"

    def test_written_alongside_a_lower_recommendation(self) -> None:
        registry = make_registry({"pkg": [pv("1.1.0"), pv("2.0.0")]})
        record = make_record("pkg", "1.0.0")

        def validator(_pkg: str, ver: str) -> DirectUpdateImpact:
            accepted = ver == "1.1.0"
            return DirectUpdateImpact(
                package_name="pkg",
                recommended_version=ver,
                transitive_impacts=[],
                is_actionable=accepted,
                fallback_version=None,
            )

        apply_update_strategy(
            [record],
            registry,
            STANDARD_PLAN,
            versions_since={("pkg", "1.0.0"): list(registry.package_versions("pkg"))},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
            validator=validator,
        )

        assert record.recommended_version == "1.1.0"
        assert len(record.rejected_candidates) == 1
        assert record.rejected_candidates[0].version == "2.0.0"


class TestBuildCandidatesStructuralGates:
    def test_gate_rejects_flagged_release_when_a_clean_alternative_exists(self) -> None:
        registry = make_registry({"pkg": [pv("1.1.0"), pv("2.0.0")]})
        record = make_record("pkg", "1.0.0")

        def gate(candidate: PackageVersion) -> str | None:
            return "known break" if candidate.version == "2.0.0" else None

        built = build_candidates(
            record, list(registry.package_versions("pkg")), registry, now=NOW, structural_gates=(gate,)
        )

        assert [c.version for c in built.candidates] == ["1.1.0"]
        assert len(built.rejected) == 1
        assert built.rejected[0].version == "2.0.0"
        assert built.rejected[0].reason == "known break"

    def test_gate_never_rejects_every_installable_release(self) -> None:
        """A structural gate must never blank the whole ladder - see build_candidates's docstring
        and the "recommend the newest anyway" rule for a fully-flagged package."""
        registry = make_registry({"pkg": [pv("2.0.0")]})
        record = make_record("pkg", "1.0.0")

        def gate(_candidate: PackageVersion) -> str | None:
            return "known break"

        built = build_candidates(
            record, list(registry.package_versions("pkg")), registry, now=NOW, structural_gates=(gate,)
        )

        assert [c.version for c in built.candidates] == ["2.0.0"]
        assert built.rejected == ()


class TestApplyUpdateStrategyBreakingChange:
    """End-to-end: apply_update_strategy wires breaking_change_gate + module_system_label."""

    def test_esm_only_candidate_rejected_when_a_compatible_alternative_exists(self) -> None:
        registry = make_npm_registry(
            {
                "chalk": [
                    pv("4.1.2", module_system=ModuleSystem.CJS),
                    pv("4.2.0", module_system=ModuleSystem.CJS),
                    pv("5.0.0", module_system=ModuleSystem.ESM_ONLY),
                ]
            }
        )
        record = make_record("chalk", "4.1.2")

        apply_update_strategy(
            [record],
            registry,
            STANDARD_PLAN,
            versions_since={("chalk", "4.1.2"): list(registry.package_versions("chalk"))},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
            project_declares_esm=False,
        )

        assert record.recommended_version == "4.2.0"
        assert record.breaking_change is None
        assert [rc.version for rc in record.rejected_candidates] == ["5.0.0"]
        assert record.rejected_candidates[0].reason == "ESM-only from 5.0.0"

    def test_recommends_newest_anyway_when_every_candidate_is_esm_only(self) -> None:
        registry = make_npm_registry(
            {"chalk": [pv("4.1.2", module_system=ModuleSystem.CJS), pv("5.0.0", module_system=ModuleSystem.ESM_ONLY)]}
        )
        record = make_record("chalk", "4.1.2")

        apply_update_strategy(
            [record],
            registry,
            STANDARD_PLAN,
            versions_since={("chalk", "4.1.2"): list(registry.package_versions("chalk"))},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
            project_declares_esm=False,
        )

        assert record.recommended_version == "5.0.0"
        assert record.rejected_candidates == []
        assert record.breaking_change == "ESM-only from 5.0.0"
        assert record.recommended_module_system == ModuleSystem.ESM_ONLY

    def test_no_breaking_change_when_project_declares_esm(self) -> None:
        registry = make_npm_registry(
            {
                "chalk": [
                    pv("4.1.2", module_system=ModuleSystem.CJS),
                    pv("4.2.0", module_system=ModuleSystem.CJS),
                    pv("5.0.0", module_system=ModuleSystem.ESM_ONLY),
                ]
            }
        )
        record = make_record("chalk", "4.1.2")

        apply_update_strategy(
            [record],
            registry,
            STANDARD_PLAN,
            versions_since={("chalk", "4.1.2"): list(registry.package_versions("chalk"))},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
            project_declares_esm=True,
        )

        assert record.recommended_version == "5.0.0"
        assert record.rejected_candidates == []
        assert record.breaking_change is None
        assert record.recommended_module_system == ModuleSystem.ESM_ONLY


class TestApplyUpdateStrategyEngineMismatch:
    """End-to-end: apply_update_strategy wires engine_mismatch_gate + the 3 engine_* fields."""

    def test_engine_mismatch_candidate_rejected_when_a_compatible_alternative_exists(self) -> None:
        registry = make_npm_registry(
            {
                "pkg": [
                    pv("1.1.0", runtime_requirements={"node": ">=16.0.0"}),
                    pv("1.2.0", runtime_requirements={"node": ">=22.0.0"}),
                ]
            }
        )
        record = make_record("pkg", "1.0.0")

        apply_update_strategy(
            [record],
            registry,
            STANDARD_PLAN,
            versions_since={("pkg", "1.0.0"): list(registry.package_versions("pkg"))},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
            engine_context={"node": "18.0.0"},
            engine_context_source=EngineContextSource.DETECTED,
        )

        assert record.recommended_version == "1.1.0"
        assert record.engine_compatible is True
        assert record.engine_requirement == {"node": ">=16.0.0"}
        assert record.engine_context_source == EngineContextSource.DETECTED
        assert [rc.version for rc in record.rejected_candidates] == ["1.2.0"]
        assert record.rejected_candidates[0].reason == "requires node >=22.0.0, detected 18.0.0"

    def test_recommends_newest_anyway_when_every_candidate_mismatches(self) -> None:
        registry = make_npm_registry(
            {
                "pkg": [
                    pv("1.1.0", runtime_requirements={"node": ">=22.0.0"}),
                    pv("1.2.0", runtime_requirements={"node": ">=22.0.0"}),
                ]
            }
        )
        record = make_record("pkg", "1.0.0")

        apply_update_strategy(
            [record],
            registry,
            STANDARD_PLAN,
            versions_since={("pkg", "1.0.0"): list(registry.package_versions("pkg"))},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
            engine_context={"node": "18.0.0"},
            engine_context_source=EngineContextSource.DETECTED,
        )

        assert record.recommended_version == "1.2.0"
        assert record.rejected_candidates == []
        assert record.engine_compatible is False
        assert record.engine_requirement == {"node": ">=22.0.0"}

    def test_no_engine_fields_when_engine_context_empty(self) -> None:
        registry = make_npm_registry({"pkg": [pv("1.1.0", runtime_requirements={"node": ">=22.0.0"})]})
        record = make_record("pkg", "1.0.0")

        apply_update_strategy(
            [record],
            registry,
            STANDARD_PLAN,
            versions_since={("pkg", "1.0.0"): list(registry.package_versions("pkg"))},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
        )

        assert record.recommended_version == "1.1.0"
        assert record.engine_compatible is None
        assert record.engine_context_source == EngineContextSource.NONE
