"""Tests for service/project/strategy.py — the impure wiring around the pure selector."""

import dataclasses
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from packaging.version import Version

from ossiq.domain.common import (
    ConstraintType,
    CveDatabase,
    EngineContext,
    EngineContextSource,
    ModuleSystem,
    PeerHold,
    ProjectPackagesRegistry,
    RecommendationRung,
    RejectionDetail,
)
from ossiq.domain.cve import CVE, AffectedRange, Severity
from ossiq.domain.project import ConstraintSource, IncomingEdge, InstalledCopy
from ossiq.domain.release_cutoff import ReleaseCutoff
from ossiq.domain.version import PackageVersion, PeerDependency, VersionsDifference
from ossiq.service.project.ladder import compute_version_ladder
from ossiq.service.project.models import ScanRecord
from ossiq.service.project.next_action import WAIT_FOR_COOLDOWN, next_action_label
from ossiq.service.project.strategy import (
    PeerConflict,
    apply_update_strategy,
    build_candidates,
    find_peer_conflict,
    peer_hold,
)
from ossiq.service.update import entry_from_record, is_held_for_widening
from ossiq.service.update_impact import DirectUpdateImpact, ImpactKind, TransitiveImpact, simulate_single
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
    peers: dict[str, PeerDependency] | None = None,
) -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url=f"https://example.com/{version}",
        declared_dependencies={},
        published_date_iso=published,
        module_system=module_system,
        runtime_requirements=runtime_requirements,
        declared_peer_dependencies=peers or {},
    )


def make_registry(versions_by_name: dict[str, list[PackageVersion]]) -> MagicMock:
    registry = MagicMock()
    registry.package_registry = ProjectPackagesRegistry.PYPI
    registry.one_copy_per_name = True
    registry.refuses_engine_mismatch = True
    registry.package_versions.side_effect = lambda name: versions_by_name.get(name, [])
    # Same source as the real adapter: a release's peers are whatever its PackageVersion declares.
    registry.package_version_peers.side_effect = lambda name, version: next(
        (p.declared_peer_dependencies for p in versions_by_name.get(name, []) if p.version == version), {}
    )
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
    registry.one_copy_per_name = False
    registry.refuses_engine_mismatch = False
    return registry


def make_record(
    name: str,
    installed: str,
    version_constraint: str | None = None,
    version_constraint_declared: str | None = None,
) -> ScanRecord:
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
        version_constraint_declared=version_constraint_declared,
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

    def test_rung_classified_against_the_declaration_not_the_lww_constraint(self) -> None:
        # version_constraint is a last-writer-wins accumulator across every parent that declares a
        # spec, so it can be some transitive parent's range rather than the root manifest's own.
        # The rung decides whether `ossiq apply` may write, so it has to follow the declaration -
        # otherwise the gate and the constraint shown to the user are different strings.
        registry = make_registry({"pkg": [pv("1.5.0"), pv("2.0.0")]})
        record = make_record("pkg", "1.0.0", version_constraint="<3.0.0", version_constraint_declared="<2.0.0")

        candidates = build_candidates(record, list(registry.package_versions("pkg")), registry, now=NOW).candidates
        rung_by_version = {c.version: c.rung for c in candidates}

        assert rung_by_version["1.5.0"] == RecommendationRung.IN_RANGE
        assert rung_by_version["2.0.0"] == RecommendationRung.LATEST

    def test_rung_falls_back_to_the_lww_constraint_when_nothing_is_declared(self) -> None:
        # Transitive-only records carry no declaration of their own; passing None through to the
        # matcher would admit every candidate as IN_RANGE and wipe out the widening hold.
        registry = make_registry({"pkg": [pv("1.5.0"), pv("2.0.0")]})
        record = make_record("pkg", "1.0.0", version_constraint="<2.0.0", version_constraint_declared=None)

        candidates = build_candidates(record, list(registry.package_versions("pkg")), registry, now=NOW).candidates
        rung_by_version = {c.version: c.rung for c in candidates}

        assert rung_by_version["1.5.0"] == RecommendationRung.IN_RANGE
        assert rung_by_version["2.0.0"] == RecommendationRung.LATEST

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
                    conflict=RejectionDetail("no version satisfies", (">=3.0.0", "==2.0.0")),
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
        assert built.rejected[0].reason == "blocked-dep is held by an OSS IQ-authored override"
        assert built.rejected[0].detail == RejectionDetail("no version satisfies", (">=3.0.0", "==2.0.0"))
        # The one-line form every non-tabular surface still prints, unchanged by the split.
        assert built.rejected[0].full_reason == (
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
                    conflict=None,
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
                    conflict=None,
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
                conflict=None,
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


class TestNestedCopiesAreNotRejected:
    """npm nests a further copy for an ordinary dependency, so only an override can reject a candidate."""

    @staticmethod
    def update(
        registry: MagicMock, record: ScanRecord, dependency: ScanRecord, requires: dict[tuple[str, str], dict[str, str]]
    ) -> None:
        registry.package_version_requires.side_effect = lambda name, version: requires.get((name, version), {})

        def validator(pkg: str, ver: str) -> DirectUpdateImpact:
            return simulate_single(
                pkg, ver, {dependency.package_name: dependency}, registry, now=NOW, installed_version="1.0.0"
            )

        apply_update_strategy(
            [record],
            registry,
            STANDARD_PLAN,
            versions_since={(record.package_name, "1.0.0"): list(registry.package_versions(record.package_name))},
            transitive_by_name={dependency.package_name: dependency},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
            validator=validator,
        )

    def test_a_candidate_needing_a_range_another_copy_satisfies_is_recommended(self) -> None:
        registry = make_npm_registry({"pkg": [pv("1.0.0"), pv("1.0.1")], "dep": [pv("10.2.5"), pv("9.0.9")]})
        record = make_record("pkg", "1.0.0", version_constraint="~1.0.0")
        dep = make_record("dep", "9.0.9")
        dep.installed_copies = [
            InstalledCopy("9.0.9", (IncomingEdge("other", "1.0.0", "^9.0.1"),), CONSTRAINT_SOURCE),
            InstalledCopy("10.2.5", (IncomingEdge("pkg", "1.0.0", "^10.2.4"),), CONSTRAINT_SOURCE),
        ]

        self.update(registry, record, dep, {("pkg", "1.0.1"): {"dep": "^10.2.4"}})

        assert record.recommended_version == "1.0.1"
        assert record.rejected_candidates == []

    def test_a_candidate_needing_a_version_no_copy_has_is_recommended_with_a_new_copy(self) -> None:
        registry = make_npm_registry({"pkg": [pv("1.0.0"), pv("1.0.1")], "dep": [pv("11.0.0"), pv("10.2.5")]})
        record = make_record("pkg", "1.0.0", version_constraint="~1.0.0")
        dep = make_record("dep", "10.2.5")

        self.update(registry, record, dep, {("pkg", "1.0.1"): {"dep": "^11.0.0"}})

        assert record.recommended_version == "1.0.1"
        assert record.rejected_candidates == []
        assert [(i.package_name, i.kind) for i in record.update_transitive_impacts] == [("dep", ImpactKind.NEW_COPY)]

    def test_an_override_the_user_wrote_still_rejects_and_is_named(self) -> None:
        registry = make_npm_registry({"pkg": [pv("1.0.0"), pv("1.0.1")], "dep": [pv("2.0.0"), pv("1.0.0")]})
        record = make_record("pkg", "1.0.0", version_constraint="~1.0.0")
        forced = ConstraintSource(
            type=ConstraintType.OVERRIDE, source_file="package.json", override_value="1.0.0", is_ossiq_authored=False
        )
        dep = make_record("dep", "1.0.0")
        dep.constraint_info = forced
        dep.installed_copies = [InstalledCopy("1.0.0", (), forced)]

        self.update(registry, record, dep, {("pkg", "1.0.1"): {"dep": "2.0.0"}})

        assert record.recommended_version is None
        assert [rc.version for rc in record.rejected_candidates] == ["1.0.1"]
        assert record.rejected_candidates[0].reason == "dep is held by an override in package.json"
        assert record.rejected_candidates[0].detail == RejectionDetail("forced to 1.0.0, wanted", ("2.0.0",))


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
    """End-to-end: apply_update_strategy wires module_system_gate + module_system_label."""

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
        assert record.compatibility.breaking_change is None
        assert [rc.version for rc in record.rejected_candidates] == ["5.0.0"]
        assert record.rejected_candidates[0].reason == "ESM-only from 5.0.0"

    def test_stays_put_when_every_candidate_is_esm_only_and_the_motive_is_drift(self) -> None:
        """chalk 4.1.2 is the top of its CommonJS line: drift alone is no reason to cross to ESM-only,
        so the target stays blank and the rejected row says what was refused and why."""
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

        assert record.recommended_version is None
        assert [(rc.version, rc.reason) for rc in record.rejected_candidates] == [("5.0.0", "ESM-only from 5.0.0")]
        assert record.compatibility.breaking_change is None

    @pytest.mark.parametrize("strategy", [UpdateStrategy.SECURITY, UpdateStrategy.STANDARD, UpdateStrategy.LATEST])
    def test_crosses_when_the_only_cve_fix_is_esm_only(self, strategy: UpdateStrategy) -> None:
        """Security beats build convenience: with no clean release left on the CommonJS line, the
        ESM-only fix is recommended at every tier - flagged, never hidden."""
        registry = make_npm_registry(
            {
                "uuid": [
                    pv("11.0.0", module_system=ModuleSystem.DUAL),
                    pv("11.0.5", module_system=ModuleSystem.DUAL),
                    pv("12.0.0", module_system=ModuleSystem.ESM_ONLY),
                    pv("13.0.0", module_system=ModuleSystem.ESM_ONLY),
                ]
            }
        )
        record = make_record("uuid", "11.0.0", version_constraint="11.0.0", version_constraint_declared="11.0.0")
        record.cve = [dataclasses.replace(UUID_ADVISORY, affected_versions=("11.0.0", "11.0.5"))]

        apply_update_strategy(
            [record],
            registry,
            StrategyPlan(default=strategy),
            versions_since={("uuid", "11.0.0"): list(registry.package_versions("uuid"))},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
            project_declares_esm=False,
        )

        expected = "12.0.0" if strategy == UpdateStrategy.SECURITY else "13.0.0"
        assert record.recommended_version == expected
        assert record.compatibility.breaking_change == f"ESM-only from {expected}"
        assert record.compatibility.recommended_module_system == ModuleSystem.ESM_ONLY

    def test_a_clean_release_on_the_module_line_beats_crossing_for_a_cve(self) -> None:
        registry = make_npm_registry({"uuid": UUID_RELEASES})
        record = make_record("uuid", "8.3.2", version_constraint="8.3.2", version_constraint_declared="8.3.2")
        record.cve = [UUID_ADVISORY]

        apply_update_strategy(
            [record],
            registry,
            StrategyPlan(default=UpdateStrategy.STANDARD),
            versions_since={("uuid", "8.3.2"): list(registry.package_versions("uuid"))},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
            project_declares_esm=False,
        )

        assert record.recommended_version == "11.1.1"
        assert record.compatibility.breaking_change is None

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
        assert record.compatibility.breaking_change is None
        assert record.compatibility.recommended_module_system == ModuleSystem.ESM_ONLY


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
            engine_context=EngineContext({"node": "18.0.0"}, EngineContextSource.DETECTED),
        )

        assert record.recommended_version == "1.1.0"
        assert record.compatibility.engine_compatible is True
        assert record.compatibility.engine_requirement == {"node": ">=16.0.0"}
        assert [rc.version for rc in record.rejected_candidates] == ["1.2.0"]
        assert record.rejected_candidates[0].reason == "requires node >=22.0.0, checked against 18.0.0"

    def test_a_release_outrunning_the_declared_python_floor_is_rejected(self) -> None:
        """The reported bug end to end: on a 3.13 interpreter this recommended the 3.12-only
        release, and uv then refused to resolve the project's own 3.11 split. The context here is
        what detect_engine_context now builds for such a project — the floor, not the interpreter."""
        registry = make_registry(
            {
                "sphinx": [
                    pv("8.2.3", runtime_requirements={"python": ">=3.11"}),
                    pv("9.1.0", runtime_requirements={"python": ">=3.12"}),
                ]
            }
        )
        record = make_record("sphinx", "8.1.0")

        apply_update_strategy(
            [record],
            registry,
            STANDARD_PLAN,
            versions_since={("sphinx", "8.1.0"): list(registry.package_versions("sphinx"))},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
            engine_context=EngineContext({"python": "3.11"}, EngineContextSource.DECLARED),
        )

        assert record.recommended_version == "8.2.3"
        assert record.compatibility.engine_compatible is True
        assert [rc.version for rc in record.rejected_candidates] == ["9.1.0"]
        assert record.rejected_candidates[0].reason == "requires python >=3.12, checked against 3.11"

    def test_a_python_floor_mismatch_is_not_waived_when_it_empties_the_ladder(self) -> None:
        """The sphinx case exactly: 9.0.4 installed, 9.1.0 the only release above it and 3.12-only.
        Waiving the gate here recommended an update `uv` then refused to resolve, so on PyPI the
        gate binds — no recommendation beats one that cannot be applied."""
        registry = make_registry({"sphinx": [pv("9.1.0", runtime_requirements={"python": ">=3.12"})]})
        record = make_record("sphinx", "9.0.4")

        apply_update_strategy(
            [record],
            registry,
            STANDARD_PLAN,
            versions_since={("sphinx", "9.0.4"): list(registry.package_versions("sphinx"))},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
            engine_context=EngineContext({"python": "3.11"}, EngineContextSource.DECLARED),
        )

        assert record.recommended_version is None
        assert [rc.version for rc in record.rejected_candidates] == ["9.1.0"]
        assert record.rejected_candidates[0].reason == "requires python >=3.12, checked against 3.11"

    def test_an_npm_engine_mismatch_is_still_waived_when_it_empties_the_ladder(self) -> None:
        """npm installs an engines mismatch with a warning rather than refusing it, so the
        best-available-answer rule still applies there."""
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
            engine_context=EngineContext({"node": "18.0.0"}, EngineContextSource.DETECTED),
        )

        assert record.recommended_version == "1.1.0"
        assert record.compatibility.engine_compatible is False

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
            engine_context=EngineContext({"node": "18.0.0"}, EngineContextSource.DETECTED),
        )

        assert record.recommended_version == "1.2.0"
        assert record.rejected_candidates == []
        assert record.compatibility.engine_compatible is False
        assert record.compatibility.engine_requirement == {"node": ">=22.0.0"}

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
        # The release's own requirement is still recorded; only the verdict is unknown, because
        # there is nothing to compare it against.
        assert record.compatibility.engine_requirement == {"node": ">=22.0.0"}
        assert record.compatibility.engine_compatible is None


class TestApplyUpdateStrategyCooldown:
    """The cooldown reaches `recommended_version` here, not only at `plan`/`apply` time.

    The reported defect: `status` recommended a 5-day-old release with "Update Immediately" while
    `apply` refused it as too fresh — and an aged release sat in between, recommended by nobody.
    """

    def test_prefers_the_newest_aged_release_over_a_fresher_one(self) -> None:
        # common-expression-language, the reported case: 0.9.0 is 12 days old, 0.10.0 is 5.
        registry = make_registry(
            {
                "cel": [
                    pv("0.9.0", published="2024-05-20T00:00:00Z"),
                    pv("0.10.0", published="2024-05-27T00:00:00Z"),
                ]
            }
        )
        record = make_record("cel", "0.8.0")

        apply_update_strategy(
            [record],
            registry,
            STANDARD_PLAN,
            versions_since={("cel", "0.8.0"): list(registry.package_versions("cel"))},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
            cooldown_period=7,
        )

        assert record.recommended_version == "0.9.0"
        assert record.recommended_version_reason is not None
        assert record.recommended_version_reason.age_days == 12
        assert record.strategy_selection is not None
        assert record.strategy_selection.cooldown_hold is None

    def test_no_recommendation_when_every_reachable_release_is_fresh(self) -> None:
        registry = make_registry({"cel": [pv("0.10.0", published="2024-05-27T00:00:00Z")]})
        record = make_record("cel", "0.8.0")

        apply_update_strategy(
            [record],
            registry,
            STANDARD_PLAN,
            versions_since={("cel", "0.8.0"): list(registry.package_versions("cel"))},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
            cooldown_period=7,
        )

        assert record.recommended_version is None
        assert record.recommended_from_rung is None
        assert record.strategy_selection is not None
        hold = record.strategy_selection.cooldown_hold
        assert hold is not None
        assert (hold.version, hold.age_days, hold.cooldown_period) == ("0.10.0", 5, 7)

    def test_default_cooldown_period_of_zero_changes_nothing(self) -> None:
        registry = make_registry(
            {
                "cel": [
                    pv("0.9.0", published="2024-05-20T00:00:00Z"),
                    pv("0.10.0", published="2024-05-27T00:00:00Z"),
                ]
            }
        )
        record = make_record("cel", "0.8.0")

        apply_update_strategy(
            [record],
            registry,
            STANDARD_PLAN,
            versions_since={("cel", "0.8.0"): list(registry.package_versions("cel"))},
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
        )

        assert record.recommended_version == "0.10.0"

    def test_a_reason_blanked_by_clamp_recommendations_is_rebuilt(self) -> None:
        # clamp_recommendations blanks the reason for the pick it re-fitted, so an unchanged target
        # used to reach `plan` with no age_days at all - no cooldown hold, and "—" in the Age column.
        registry = make_registry({"pkg": [pv("1.1.0", published="2024-05-20T00:00:00Z")]})
        record = make_record("pkg", "1.0.0")
        record.recommended_version = "1.1.0"
        record.recommended_version_reason = None

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
        assert record.recommended_version_reason is not None
        assert record.recommended_version_reason.age_days == 12


# uv's `exclude-newer = "14 days"`, resolved at NOW.
UV_CUTOFF = ReleaseCutoff("uv exclude-newer", default=datetime(2024, 5, 18, tzinfo=UTC))


class TestApplyUpdateStrategyReleaseCutoff:
    """The package manager's own cutoff binds the selector, and the hold names the package manager."""

    def run(self, record: ScanRecord, registry: MagicMock, **kwargs) -> None:
        apply_update_strategy(
            [record],
            registry,
            STANDARD_PLAN,
            versions_since={
                (record.package_name, record.installed_version): list(registry.package_versions(record.package_name))
            },
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
            release_cutoff=UV_CUTOFF,
            **kwargs,
        )

    def test_prefers_the_newest_release_the_package_manager_accepts(self) -> None:
        registry = make_registry(
            {
                "cel": [
                    pv("0.9.0", published="2024-05-10T00:00:00Z"),
                    pv("0.10.0", published="2024-05-20T00:00:00Z"),
                ]
            }
        )
        record = make_record("cel", "0.8.0")

        self.run(record, registry, cooldown_period=7)

        # 0.10.0 is 12 days old - past OSS IQ's 7-day cooldown, but not uv's 14 days.
        assert record.recommended_version == "0.9.0"

    def test_hold_is_attributed_to_the_package_manager(self) -> None:
        registry = make_registry({"cel": [pv("0.10.0", published="2024-05-20T00:00:00Z")]})
        record = make_record("cel", "0.8.0")

        self.run(record, registry, cooldown_period=7)

        assert record.recommended_version is None
        assert record.strategy_selection is not None
        hold = record.strategy_selection.cooldown_hold
        assert hold is not None
        assert (hold.version, hold.enforced_by, hold.cutoff) == ("0.10.0", "uv exclude-newer", UV_CUTOFF.default)
        assert next_action_label(record) == WAIT_FOR_COOLDOWN

    def test_a_cve_does_not_lift_the_package_manager_hold(self) -> None:
        registry = make_registry({"cel": [pv("0.10.0", published="2024-05-20T00:00:00Z")]})
        record = make_record("cel", "0.8.0")
        record.cve = [
            CVE(
                id="GHSA-cel",
                cve_ids=("GHSA-cel",),
                source=CveDatabase.OSV,
                package_name="cel",
                package_registry=ProjectPackagesRegistry.PYPI,
                summary="cel < 0.10.0",
                severity=Severity.HIGH,
                affected_versions=("0.8.0",),
                published=None,
                link="https://osv.dev/vulnerability/GHSA-cel",
            )
        ]

        self.run(record, registry, cooldown_period=7)

        assert record.recommended_version is None
        assert record.strategy_selection is not None
        assert record.strategy_selection.cooldown_hold is not None
        assert record.strategy_selection.cooldown_hold.enforced_by == "uv exclude-newer"

    def test_an_installed_version_past_the_cutoff_is_left_alone(self) -> None:
        """uv keeps a locked release past its cutoff, so there is nothing to recommend - or hold."""
        registry = make_registry({"cel": [pv("0.10.0", published="2024-05-20T00:00:00Z")]})
        record = make_record("cel", "0.10.0")

        self.run(record, registry)

        assert record.recommended_version is None
        assert record.strategy_selection is not None
        assert record.strategy_selection.cooldown_hold is None


# Release shapes from the npm registry as of 2026-09-08 (see PLAN.md, Milestone 1 findings). chalk
# 5+/6 export only a default, so `require("chalk").bold` fails on every Node; uuid 12+ exports
# named functions, so require() works on Node >= 22.12 and fails below it.
CHALK_RELEASES = [
    pv("4.0.0", module_system=ModuleSystem.CJS),
    pv("4.1.2", module_system=ModuleSystem.CJS),
    pv("5.0.0", module_system=ModuleSystem.ESM_ONLY),
    pv("5.6.2", module_system=ModuleSystem.ESM_ONLY),
    pv("6.0.0", module_system=ModuleSystem.ESM_ONLY),
]
UUID_RELEASES = [
    pv("8.3.2", module_system=ModuleSystem.DUAL),
    pv("9.0.1", module_system=ModuleSystem.DUAL),
    pv("10.0.0", module_system=ModuleSystem.DUAL),
    pv("11.0.5", module_system=ModuleSystem.DUAL),
    pv("11.1.1", module_system=ModuleSystem.DUAL),
    pv("12.0.0", module_system=ModuleSystem.ESM_ONLY),
    pv("13.0.2", module_system=ModuleSystem.ESM_ONLY),
    pv("14.0.2", module_system=ModuleSystem.ESM_ONLY),
]
UUID_ADVISORY = CVE(
    id="GHSA-w5hq-g745-h8pq",
    cve_ids=("GHSA-w5hq-g745-h8pq",),
    source=CveDatabase.OSV,
    package_name="uuid",
    package_registry=ProjectPackagesRegistry.NPM,
    summary="uuid < 11.1.1",
    severity=Severity.HIGH,
    affected_versions=("8.3.2", "9.0.1", "10.0.0", "11.0.5"),
    published=None,
    link="https://osv.dev/vulnerability/GHSA-w5hq-g745-h8pq",
)
BENCH_NODE = "26.8.1"


def recommend_for_cjs_project(
    name: str,
    releases: list[PackageVersion],
    installed: str,
    *,
    node_version: str | None,
    strategy: UpdateStrategy = UpdateStrategy.STANDARD,
    cves: list[CVE] | None = None,
) -> ScanRecord:
    """Run apply_update_strategy for one exact-pinned dependency of a CommonJS npm project."""
    registry = make_npm_registry({name: releases})
    record = make_record(name, installed, version_constraint=installed, version_constraint_declared=installed)
    record.cve = list(cves or [])
    engine_context = (
        EngineContext({"node": node_version}, EngineContextSource.DETECTED) if node_version else EngineContext()
    )
    apply_update_strategy(
        [record],
        registry,
        StrategyPlan(default=strategy),
        versions_since={(name, installed): [r for r in releases if Version(r.version) >= Version(installed)]},
        transitive_by_name={},
        installed_names=set(),
        allow_prerelease=False,
        now=NOW,
        project_declares_esm=False,
        engine_context=engine_context,
    )
    return record


class TestModuleSystemEscalationD1:
    """D1 reproduction: a CommonJS project is recommended an ESM-only release."""

    def test_uuid_recommendation_does_not_depend_on_the_probed_node(self) -> None:
        targets = {
            node: recommend_for_cjs_project(
                "uuid", UUID_RELEASES, "8.3.2", node_version=node, cves=[UUID_ADVISORY]
            ).recommended_version
            for node in (None, "18.20.8", "20.18.3", "22.12.0", BENCH_NODE)
        }

        assert set(targets.values()) == {"11.1.1"}, targets

    def test_latest_strategy_crosses_to_esm_only_on_a_require_esm_node(self) -> None:
        """The user's call (26 Sep 2026): `latest` may cross when the runtime can require() ESM,
        flagged with breaking_change so `apply` asks, and qualified by the named-exports note."""
        record = recommend_for_cjs_project(
            "chalk", CHALK_RELEASES, "4.0.0", node_version=BENCH_NODE, strategy=UpdateStrategy.LATEST
        )

        assert record.recommended_version == "6.0.0"
        assert record.compatibility.recommended_module_system == ModuleSystem.ESM_ONLY
        assert record.compatibility.breaking_change == "ESM-only from 6.0.0"

    @pytest.mark.parametrize("node_version", [None, "18.20.8", "20.18.3"])
    def test_latest_strategy_keeps_chalk_on_the_cjs_line_without_require_esm(self, node_version: str | None) -> None:
        record = recommend_for_cjs_project(
            "chalk", CHALK_RELEASES, "4.0.0", node_version=node_version, strategy=UpdateStrategy.LATEST
        )

        assert record.recommended_version == "4.1.2"
        assert record.compatibility.recommended_module_system == ModuleSystem.CJS

    @pytest.mark.parametrize("node_version", [None, "20.18.3", BENCH_NODE])
    def test_higher_tiers_never_recommend_lower(self, node_version: str | None) -> None:
        """The pyramid invariant (targeting rule 6) survives the module-system gate."""
        order = [UpdateStrategy.SECURITY, UpdateStrategy.DEPRECATION, UpdateStrategy.STANDARD, UpdateStrategy.LATEST]
        for name, releases, installed, cves in (
            ("chalk", CHALK_RELEASES, "4.0.0", None),
            ("uuid", UUID_RELEASES, "8.3.2", [UUID_ADVISORY]),
        ):
            targets = [
                recommend_for_cjs_project(
                    name, releases, installed, node_version=node_version, strategy=tier, cves=cves
                ).recommended_version
                for tier in order
            ]
            moved = [Version(t) for t in targets if t is not None]
            assert moved == sorted(moved), (name, node_version, targets)

    def test_latest_strategy_without_node_ignores_the_unpublished_tombstone(self) -> None:
        releases = [*CHALK_RELEASES, dataclasses.replace(pv("5.6.1"), is_unpublished=True)]

        record = recommend_for_cjs_project(
            "chalk", releases, "4.0.0", node_version=None, strategy=UpdateStrategy.LATEST
        )

        assert record.recommended_version == "4.1.2"

    def test_standard_strategy_keeps_chalk_on_the_cjs_line(self) -> None:
        # The benchmark's one "correct" run: same Node, default strategy. Passing today - the
        # flip between s1 and s3 is the strategy argument, not iteration order.
        record = recommend_for_cjs_project("chalk", CHALK_RELEASES, "4.0.0", node_version=BENCH_NODE)

        assert record.recommended_version == "4.1.2"

    @pytest.mark.parametrize("strategy", [UpdateStrategy.STANDARD, UpdateStrategy.LATEST])
    def test_same_input_gives_the_same_answer_every_time(self, strategy: UpdateStrategy) -> None:
        def snapshot() -> tuple[object, ...]:
            chalk = recommend_for_cjs_project(
                "chalk", CHALK_RELEASES, "4.0.0", node_version=BENCH_NODE, strategy=strategy
            )
            uuid = recommend_for_cjs_project(
                "uuid", UUID_RELEASES, "8.3.2", node_version=BENCH_NODE, strategy=strategy, cves=[UUID_ADVISORY]
            )
            return tuple(
                (
                    record.recommended_version,
                    record.recommended_from_rung,
                    record.compatibility.recommended_module_system,
                    tuple(record.rejected_candidates),
                    record.strategy_selection,
                )
                for record in (chalk, uuid)
            )

        first = snapshot()
        assert all(snapshot() == first for _ in range(20))


# npm advisories as OSV actually publishes them: ranges only, `affected_versions` empty. The
# fixtures above enumerate versions, which no npm record does - and is why D7 went unnoticed.
QS_RELEASES = [pv(v, module_system=ModuleSystem.CJS) for v in ("6.10.1", "6.10.2", "6.10.3", "6.11.0")]
QS_ADVISORY = CVE(
    id="GHSA-hrpp-h998-j3pp",
    cve_ids=("CVE-2022-24999",),
    source=CveDatabase.OSV,
    package_name="qs",
    package_registry=ProjectPackagesRegistry.NPM,
    summary="qs vulnerable to Prototype Pollution",
    severity=Severity.HIGH,
    affected_versions=(),
    published=None,
    link="https://osv.dev/GHSA-hrpp-h998-j3pp",
    epss=0.1506,
    affected_ranges=(AffectedRange(introduced="6.10.0", fixed="6.10.3"), AffectedRange(fixed="6.2.4")),
)
UUID_RANGE_ADVISORY = dataclasses.replace(
    UUID_ADVISORY,
    affected_versions=(),
    epss=0.5,
    affected_ranges=(
        AffectedRange(fixed="11.1.1"),
        AffectedRange(introduced="12.0.0", fixed="12.0.1"),
        AffectedRange(introduced="13.0.0", fixed="13.0.1"),
    ),
)


class TestNpmAdvisoryRangesD7:
    """D7 reproduction: an npm advisory without enumerated versions read every release as clean."""

    def test_candidate_inside_an_advisory_range_carries_the_cve(self) -> None:
        registry = make_npm_registry({"qs": QS_RELEASES})
        record = make_record("qs", "6.10.1")
        record.cve = [QS_ADVISORY]

        candidates = build_candidates(record, QS_RELEASES, registry, now=NOW).candidates
        by_version = {c.version: c.has_cve for c in candidates}

        assert by_version == {"6.10.2": True, "6.10.3": False, "6.11.0": False}

    def test_security_tier_steps_over_a_release_still_inside_the_range(self) -> None:
        record = recommend_for_cjs_project(
            "qs", QS_RELEASES, "6.10.1", node_version=None, strategy=UpdateStrategy.SECURITY, cves=[QS_ADVISORY]
        )

        assert record.recommended_version == "6.10.3"

    def test_security_tier_moves_uuid_to_the_first_release_outside_every_range(self) -> None:
        record = recommend_for_cjs_project(
            "uuid",
            UUID_RELEASES,
            "8.3.2",
            node_version=None,
            strategy=UpdateStrategy.SECURITY,
            cves=[UUID_RANGE_ADVISORY],
        )

        assert record.recommended_version == "11.1.1"

    def test_that_fix_past_the_declared_range_is_written_not_held_for_widening(self) -> None:
        """uuid is pinned to 8.3.2, so 11.1.1 widens the range: the CVE motive is the authorization."""
        record = recommend_for_cjs_project(
            "uuid",
            UUID_RELEASES,
            "8.3.2",
            node_version=None,
            strategy=UpdateStrategy.SECURITY,
            cves=[UUID_RANGE_ADVISORY],
        )

        assert record.strategy_selection is not None
        assert record.strategy_selection.widening_authorized is True
        entry = entry_from_record(record, is_direct=True)
        assert entry.widens_constraint is True
        assert not is_held_for_widening(entry, UpdateStrategy.SECURITY)


class TestPeerReconciliation:
    """Each pick is made alone, so a last pass sends back any that peer-require another pick out."""

    @staticmethod
    def apply(records: list[ScanRecord], registry: MagicMock, **kwargs) -> None:
        apply_update_strategy(
            records,
            registry,
            STANDARD_PLAN,
            versions_since={
                (r.package_name, r.installed_version): list(registry.package_versions(r.package_name)) for r in records
            },
            transitive_by_name={},
            installed_names=set(),
            allow_prerelease=False,
            now=NOW,
            **kwargs,
        )

    @staticmethod
    def lockstep(*, renderer_follows: bool) -> tuple[MagicMock, ScanRecord, ScanRecord]:
        """vue, and a direct @vue/server-renderer that peer-pins vue exactly."""
        renderer = [pv("3.5.43", peers={"vue": PeerDependency("3.5.43")})]
        if renderer_follows:
            renderer.append(pv("3.5.44", peers={"vue": PeerDependency("3.5.44")}))
        registry = make_npm_registry({"vue": [pv("3.5.43"), pv("3.5.44")], "@vue/server-renderer": renderer})
        return registry, make_record("vue", "3.5.43"), make_record("@vue/server-renderer", "3.5.43")

    def test_a_lockstep_pair_that_can_follow_moves_together(self) -> None:
        registry, vue, renderer = self.lockstep(renderer_follows=True)

        self.apply([vue, renderer], registry)

        assert (vue.recommended_version, renderer.recommended_version) == ("3.5.44", "3.5.44")

    def test_a_pair_where_one_half_cannot_follow_does_not_move_at_all(self) -> None:
        """Never a mismatched pair: vue stays when no server-renderer exists for 3.5.44."""
        registry, vue, renderer = self.lockstep(renderer_follows=False)

        self.apply([vue, renderer], registry)

        assert vue.recommended_version is None
        assert renderer.recommended_version is None

    def test_the_refusal_is_recorded_so_the_plan_can_say_why(self) -> None:
        registry, vue, renderer = self.lockstep(renderer_follows=False)

        self.apply([vue, renderer], registry)

        (refused,) = vue.rejected_candidates
        assert refused.version == "3.5.44"
        assert refused.reason == "@vue/server-renderer peer-requires vue"
        assert refused.detail == RejectionDetail("3.5.44 violates", ("3.5.43",))
        assert refused.held_by_peer == PeerHold("vue", "3.5.44", "@vue/server-renderer", "3.5.43")

    def test_a_refused_pick_falls_back_to_the_newest_release_that_fits(self) -> None:
        registry = make_npm_registry(
            {
                "vue": [pv("3.5.43"), pv("3.5.44"), pv("3.5.45")],
                "@vue/server-renderer": [
                    pv("3.5.43", peers={"vue": PeerDependency("3.5.43")}),
                    pv("3.5.44", peers={"vue": PeerDependency("3.5.44")}),
                ],
            }
        )
        vue, renderer = make_record("vue", "3.5.43"), make_record("@vue/server-renderer", "3.5.43")

        self.apply([vue, renderer], registry)

        assert (vue.recommended_version, renderer.recommended_version) == ("3.5.44", "3.5.44")

    def test_a_package_the_plan_never_moves_is_held_in_place(self) -> None:
        """An ignored package is not a record here, but its installed peers still bind."""
        registry = make_npm_registry(
            {"plugin": [pv("1.0.0"), pv("2.0.0", peers={"host": PeerDependency("^2")})], "host": [pv("1.0.0")]}
        )
        plugin = make_record("plugin", "1.0.0")

        self.apply([plugin], registry, fixed_versions={"host": "1.0.0"})

        assert plugin.recommended_version is None
        (refused,) = plugin.rejected_candidates
        assert refused.reason == "plugin 2.0.0 peer-requires host"
        assert refused.detail == RejectionDetail("held at 1.0.0, wanted", ("^2",))
        assert refused.held_by_peer is None

    def test_a_range_the_installed_pair_already_missed_does_not_block_a_bump(self) -> None:
        registry = make_npm_registry(
            {
                "plugin": [
                    pv("1.0.0", peers={"host": PeerDependency("^1")}),
                    pv("1.1.0", peers={"host": PeerDependency("^1")}),
                ]
            }
        )
        plugin = make_record("plugin", "1.0.0")

        self.apply([plugin], registry, fixed_versions={"host": "2.0.0"})

        assert plugin.recommended_version == "1.1.0"

    def test_a_pick_is_held_to_where_a_transitive_package_ends_up(self):
        """The transitive pass moved host to 2.0.0; plugin 1.1.0 still peer-requires ^1, so it can't follow."""
        registry = make_npm_registry(
            {
                "plugin": [
                    pv("1.0.0", peers={"host": PeerDependency("^1 || ^2")}),
                    pv("1.1.0", peers={"host": PeerDependency("^1")}),
                ]
            }
        )
        plugin = make_record("plugin", "1.0.0")

        self.apply([plugin], registry, fixed_versions={"host": "2.0.0"}, fixed_installed={"host": "1.0.0"})

        assert plugin.recommended_version is None
        (refused,) = plugin.rejected_candidates
        assert refused.detail == RejectionDetail("held at 2.0.0, wanted", ("^1",))

    def test_a_transitive_package_that_peer_requires_the_pick_holds_it(self):
        registry = make_npm_registry(
            {
                "vue": [pv("3.5.43"), pv("3.5.44")],
                "@vue/server-renderer": [pv("3.5.43", peers={"vue": PeerDependency("3.5.43")})],
            }
        )
        vue = make_record("vue", "3.5.43")

        self.apply([vue], registry, fixed_versions={"@vue/server-renderer": "3.5.43"})

        assert vue.recommended_version is None
        assert vue.rejected_candidates[0].held_by_peer == PeerHold("vue", "3.5.44", "@vue/server-renderer", "3.5.43")

    def test_a_python_project_is_untouched(self) -> None:
        registry = make_registry({"a": [pv("1.0.0"), pv("1.1.0")], "b": [pv("2.0.0"), pv("2.1.0")]})
        a, b = make_record("a", "1.0.0"), make_record("b", "2.0.0")

        self.apply([a, b], registry)

        assert (a.recommended_version, b.recommended_version) == ("1.1.0", "2.1.0")
        assert a.rejected_candidates == [] and b.rejected_candidates == []


class TestFindPeerConflict:
    @staticmethod
    def registry() -> MagicMock:
        return make_npm_registry(
            {
                "plugin": [
                    pv("1.0.0", peers={"host": PeerDependency("^1")}),
                    pv("2.0.0", peers={"host": PeerDependency("^2"), "absent": PeerDependency("^1")}),
                    pv("3.0.0", peers={"host": PeerDependency("")}),
                ],
                "host": [pv("1.0.0"), pv("2.0.0")],
            }
        )

    def test_the_picks_own_peer_against_where_the_other_ends_up(self) -> None:
        conflict = find_peer_conflict(
            "plugin",
            "2.0.0",
            {"plugin": "2.0.0", "host": "1.0.0"},
            {"plugin": "1.0.0", "host": "1.0.0"},
            self.registry(),
        )

        assert conflict == PeerConflict(requirer="plugin", package="host", spec="^2", held_at="1.0.0")

    def test_the_others_peer_on_the_pick(self) -> None:
        conflict = find_peer_conflict(
            "host", "2.0.0", {"plugin": "1.0.0", "host": "2.0.0"}, {"plugin": "1.0.0", "host": "1.0.0"}, self.registry()
        )

        assert conflict == PeerConflict(requirer="plugin", package="host", spec="^1", held_at="2.0.0")

    def test_a_peer_on_a_package_outside_the_plan_binds_nothing(self) -> None:
        conflict = find_peer_conflict(
            "plugin",
            "2.0.0",
            {"plugin": "2.0.0", "host": "2.0.0"},
            {"plugin": "1.0.0", "host": "2.0.0"},
            self.registry(),
        )

        assert conflict is None

    def test_a_peer_with_no_range_binds_nothing(self) -> None:
        conflict = find_peer_conflict(
            "plugin",
            "3.0.0",
            {"plugin": "3.0.0", "host": "1.0.0"},
            {"plugin": "1.0.0", "host": "1.0.0"},
            self.registry(),
        )

        assert conflict is None


class TestPeerHold:
    @staticmethod
    def impact(*blockers: TransitiveImpact) -> DirectUpdateImpact:
        return DirectUpdateImpact("typescript", "7.0.2", list(blockers), is_actionable=False, fallback_version=None)

    @staticmethod
    def blocker(requirer: str, spec: str, kind: ImpactKind = ImpactKind.PEER) -> TransitiveImpact:
        return TransitiveImpact(
            package_name=requirer,
            current_version="8.0.0",
            projected_version=None,
            new_constraint=spec,
            driven_by="typescript",
            has_conflict=True,
            kind=kind,
        )

    def test_names_the_first_requirer_and_counts_the_rest(self) -> None:
        hold = peer_hold(self.impact(self.blocker("utils", "<6.1.0"), self.blocker("parser", "<6.1.0")))

        assert hold == PeerHold("typescript", "7.0.2", "utils", "<6.1.0", others=1)

    def test_anything_that_is_not_a_peer_is_not_a_peer_hold(self) -> None:
        assert peer_hold(self.impact(self.blocker("x", "^1", ImpactKind.UPGRADE))) is None
        assert peer_hold(self.impact()) is None
