"""Wires the pure `strategy/` selector onto `ScanRecord`s.

Modelled on `service.project.stability`: the pure decision lives in `strategy/`, this module is
the only place that turns a `ScanRecord` into the pure module's input (`facts_from_record`,
`build_candidates`) and writes its output back (`apply_update_strategy`).

Must run after `populate_stability` — `record.maintenance` and `record.triage` are populated
there, and `classify_motives` needs both to decide `END_OF_LIFE` correctly.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from functools import cmp_to_key

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import ConstraintType, RecommendationRung, RejectedCandidate
from ossiq.risk.maintenance import DEPRECATION_NONE
from ossiq.risk.triage import EPSS_NOISE_THRESHOLD
from ossiq.service.common.package_versions import PackageVersion
from ossiq.service.project.models import ScanRecord
from ossiq.service.update_impact import DirectUpdateImpact, simulate_single
from ossiq.solver.reason import RecommendationReason
from ossiq.solver.universe import is_published_before
from ossiq.solver.version_matchers import major_key, version_satisfies_constraint
from ossiq.strategy.motive import PackageFacts
from ossiq.strategy.overrides import StrategyPlan
from ossiq.strategy.targeting import Candidate, select_target
from ossiq.timeutil import age_days_from_iso

__all__ = ["PackageFacts", "StrategyPlan", "apply_update_strategy", "build_candidates", "facts_from_record"]

RUNG_ORDER = (RecommendationRung.IN_RANGE, RecommendationRung.IN_MAJOR, RecommendationRung.LATEST)


def facts_from_record(record: ScanRecord) -> PackageFacts:
    """Reduce a ScanRecord's evidence to the flags the pure selector needs."""
    return PackageFacts(
        package_name=record.package_name,
        installed_version=record.installed_version,
        cve_epss_scores=tuple(cve.epss for cve in record.cve),
        maintenance_state=record.maintenance.state if record.maintenance else None,
        is_registry_deprecated=record.is_installed_deprecated,
        deprecation_strength=record.deprecation.strength if record.deprecation else DEPRECATION_NONE,
    )


@dataclass(frozen=True)
class BuiltCandidates:
    """build_candidates's result: the admissible ladder plus what was held back and why."""

    candidates: tuple[Candidate, ...]
    rejected: tuple[RejectedCandidate, ...]


def classify_rung(
    version: str,
    record: ScanRecord,
    installed_major: tuple[int, int] | None,
    registry: AbstractPackageRegistryApi,
) -> RecommendationRung:
    if version_satisfies_constraint(version, record.version_constraint, registry.package_registry):
        return RecommendationRung.IN_RANGE
    if installed_major is not None and major_key(version, registry.package_registry) == installed_major:
        return RecommendationRung.IN_MAJOR
    return RecommendationRung.LATEST


def describe_rejection(impact: DirectUpdateImpact, transitive_by_name: dict[str, ScanRecord]) -> str:
    """Explain why a candidate release was rejected, naming the blocking transitive dep.

    Attributes the block to an OSS IQ-authored override only when constraint_info says so —
    ConstraintSource.is_ossiq_authored (item #14) is what makes that claim verifiable rather than
    a guess.
    """
    blockers = [ti for ti in impact.transitive_impacts if ti.has_conflict]
    if not blockers:
        return "blocked by a transitive dependency conflict"
    ti = blockers[0]
    blocking = transitive_by_name.get(ti.package_name)
    if blocking and blocking.constraint_info.type == ConstraintType.OVERRIDE:
        if blocking.constraint_info.is_ossiq_authored:
            prefix = f"{ti.package_name} is held by an OSS IQ-authored override"
        else:
            prefix = f"{ti.package_name} is held by an override in {blocking.constraint_info.source_file}"
    else:
        prefix = f"{ti.package_name} requires {ti.new_constraint}"
    return f"{prefix} ({ti.conflict_detail})" if ti.conflict_detail else prefix


def build_candidates(
    record: ScanRecord,
    releases: list[PackageVersion],
    registry: AbstractPackageRegistryApi,
    *,
    now: datetime | None = None,
    validator: Callable[[str, str], DirectUpdateImpact] | None = None,
    transitive_by_name: dict[str, ScanRecord] | None = None,
) -> BuiltCandidates:
    """Build the ascending candidate ladder for one record.

    Reuses the same three helpers `service.project.ladder.compute_version_ladder` uses
    (`is_published_before`, `version_satisfies_constraint`, `major_key`), so a candidate's rung
    can never disagree with the ladder rung on the same input. `has_cve` is true only for a
    qualifying CVE — one at/above EPSS_NOISE_THRESHOLD, or unscored — mirroring
    `strategy.motive.classify_motives`'s EXPLOITABLE_CVE rule.

    A release that clears the structural pre-filter but fails `validator` (i.e. it would break a
    transitive dependency) is not silently dropped: it's kept as a `RejectedCandidate`, capped at
    one per rung (the newest rejected release at that rung), so callers can explain a blank or
    lower `recommended_version` instead of staying silent about it.
    """
    qualifying_versions: set[str] = set()
    for cve in record.cve:
        if cve.epss is None or cve.epss >= EPSS_NOISE_THRESHOLD:
            qualifying_versions.update(cve.affected_versions)

    installed_major = major_key(record.installed_version, registry.package_registry)
    transitive_by_name = transitive_by_name or {}

    installable = [
        pv
        for pv in releases
        if not pv.is_yanked
        and not pv.is_unpublished
        and is_published_before(pv.published_date_iso, now)
        and major_key(pv.version, registry.package_registry) is not None
        and registry.compare_versions(pv.version, record.installed_version) > 0
    ]
    installable.sort(key=cmp_to_key(lambda a, b: registry.compare_versions(a.version, b.version)))

    candidates: list[Candidate] = []
    rejected_by_rung: dict[RecommendationRung, RejectedCandidate] = {}
    for pv in installable:
        rung = classify_rung(pv.version, record, installed_major, registry)
        if validator is None:
            candidates.append(Candidate(version=pv.version, rung=rung, has_cve=pv.version in qualifying_versions))
            continue

        impact = validator(record.package_name, pv.version)
        if impact.is_actionable:
            candidates.append(Candidate(version=pv.version, rung=rung, has_cve=pv.version in qualifying_versions))
        else:
            # Overwriting on each hit keeps the newest rejected release per rung, since
            # installable is sorted ascending.
            rejected_by_rung[rung] = RejectedCandidate(
                version=pv.version, reason=describe_rejection(impact, transitive_by_name)
            )

    rejected = tuple(rejected_by_rung[rung] for rung in RUNG_ORDER if rung in rejected_by_rung)
    return BuiltCandidates(candidates=tuple(candidates), rejected=rejected)


def apply_update_strategy(
    records: list[ScanRecord],
    registry: AbstractPackageRegistryApi,
    plan: StrategyPlan,
    *,
    versions_since: dict[tuple[str, str], list[PackageVersion]],
    transitive_by_name: dict[str, ScanRecord],
    installed_names: set[str],
    allow_prerelease: bool,
    now: datetime | None = None,
    validator: Callable[[str, str], DirectUpdateImpact] | None = None,
) -> None:
    """Run the selector for each record and write its verdict, replacing `apply_ladder_fallback`.

    The single writer of `recommended_version` past this point: whatever `select_target` returns
    is what the record carries afterward, whether that raises, lowers, or clears the pick the
    solver/`clamp_recommendations` left in place. `record.recommended_version` going into this
    function is `select_target`'s own candidate ladder, so a freshness tier's "newest in reach"
    can never end up lower than it — only a minimal-diff tier deliberately lowers it.

    Also the single writer of `rejected_candidates` for direct records: every release `validator`
    held back from the ladder is recorded here regardless of what `select_target` ends up
    choosing, so a blank or lowered `recommended_version` can always be explained.

    Re-simulates transitive impacts for any record whose target changed, since a stale
    `update_transitive_impacts` (computed against the old target) would otherwise mislead the
    writers; clears it when the re-simulation says the new target is not actionable.
    """
    for record in records:
        strategy = plan.for_package(record.package_name)
        facts = facts_from_record(record)
        releases = versions_since.get((record.package_name, record.installed_version), [])
        built = build_candidates(
            record, releases, registry, now=now, validator=validator, transitive_by_name=transitive_by_name
        )
        selection = select_target(facts, strategy, built.candidates)
        record.strategy_selection = selection
        record.rejected_candidates = list(built.rejected)

        previous_target = record.recommended_version
        if selection.target_version is None:
            record.recommended_version = None
            record.recommended_from_rung = None
            record.recommended_version_reason = None
            record.update_transitive_impacts = []
            continue

        record.recommended_version = selection.target_version
        record.recommended_from_rung = selection.rung
        if selection.target_version != previous_target:
            picked = next((pv for pv in releases if pv.version == selection.target_version), None)
            record.recommended_version_reason = RecommendationReason(
                selected_version=selection.target_version,
                constraint=record.version_constraint,
                hard_rejections=[],
                soft_rejections=[],
                lower_semver_alternatives=[],
                age_days=age_days_from_iso(picked.published_date_iso, now=now) if picked else None,
                is_latest=selection.target_version == record.latest_version,
            )
            impact = simulate_single(
                record.package_name,
                selection.target_version,
                transitive_by_name,
                registry,
                allow_prerelease,
                installed_names=installed_names,
                now=now,
                installed_version=record.installed_version,
            )
            record.update_transitive_impacts = impact.transitive_impacts if impact.is_actionable else []
