"""Wires the pure `strategy/` selector onto `ScanRecord`s.

Modelled on `service.project.stability`: the pure decision lives in `strategy/`, this module is
the only place that turns a `ScanRecord` into the pure module's input (`facts_from_record`,
`build_candidates`) and writes its output back (`apply_update_strategy`).

Must run after `populate_stability` — `record.maintenance` and `record.triage` are populated
there, and `classify_motives` needs both to decide `END_OF_LIFE` correctly.
"""

from collections.abc import Callable
from datetime import datetime
from functools import cmp_to_key

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import RecommendationRung
from ossiq.risk.maintenance import DEPRECATION_NONE
from ossiq.risk.triage import EPSS_NOISE_THRESHOLD
from ossiq.service.common.package_versions import PackageVersion
from ossiq.service.project.models import ScanRecord
from ossiq.service.update_impact import simulate_single
from ossiq.solver.reason import RecommendationReason
from ossiq.solver.universe import is_published_before
from ossiq.solver.version_matchers import major_key, version_satisfies_constraint
from ossiq.strategy.motive import PackageFacts
from ossiq.strategy.overrides import StrategyPlan
from ossiq.strategy.targeting import Candidate, select_target
from ossiq.timeutil import age_days_from_iso

__all__ = ["PackageFacts", "StrategyPlan", "apply_update_strategy", "build_candidates", "facts_from_record"]


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


def build_candidates(
    record: ScanRecord,
    releases: list[PackageVersion],
    registry: AbstractPackageRegistryApi,
    *,
    now: datetime | None = None,
    validator: Callable[[str, str], bool] | None = None,
) -> tuple[Candidate, ...]:
    """Build the ascending candidate ladder for one record.

    Reuses the same three helpers `service.project.ladder.compute_version_ladder` uses
    (`is_published_before`, `version_satisfies_constraint`, `major_key`), so a candidate's rung
    can never disagree with the ladder rung on the same input. `has_cve` is true only for a
    qualifying CVE — one at/above EPSS_NOISE_THRESHOLD, or unscored — mirroring
    `strategy.motive.classify_motives`'s EXPLOITABLE_CVE rule.
    """
    qualifying_versions: set[str] = set()
    for cve in record.cve:
        if cve.epss is None or cve.epss >= EPSS_NOISE_THRESHOLD:
            qualifying_versions.update(cve.affected_versions)

    installed_major = major_key(record.installed_version, registry.package_registry)

    installable = [
        pv
        for pv in releases
        if not pv.is_yanked
        and not pv.is_unpublished
        and is_published_before(pv.published_date_iso, now)
        and major_key(pv.version, registry.package_registry) is not None
        and registry.compare_versions(pv.version, record.installed_version) > 0
        and (validator is None or validator(record.package_name, pv.version))
    ]
    installable.sort(key=cmp_to_key(lambda a, b: registry.compare_versions(a.version, b.version)))

    candidates: list[Candidate] = []
    for pv in installable:
        if version_satisfies_constraint(pv.version, record.version_constraint, registry.package_registry):
            rung = RecommendationRung.IN_RANGE
        elif installed_major is not None and major_key(pv.version, registry.package_registry) == installed_major:
            rung = RecommendationRung.IN_MAJOR
        else:
            rung = RecommendationRung.LATEST
        candidates.append(Candidate(version=pv.version, rung=rung, has_cve=pv.version in qualifying_versions))

    return tuple(candidates)


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
    validator: Callable[[str, str], bool] | None = None,
) -> None:
    """Run the selector for each record and write its verdict, replacing `apply_ladder_fallback`.

    The single writer of `recommended_version` past this point: whatever `select_target` returns
    is what the record carries afterward, whether that raises, lowers, or clears the pick the
    solver/`clamp_recommendations` left in place. `record.recommended_version` going into this
    function is `select_target`'s own candidate ladder, so a freshness tier's "newest in reach"
    can never end up lower than it — only a minimal-diff tier deliberately lowers it.

    Re-simulates transitive impacts for any record whose target changed, since a stale
    `update_transitive_impacts` (computed against the old target) would otherwise mislead the
    writers; clears it when the re-simulation says the new target is not actionable.
    """
    for record in records:
        strategy = plan.for_package(record.package_name)
        facts = facts_from_record(record)
        releases = versions_since.get((record.package_name, record.installed_version), [])
        candidates = build_candidates(record, releases, registry, now=now, validator=validator)
        selection = select_target(facts, strategy, candidates)
        record.strategy_selection = selection

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
