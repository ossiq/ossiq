"""Wires the pure `strategy/` selector onto `ScanRecord`s.

Modelled on `service.project.stability`: the pure decision lives in `strategy/`, this module is
the only place that turns a `ScanRecord` into the pure module's input (`facts_from_record`,
`build_candidates`) and writes its output back (`apply_update_strategy`).

Must run after `populate_stability` — `record.maintenance` and `record.triage` are populated
there, and `classify_motives` needs both to decide `END_OF_LIFE` correctly.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from functools import cmp_to_key

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import (
    RUNG_ORDER,
    ConstraintType,
    EngineContext,
    ProjectPackagesRegistry,
    RecommendationRung,
    RejectedCandidate,
)
from ossiq.risk.maintenance import DEPRECATION_NONE
from ossiq.risk.triage import EPSS_NOISE_THRESHOLD
from ossiq.service.common.package_versions import PackageVersion
from ossiq.service.project.breaking_changes import breaking_majors
from ossiq.service.project.ladder import classify_rung as ladder_classify_rung
from ossiq.service.project.ladder import installable_releases
from ossiq.service.project.models import ScanRecord
from ossiq.service.project.target_facts import annotate_target_facts, clear_target_facts
from ossiq.service.update_impact import DirectUpdateImpact, simulate_single
from ossiq.solver.reason import RecommendationReason
from ossiq.solver.version_matchers import (
    engine_mismatch_reason,
    major_key,
)
from ossiq.strategy.motive import PackageFacts
from ossiq.strategy.overrides import StrategyPlan
from ossiq.strategy.targeting import Candidate, select_target
from ossiq.timeutil import age_days_from_iso

__all__ = ["PackageFacts", "StrategyPlan", "apply_update_strategy", "build_candidates", "facts_from_record"]

# A gate returns a rejection reason for a release, or None to admit it. Evaluated before
# `validator` in build_candidates - cheap, in-memory checks first.
StructuralGate = Callable[[PackageVersion], str | None]


def breaking_change_gate(
    breaks: dict[tuple[int, int], str],
    registry: AbstractPackageRegistryApi,
    project_declares_esm: bool,
) -> StructuralGate:
    """Reject a release whose major line is a known module-system/API break.

    Never fires when the project itself declares ESM (`project_declares_esm`) - an ESM-only
    dependency is not a break for a project that is itself `"type": "module"`.
    """

    def gate(pv: PackageVersion) -> str | None:
        if project_declares_esm:
            return None
        major = major_key(pv.version, registry.package_registry)
        return breaks.get(major) if major is not None else None

    return gate


def engine_mismatch_gate(engine_context: EngineContext) -> StructuralGate:
    """Reject a release whose declared runtime_requirements conflict with engine_context.

    No-op (never rejects) when the context carries no versions — `engine_mismatch_reason` applies
    the same "either side empty -> no mismatch" rule the solver's own L2 check uses.
    """

    def gate(pv: PackageVersion) -> str | None:
        return engine_mismatch_reason(pv.runtime_requirements, engine_context.versions)

    return gate


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
    """Place *version* on the widening ladder relative to what *record*'s root manifest declares."""
    # The declaration, not version_constraint's last-writer-wins accumulator: this rung decides
    # whether `ossiq apply` may write, and it must be the same string the user is shown. Falls
    # back for transitive-only records, which have no declaration of their own - passing None
    # through would admit every candidate as IN_RANGE.
    constraint = record.version_constraint_declared or record.version_constraint
    return ladder_classify_rung(version, constraint, installed_major, registry.package_registry)


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
    structural_gates: Sequence[StructuralGate] = (),
    binding_gates: Sequence[StructuralGate] = (),
) -> BuiltCandidates:
    """Build the ascending candidate ladder for one record.

    Shares `installable_releases` and `classify_rung` with `ladder.compute_version_ladder`, so a
    candidate's rung can never disagree with the ladder rung on the same input. `has_cve` is true
    only for a qualifying CVE — one at/above EPSS_NOISE_THRESHOLD, or unscored — mirroring
    `strategy.motive.classify_motives`'s EXPLOITABLE_CVE rule.

    `structural_gates` are cheap, in-memory checks (e.g. a known module-system break) evaluated
    before `validator`; the first non-None reason wins. Unlike `validator`, a structural gate never
    blanks the whole ladder: if it would reject every installable release, none of them are
    treated as gated for this call, so `select_target` can still pick the newest and the caller can
    explain the pick via the same evidence the gate would have used (e.g. ScanRecord.breaking_change) —
    mirrors the "every reachable version affected -> recommend the newest anyway" CVE rule.

    `binding_gates` are the exception, for rejections the installer will enforce whatever OSS IQ
    says: a release excluded by `requires-python` is not "incompatible but still the best answer",
    it is one `uv`/`pip` refuse to resolve at all. Waiving those produced a recommendation that
    could only ever fail at `apply`, so they empty the ladder rather than be waived.

    A release that clears the structural pre-filter but fails `validator` (i.e. it would break a
    transitive dependency) is not silently dropped: it's kept as a `RejectedCandidate`, capped at
    one per rung (the newest rejected release at that rung), so callers can explain a blank or
    lower `recommended_version` instead of staying silent about it.

    The cooldown is deliberately *not* applied here: every installable release becomes a candidate,
    tagged with its `age_days`, and `select_target` decides. Dropping fresh releases at this level
    would hide them from its escalation rules, which have to be able to see a fresh release to take
    it when a CVE leaves no other option.
    """
    qualifying_versions: set[str] = set()
    for cve in record.cve:
        if cve.epss is None or cve.epss >= EPSS_NOISE_THRESHOLD:
            qualifying_versions.update(cve.affected_versions)

    installed_major = major_key(record.installed_version, registry.package_registry)
    transitive_by_name = transitive_by_name or {}

    installable = installable_releases(releases, registry, now=now, newer_than=record.installed_version)
    installable.sort(key=cmp_to_key(lambda a, b: registry.compare_versions(a.version, b.version)))

    gate_reasons: dict[str, str] = {}
    if structural_gates:
        for pv in installable:
            for gate in structural_gates:
                reason = gate(pv)
                if reason is not None:
                    gate_reasons[pv.version] = reason
                    break
        if gate_reasons and len(gate_reasons) == len(installable):
            # Every installable release is flagged - never let a structural gate blank the whole
            # recommendation, so treat none of them as gated this pass.
            gate_reasons = {}

    # Applied after the waiver, and overwriting it: these rejections are not advisory, so a ladder
    # they empty stays empty.
    for pv in installable:
        for gate in binding_gates:
            reason = gate(pv)
            if reason is not None:
                gate_reasons[pv.version] = reason
                break

    candidates: list[Candidate] = []
    rejected_by_rung: dict[RecommendationRung, RejectedCandidate] = {}
    for pv in installable:
        rung = classify_rung(pv.version, record, installed_major, registry)

        gate_reason = gate_reasons.get(pv.version)
        if gate_reason is not None:
            rejected_by_rung[rung] = RejectedCandidate(version=pv.version, reason=gate_reason)
            continue

        candidate = Candidate(
            version=pv.version,
            rung=rung,
            has_cve=pv.version in qualifying_versions,
            age_days=age_days_from_iso(pv.published_date_iso, now=now),
        )

        if validator is None:
            candidates.append(candidate)
            continue

        impact = validator(record.package_name, pv.version)
        if impact.is_actionable:
            candidates.append(candidate)
        else:
            # Overwriting on each hit keeps the newest rejected release per rung, since
            # installable is sorted ascending.
            rejected_by_rung[rung] = RejectedCandidate(
                version=pv.version, reason=describe_rejection(impact, transitive_by_name)
            )

    rejected = tuple(rejected_by_rung[rung] for rung in sorted(rejected_by_rung, key=RUNG_ORDER.__getitem__))
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
    project_declares_esm: bool = False,
    engine_context: EngineContext | None = None,
    cooldown_period: int = 0,
) -> None:
    """Run the selector for each record and write its verdict, replacing `apply_ladder_fallback`.

    The single writer of `recommended_version` past this point: whatever `select_target` returns
    is what the record carries afterward, whether that raises, lowers, or clears the pick the
    solver/`clamp_recommendations` left in place. `record.recommended_version` going into this
    function is `select_target`'s own candidate ladder, so a freshness tier's "newest in reach"
    can never end up lower than it — only a minimal-diff tier deliberately lowers it.

    Also the single writer of `rejected_candidates` for direct records: every release `validator`
    or a structural gate (module-system break, engine mismatch) held back from the ladder is
    recorded here regardless of what `select_target` ends up choosing, so a blank or lowered
    The target-compatibility cluster (`recommended_module_system`, `breaking_change`,
    `engine_requirement`, `engine_compatible`) is written by
    `target_facts.annotate_target_facts` for whatever target ends up chosen — one writer shared
    with `apply_recommendations`, which annotates transitive records the same way.

    Running last also makes this the only place the cooldown can be honoured for a direct
    dependency: the solver's soft `W_VERY_FRESH` penalty and `clamp_recommendations`' aged
    preference are both upstream of this pass and were simply overwritten by it, so `status`
    recommended a release `apply` then refused. `cooldown_period` is forwarded to `select_target`,
    which prefers an aged release, blanks the target when only fresh ones are reachable (recording
    `strategy_selection.cooldown_hold`), and sets `cooldown_bypassed` when a CVE or end-of-life
    motive justified taking a fresh one anyway.

    Re-simulates transitive impacts for any record whose target changed, since a stale
    `update_transitive_impacts` (computed against the old target) would otherwise mislead the
    writers; clears it when the re-simulation says the new target is not actionable.
    """
    engine_context = engine_context or EngineContext()
    for record in records:
        strategy = plan.for_package(record.package_name)
        facts = facts_from_record(record)
        releases = versions_since.get((record.package_name, record.installed_version), [])
        breaks = breaking_majors(record.package_name, releases, registry.package_registry)
        engine_gate = engine_mismatch_gate(engine_context)
        # npm installs an engines mismatch anyway (a warning, not a refusal), so there it stays
        # advisory and waivable. pip and uv refuse outright, so on PyPI the gate has to bind.
        engine_gate_binds = registry.package_registry == ProjectPackagesRegistry.PYPI
        gates: tuple[StructuralGate, ...] = (breaking_change_gate(breaks, registry, project_declares_esm),)
        if not engine_gate_binds:
            gates += (engine_gate,)
        built = build_candidates(
            record,
            releases,
            registry,
            now=now,
            validator=validator,
            transitive_by_name=transitive_by_name,
            structural_gates=gates,
            binding_gates=(engine_gate,) if engine_gate_binds else (),
        )
        selection = select_target(facts, strategy, built.candidates, cooldown_period=cooldown_period)
        record.strategy_selection = selection
        record.rejected_candidates = list(built.rejected)

        previous_target = record.recommended_version
        if selection.target_version is None:
            record.recommended_version = None
            record.recommended_from_rung = None
            record.recommended_version_reason = None
            record.update_transitive_impacts = []
            clear_target_facts(record)
            continue

        record.recommended_version = selection.target_version
        record.recommended_from_rung = selection.rung
        annotate_target_facts(
            record,
            selection.target_version,
            releases,
            registry.package_registry,
            engine_context=engine_context,
            project_declares_esm=project_declares_esm,
        )
        picked = next((pv for pv in releases if pv.version == selection.target_version), None)
        # `clamp_recommendations` blanks the reason for the pick it re-fitted, so an unchanged
        # target can still arrive here with no reason at all - and a reason is where the cooldown
        # hold and the plan's Age column read `age_days` from.
        if selection.target_version != previous_target or record.recommended_version_reason is None:
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
