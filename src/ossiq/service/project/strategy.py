"""Wires the pure `strategy/` selector onto `ScanRecord`s.

Modelled on `service.project.stability`: the pure decision lives in `strategy/`, this module is
the only place that turns a `ScanRecord` into the pure module's input (`facts_from_record`,
`build_candidates`) and writes its output back (`apply_update_strategy`).

Must run after `populate_stability` — `record.maintenance` and `record.triage` are populated
there, and `classify_motives` needs both to decide `END_OF_LIFE` correctly.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from functools import cache, cmp_to_key, partial

from ossiq.domain.common import (
    RUNG_ORDER,
    ConstraintType,
    EngineContext,
    ModuleSystem,
    OverrideHold,
    PeerHold,
    RecommendationRung,
    RejectedCandidate,
    RejectionDetail,
)
from ossiq.domain.policy import Policy, PolicyRule
from ossiq.domain.provenance import VersionBlocks
from ossiq.domain.release_cutoff import ReleaseCutoff
from ossiq.domain.update_plan import ImpactKind, RecommendationReason
from ossiq.domain.version import PeerDependency
from ossiq.risk.maintenance import DEPRECATION_NONE
from ossiq.service.common.package_versions import PackageVersion
from ossiq.service.project.breaking_changes import (
    crosses_module_system,
    module_break_reason,
    node_supports_require_esm,
)
from ossiq.service.project.ladder import classify_rung as ladder_classify_rung
from ossiq.service.project.ladder import installable_releases
from ossiq.service.project.models import ScanRecord
from ossiq.service.project.target_facts import annotate_target_facts, clear_target_facts
from ossiq.service.update_impact import (
    DirectUpdateImpact,
    find_best_satisfying_package_version,
    incoming_peer_edges,
    moves_with_candidate,
    simulate_single,
)
from ossiq.solver.ports import RegistryReader
from ossiq.solver.version_matchers import (
    cve_affects_version,
    engine_mismatch_reason,
    major_key,
    version_satisfies_constraint,
)
from ossiq.strategy.motive import PackageFacts, is_qualifying_score
from ossiq.strategy.overrides import StrategyPlan
from ossiq.strategy.pyramid import ESCALATING_MOTIVES, MODULE_BREAK_TIERS, UpdateStrategy, withholds_widening
from ossiq.strategy.targeting import Candidate, StrategySelection, select_target
from ossiq.timeutil import age_days_from_iso, parse_iso_datetime

__all__ = ["PackageFacts", "StrategyPlan", "apply_update_strategy", "build_candidates", "facts_from_record"]

# A gate returns a rejection reason for a release, or None to admit it. Evaluated before
# `validator` in build_candidates - cheap, in-memory checks first.
StructuralGate = Callable[[PackageVersion], str | None]


def module_system_gate(
    installed_module_system: ModuleSystem | None,
    project_declares_esm: bool,
    releases: list[PackageVersion],
    registry: RegistryReader,
) -> StructuralGate:
    """Reject a release that code on the installed module system can no longer load.

    Per release, through `crosses_module_system` — the same predicate behind
    `latest_preserving_module_system` — so the ladder fact and the gate cannot disagree. Never fires
    for a `"type": "module"` project.
    """

    def gate(pv: PackageVersion) -> str | None:
        if not crosses_module_system(installed_module_system, pv.module_system, project_declares_esm):
            return None
        return module_break_reason(pv, releases, registry.package_registry)

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
    strictly_gated: bool = False
    """Whether a `strict_gates` gate held any release back — the caller's cue that waiving it could
    still find a target."""


def classify_rung(
    version: str,
    record: ScanRecord,
    installed_major: tuple[int, int] | None,
    registry: RegistryReader,
) -> RecommendationRung:
    """Place *version* on the widening ladder relative to what *record*'s root manifest declares."""
    # The declaration, not version_constraint's last-writer-wins accumulator: this rung decides
    # whether `ossiq apply` may write, and it must be the same string the user is shown. Falls
    # back for transitive-only records, which have no declaration of their own - passing None
    # through would admit every candidate as IN_RANGE.
    constraint = record.version_constraint_declared or record.version_constraint
    return ladder_classify_rung(version, constraint, installed_major, registry.package_registry)


def describe_rejection(
    impact: DirectUpdateImpact, transitive_by_name: dict[str, ScanRecord]
) -> tuple[str, RejectionDetail | None]:
    """Explain why a candidate release was rejected, naming the blocking transitive dep.

    Attributes the block to an OSS IQ-authored override only when constraint_info says so —
    ConstraintSource.is_ossiq_authored (item #14) is what makes that claim verifiable rather than
    a guess. The override an impact itself names wins over the record's: with several copies of a
    package installed, the record stands for one and the rule that blocked may be on another.

    Returns the headline and its spec list separately rather than one joined sentence: the list
    can run to a dozen specs, and a table needs to elide what a log line prints in full.
    """
    blockers = [ti for ti in impact.transitive_impacts if ti.has_conflict]
    if not blockers:
        return "blocked by a transitive dependency conflict", None
    ti = blockers[0]
    blocking = transitive_by_name.get(ti.package_name)
    held = ti.held_by_override
    if held is None and blocking and blocking.constraint_info.type == ConstraintType.OVERRIDE:
        held = blocking.constraint_info
    if held is not None:
        if held.is_ossiq_authored:
            prefix = f"{ti.package_name} is held by an OSS IQ-authored override"
        else:
            prefix = f"{ti.package_name} is held by an override in {held.source_file}"
    elif ti.kind == ImpactKind.PEER:
        prefix = f"{ti.package_name} peer-requires {ti.driven_by}"
    else:
        prefix = f"{ti.package_name} requires {ti.new_constraint}"
    return prefix, ti.conflict


def user_override_hold(impact: DirectUpdateImpact) -> OverrideHold | None:
    """The user's own override behind a rejected candidate, or None when the block is anything else.

    An override OSS IQ wrote is not a hold: it is OSS IQ's to move, and a candidate it blocks is
    rejected on the strength of what that override would need, not on the user's say-so.
    """
    for ti in impact.transitive_impacts:
        held = ti.held_by_override
        if ti.has_conflict and held is not None and not held.is_ossiq_authored and held.override_value is not None:
            return OverrideHold(
                package=ti.package_name,
                value=held.override_value,
                key=held.override_key,
                source_file=held.source_file,
                blocked=(f"{impact.package_name}@{impact.recommended_version}",),
            )
    return None


def peer_hold(impact: DirectUpdateImpact) -> PeerHold | None:
    """The peer range behind a rejected candidate, or None when the block is anything else."""
    blockers = [ti for ti in impact.transitive_impacts if ti.has_conflict and ti.kind == ImpactKind.PEER]
    if not blockers:
        return None
    first = blockers[0]
    return PeerHold(
        package=impact.package_name,
        blocked_version=impact.recommended_version,
        requirer=first.package_name,
        spec=first.new_constraint,
        others=len(blockers) - 1,
    )


def build_candidates(
    record: ScanRecord,
    releases: list[PackageVersion],
    registry: RegistryReader,
    *,
    now: datetime | None = None,
    validator: Callable[[str, str], DirectUpdateImpact] | None = None,
    transitive_by_name: dict[str, ScanRecord] | None = None,
    structural_gates: Sequence[StructuralGate] = (),
    binding_gates: Sequence[StructuralGate] = (),
    strict_gates: Sequence[StructuralGate] = (),
    policy_blocks: Mapping[str, tuple[str, ...]] | None = None,
    policy: Policy | None = None,
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

    `strict_gates` are structural gates this function never waives: the module-system break, which
    a drift-only package should rather stay put for than cross. Whether an escalating motive (a CVE
    or end-of-life) justifies crossing anyway is `apply_update_strategy`'s call, since only it
    knows the motives; `strictly_gated` on the result tells it there was something to waive.

    `binding_gates` are the exception, for rejections the installer will enforce whatever OSS IQ
    says: a release excluded by `requires-python` is not "incompatible but still the best answer",
    it is one `uv`/`pip` refuse to resolve at all. Waiving those produced a recommendation that
    could only ever fail at `apply`, so they empty the ladder rather than be waived.

    `policy_blocks` maps a version to the reasons a configured supply-chain policy rules it out. Those
    releases are never candidates and are never waived, even when that leaves the ladder empty: the
    point of the policy is to refuse a release, however attractive it is otherwise. They are recorded
    as `RejectedCandidate(held_by_policy=True)` so the plan can say why nothing was proposed.

    `policy` is read for its cooldown waivers only: a candidate it waives is tagged `cooldown_waived`,
    so `select_target` treats it as aged however young it is.

    A release that clears the structural pre-filter but fails `validator` (i.e. it would break a
    transitive dependency) is not silently dropped: it's kept as a `RejectedCandidate`, capped at
    one per rung (the newest rejected release at that rung), so callers can explain a blank or
    lower `recommended_version` instead of staying silent about it.

    The cooldown is deliberately *not* applied here: every installable release becomes a candidate,
    tagged with its `age_days`, and `select_target` decides. Dropping fresh releases at this level
    would hide them from its escalation rules, which have to be able to see a fresh release to take
    it when a CVE leaves no other option.
    """
    qualifying_cves = [cve for cve in record.cve if is_qualifying_score(cve.epss)]

    installed_major = major_key(record.installed_version, registry.package_registry)
    transitive_by_name = transitive_by_name or {}

    installable = installable_releases(releases, registry, now=now, newer_than=record.installed_version)
    installable.sort(key=cmp_to_key(lambda a, b: registry.compare_versions(a.version, b.version)))

    strict_reasons: dict[str, str] = {}
    for pv in installable:
        for gate in strict_gates:
            reason = gate(pv)
            if reason is not None:
                strict_reasons[pv.version] = reason
                break

    gate_reasons: dict[str, str] = {}
    if structural_gates:
        waivable = [pv for pv in installable if pv.version not in strict_reasons]
        for pv in waivable:
            for gate in structural_gates:
                reason = gate(pv)
                if reason is not None:
                    gate_reasons[pv.version] = reason
                    break
        if gate_reasons and len(gate_reasons) == len(waivable):
            # Every installable release is flagged - never let a structural gate blank the whole
            # recommendation, so treat none of them as gated this pass.
            gate_reasons = {}
    # Strict gates sit outside that waiver: the caller decides, from the package's motives,
    # whether a ladder they empty should stay empty.
    gate_reasons.update(strict_reasons)

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

        policy_reasons = (policy_blocks or {}).get(pv.version)
        if policy_reasons:
            rejected_by_rung[rung] = RejectedCandidate(
                version=pv.version, reason="; ".join(policy_reasons), held_by_policy=True
            )
            continue

        gate_reason = gate_reasons.get(pv.version)
        if gate_reason is not None:
            rejected_by_rung[rung] = RejectedCandidate(version=pv.version, reason=gate_reason)
            continue

        candidate = Candidate(
            version=pv.version,
            rung=rung,
            has_cve=any(cve_affects_version(cve, pv.version) for cve in qualifying_cves),
            age_days=age_days_from_iso(pv.published_date_iso, now=now),
            published_at=parse_iso_datetime(pv.published_date_iso),
            cooldown_waived=policy is not None and policy.waives(PolicyRule.COOLDOWN, record.package_name, pv.version),
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
            headline, detail = describe_rejection(impact, transitive_by_name)
            rejected_by_rung[rung] = RejectedCandidate(
                version=pv.version,
                reason=headline,
                detail=detail,
                held_by_override=user_override_hold(impact),
                held_by_peer=peer_hold(impact),
            )

    rejected = tuple(rejected_by_rung[rung] for rung in sorted(rejected_by_rung, key=RUNG_ORDER.__getitem__))
    return BuiltCandidates(candidates=tuple(candidates), rejected=rejected, strictly_gated=bool(strict_reasons))


def clears_motive(selection: StrategySelection, built: BuiltCandidates) -> bool:
    """Whether *selection* found a target that leaves no qualifying CVE behind.

    For an end-of-life motive any target resolves it; for an exploitable CVE the target must not
    carry one itself — `select_target`'s rule 7 picks a still-affected release when nothing clean is
    in reach, and that is exactly the case a waived gate might improve on.
    """
    if selection.target_version is None:
        return False
    picked = next((c for c in built.candidates if c.version == selection.target_version), None)
    return picked is None or not picked.has_cve


MAX_PEER_ROUNDS = 10


@dataclass(frozen=True)
class PeerConflict:
    """A range two direct packages cannot both meet at the versions the plan gives them."""

    requirer: str
    """The package that declares the range."""

    package: str
    """The package the range is on."""

    spec: str

    held_at: str
    """The version `package` would be at, or the declared range a package the plan leaves is held to."""

    is_peer: bool = True
    """False for an ordinary requirement, which binds like a peer where one copy is installed per name."""


@dataclass(frozen=True)
class TargetDecision:
    """One direct record's verdict, kept so a peer conflict can send it back for a lower pick."""

    record: ScanRecord
    facts: PackageFacts
    strategy: UpdateStrategy
    built: BuiltCandidates
    releases: list[PackageVersion]
    refused: dict[str, PeerConflict] = field(default_factory=dict)
    """Versions this record may not take, with the conflict that ruled each out."""


def find_peer_conflict(
    name: str,
    version: str,
    finals: Mapping[str, str],
    installed: Mapping[str, str],
    registry: RegistryReader,
    peers_of: Callable[[str, str], Mapping[str, PeerDependency]] | None = None,
) -> PeerConflict | None:
    """The first peer range *name* at *version* breaks against every other package's final version.

    Checked both ways: the peers *version* declares on the others, and the peers the others declare
    on *name*. A peer binds the one hoisted instance, so unlike an ordinary requirement there is no
    copy to nest. A range the installed pair already missed is existing drift, not something this
    plan introduces, and does not count.

    Args:
        name: The package whose pick is being checked.
        version: The version it would move to.
        finals: Each package's version once the plan applies (its pick, or as installed).
        installed: Each package's installed version, to tell drift from new breakage.
        registry: Registry, for each release's declared peers.
        peers_of: The peer lookup to use, when the caller memoizes it; the registry's otherwise.

    Returns:
        The conflict, or None when *version* fits everything the others will be at.
    """
    kind = registry.package_registry
    peers = peers_of or registry.package_version_peers
    current = installed.get(name)

    def satisfies(candidate: str, spec: str) -> bool:
        return version_satisfies_constraint(candidate, spec, kind)

    for dep, peer in peers(name, version).items():
        held = finals.get(dep)
        if dep == name or held is None or not peer.spec or satisfies(held, peer.spec):
            continue
        earlier = peers(name, current).get(dep) if current else None
        if earlier is not None and dep in installed and not satisfies(installed[dep], earlier.spec):
            continue
        return PeerConflict(requirer=name, package=dep, spec=peer.spec, held_at=held)

    for other, other_version in finals.items():
        if other == name:
            continue
        peer = peers(other, other_version).get(name)
        if peer is None or not peer.spec or satisfies(version, peer.spec):
            continue
        earlier = peers(other, installed[other]).get(name) if other in installed else None
        if earlier is not None and current and not satisfies(current, earlier.spec):
            continue
        return PeerConflict(requirer=other, package=name, spec=peer.spec, held_at=version)
    return None


def find_requirement_conflict(
    name: str,
    version: str,
    finals: Mapping[str, str],
    installed: Mapping[str, str],
    *,
    registry: RegistryReader,
    declared_ranges: Mapping[str, str | None],
    fits: Callable[[str, list[str]], PackageVersion | None],
) -> PeerConflict | None:
    """The first requirement *name* at *version* places on another direct package the plan cannot meet.

    Only for a package manager that installs one copy per name, where an ordinary requirement binds
    that copy as a peer does. A package the plan moves is pinned at its pick. One it leaves can still
    move inside its declared range when the lock is rebuilt, so it conflicts only when no release in
    that range meets the requirement. Transitive packages are `simulate_single`'s to judge.

    Args:
        name: The package whose pick is being checked.
        version: The version it would move to.
        finals: Each package's version once the plan applies (its pick, or as installed).
        installed: Each package's installed version, to tell a pick from a package left in place.
        registry: Registry, for each release's declared requirements.
        declared_ranges: The range each direct package declares, for those a requirement binds.
        fits: The newest release of a package meeting every given range, or None.

    Returns:
        The conflict, or None when every direct package can meet what *version* requires of it.
    """
    for dep, spec in registry.package_version_requires(name, version).items():
        if dep == name or not spec or dep not in declared_ranges or dep not in finals:
            continue
        held = finals[dep]
        if version_satisfies_constraint(held, spec, registry.package_registry):
            continue
        if held != installed.get(dep):
            return PeerConflict(requirer=name, package=dep, spec=spec, held_at=held, is_peer=False)
        declared = declared_ranges[dep]
        if declared and fits(dep, [declared, spec]) is None:
            return PeerConflict(requirer=name, package=dep, spec=spec, held_at=declared, is_peer=False)
    return None


def record_peer_refusal(record: ScanRecord, version: str, conflict: PeerConflict, registry: RegistryReader) -> None:
    """Add a release the joint pass refused to the record's rejected candidates, one per rung as elsewhere."""
    verb = "peer-requires" if conflict.is_peer else "requires"
    if conflict.requirer == record.package_name:
        refused = RejectedCandidate(
            version=version,
            reason=f"{record.package_name} {version} {verb} {conflict.package}",
            detail=RejectionDetail(f"held at {conflict.held_at}, wanted", (conflict.spec,)),
        )
    else:
        refused = RejectedCandidate(
            version=version,
            reason=f"{conflict.requirer} {verb} {record.package_name}",
            detail=RejectionDetail(f"{version} violates", (conflict.spec,)),
            held_by_peer=PeerHold(
                package=record.package_name,
                blocked_version=version,
                requirer=conflict.requirer,
                spec=conflict.spec,
            ),
        )
    installed_major = major_key(record.installed_version, registry.package_registry)
    by_rung = {classify_rung(rc.version, record, installed_major, registry): rc for rc in record.rejected_candidates}
    rung = classify_rung(version, record, installed_major, registry)
    kept = by_rung.get(rung)
    if kept is None or registry.compare_versions(version, kept.version) > 0:
        by_rung[rung] = refused
    record.rejected_candidates = [by_rung[r] for r in sorted(by_rung, key=RUNG_ORDER.__getitem__)]


def landing_version(decision: TargetDecision) -> str:
    """The version the decision's package ends at once the plan applies.

    Its pick, unless the plan holds that pick back for a widening the tier does not reach
    (`holds.is_held_for_widening`); then it stays as installed.
    """
    record = decision.record
    selection = record.strategy_selection
    authorized = selection is not None and selection.widening_authorized
    if record.recommended_version is None or withholds_widening(
        decision.strategy, record.recommended_from_rung, authorized
    ):
        return record.installed_version
    return record.recommended_version


def dragged_copies(record: ScanRecord, transitive_by_name: Mapping[str, ScanRecord]) -> dict[str, tuple[str, str]]:
    """The installed copies the record's pick replaces, as {name: (copy version, version it moves to)}.

    Same rule as `assess_incoming_peers`: an override bump moves its copy in place, any other copy
    only when nothing but the pick and what it pulls along asks for it. vue pins its renderer to its
    own version, so the renderer's old copy is gone once vue lands and cannot hold vue back.

    Args:
        record: The direct record whose pick is being judged.
        transitive_by_name: The scan's transitive records, for each copy's owners.

    Returns:
        The copies that go away with the pick, keyed by package name.
    """
    moving = [
        i for i in record.update_transitive_impacts if not i.has_conflict and i.projected_version != i.current_version
    ]
    movers = {record.package_name, *(i.package_name for i in moving)}
    dragged: dict[str, tuple[str, str]] = {}
    for impact in moving:
        if impact.current_version is None or impact.projected_version is None:
            continue
        dep = transitive_by_name.get(impact.package_name)
        if impact.kind == ImpactKind.OVERRIDE_BUMP or (
            dep and moves_with_candidate(dep, impact.current_version, movers)
        ):
            dragged[impact.package_name] = (impact.current_version, impact.projected_version)
    return dragged


def reconcile_peer_targets(
    decisions: Sequence[TargetDecision],
    registry: RegistryReader,
    fixed_versions: Mapping[str, str],
    reselect: Callable[[TargetDecision, tuple[Candidate, ...]], StrategySelection],
    write: Callable[[TargetDecision, StrategySelection, str], None],
    fixed_installed: Mapping[str, str] | None = None,
    requirement_conflict: Callable[[str, str, Mapping[str, str], Mapping[str, str]], PeerConflict | None] | None = None,
    transitive_by_name: Mapping[str, ScanRecord] | None = None,
) -> None:
    """Send back every pick whose peers, or requirements, clash with another package's final version.

    Each pick is chosen on its own, so two packages can end up on versions that peer-require each
    other out (vue bumped while its lockstep partner stays), and the transitive picks were made
    before this pass even ran. The mover is re-selected from the candidates it still has, until no
    pick clashes; a record left with none keeps its installed version. Only direct picks are checked,
    so a package this pass does not decide (an ignored one, a transitive one, a record with no
    target) is never the one that gives way.

    Args:
        decisions: One per direct record the strategy pass decided on.
        registry: Registry, for each release's declared peers.
        fixed_versions: The final version of every package this pass does not move: ignored direct
            ones as installed, transitive ones as the plan leaves them.
        reselect: Runs the selector again over a reduced candidate list.
        write: Writes a new verdict onto its record; the third argument is the pick it replaces.
        fixed_installed: The installed version of each package in `fixed_versions`, to tell drift
            from new breakage; `fixed_versions` itself when omitted.
        requirement_conflict: Where one copy is installed per name, the check for ordinary
            requirements on other direct packages (`find_requirement_conflict`); None elsewhere.
        transitive_by_name: The scan's transitive records. A transitive copy that only a landing
            pick owns moves with it (`dragged_copies`), so it does not hold that pick back.
    """
    installed = {
        **(fixed_installed if fixed_installed is not None else fixed_versions),
        **{d.record.package_name: d.record.installed_version for d in decisions},
    }
    peers_of = cache(registry.package_version_peers)

    def landed() -> dict[str, str]:
        # shortcut: two picks dragging the same copy to different versions - the later one wins; upgrade
        # when a package family is ever pulled two ways at once.
        dragged = {
            name: new
            for d in decisions
            if d.record.recommended_version is not None and landing_version(d) == d.record.recommended_version
            for name, (old, new) in dragged_copies(d.record, transitive_by_name or {}).items()
            if installed.get(name) == old
        }
        return {**fixed_versions, **dragged, **{d.record.package_name: landing_version(d) for d in decisions}}

    finals = landed()

    for _ in range(MAX_PEER_ROUNDS):
        demoted = False
        for decision in decisions:
            record = decision.record
            pick = record.recommended_version
            # A pick the plan holds back never lands, so nothing it requires can break.
            if pick is None or landing_version(decision) != pick:
                continue
            conflict = find_peer_conflict(record.package_name, pick, finals, installed, registry, peers_of)
            if conflict is None and requirement_conflict is not None:
                conflict = requirement_conflict(record.package_name, pick, finals, installed)
            if conflict is None:
                continue
            decision.refused[pick] = conflict
            remaining = tuple(c for c in decision.built.candidates if c.version not in decision.refused)
            selection = reselect(decision, remaining)
            record.strategy_selection = selection
            record_peer_refusal(record, pick, conflict, registry)
            write(decision, selection, pick)
            finals = landed()
            demoted = True
        if not demoted:
            return


def apply_update_strategy(
    records: list[ScanRecord],
    registry: RegistryReader,
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
    release_cutoff: ReleaseCutoff | None = None,
    fixed_versions: Mapping[str, str] | None = None,
    fixed_installed: Mapping[str, str] | None = None,
    version_blocks: VersionBlocks | None = None,
    policy: Policy | None = None,
    declared_ranges: Mapping[str, str | None] | None = None,
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
    motive justified taking a fresh one anyway. `release_cutoff`, the package manager's own limit,
    goes to `select_target` too and binds whatever the motive, since the installer enforces it.

    Re-simulates transitive impacts for any record whose target changed, since a stale
    `update_transitive_impacts` (computed against the old target) would otherwise mislead the
    writers; clears it when the re-simulation says the new target is not actionable.

    Picks are made one record at a time, so a last pass (`reconcile_peer_targets`) sends back any
    that peer-require another package out of its final version. `fixed_versions` holds the final
    version of every package this pass does not move (ignored direct ones, transitive ones), and
    `fixed_installed` their installed versions; that pass holds them in place.

    `version_blocks` carries the configured supply-chain policy's verdicts; a blocked release is never
    a candidate, and the installed one is never in the ladder anyway, so it stays.

    `declared_ranges` maps every direct package a requirement binds to the range its manifest
    declares. Where one copy is installed per name, that last pass also sends back a pick whose
    ordinary requirements another direct package cannot meet (`find_requirement_conflict`).
    """
    engine_context = engine_context or EngineContext()
    decisions: list[TargetDecision] = []
    direct_versions = {**(fixed_versions or {}), **{r.package_name: r.installed_version for r in records}}

    def write_verdict(decision: TargetDecision, selection: StrategySelection, previous_target: str | None) -> None:
        record, releases = decision.record, decision.releases
        if selection.target_version is None:
            record.recommended_version = None
            record.recommended_from_rung = None
            record.recommended_version_reason = None
            record.update_transitive_impacts = []
            clear_target_facts(record)
            return

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
                release_cutoff=release_cutoff,
                incoming_peers=incoming_peer_edges(record.installed_copies, record.installed_version),
                direct_versions=direct_versions,
            )
            record.update_transitive_impacts = impact.transitive_impacts if impact.is_actionable else []

    def reselect(decision: TargetDecision, candidates: tuple[Candidate, ...]) -> StrategySelection:
        return select_target(
            decision.facts,
            decision.strategy,
            candidates,
            cooldown_period=cooldown_period,
            release_cutoff=release_cutoff,
        )

    for record in records:
        strategy = plan.for_package(record.package_name)
        facts = facts_from_record(record)
        releases = versions_since.get((record.package_name, record.installed_version), [])
        engine_gate = engine_mismatch_gate(engine_context)
        # npm installs an engines mismatch anyway (a warning, not a refusal), so there it stays
        # advisory and waivable. pip and uv refuse outright, so on PyPI the gate has to bind.
        engine_gate_binds = registry.refuses_engine_mismatch
        # Crossing to ESM-only is a freshness tier's call, and only on a runtime that can
        # require() ESM at all. Even there it stays flagged (breaking_change), because require()
        # returns the namespace and a default-export-only package still breaks.
        may_cross = strategy in MODULE_BREAK_TIERS and node_supports_require_esm(engine_context.versions.get("node"))
        module_gates: tuple[StructuralGate, ...] = (
            ()
            if may_cross
            else (module_system_gate(record.compatibility.module_system, project_declares_esm, releases, registry),)
        )

        build = partial(
            build_candidates,
            record,
            releases,
            registry,
            now=now,
            validator=validator,
            transitive_by_name=transitive_by_name,
            structural_gates=() if engine_gate_binds else (engine_gate,),
            binding_gates=(engine_gate,) if engine_gate_binds else (),
            policy_blocks=(version_blocks or {}).get(record.package_name),
            policy=policy,
        )

        built = build(strict_gates=module_gates)
        selection = select_target(
            facts, strategy, built.candidates, cooldown_period=cooldown_period, release_cutoff=release_cutoff
        )
        if built.strictly_gated and selection.motives & ESCALATING_MOTIVES and not clears_motive(selection, built):
            # A CVE or end-of-life motive with no clean answer left on the module line: security
            # beats build convenience, so the gated releases come back in. Drift alone never
            # reaches here, which is what keeps a CommonJS project on its CommonJS line.
            waived = build(strict_gates=())
            waived_selection = select_target(
                facts, strategy, waived.candidates, cooldown_period=cooldown_period, release_cutoff=release_cutoff
            )
            if clears_motive(waived_selection, waived):
                built, selection = waived, waived_selection
        record.strategy_selection = selection
        record.rejected_candidates = list(built.rejected)

        decision = TargetDecision(record, facts, strategy, built, releases)
        decisions.append(decision)
        write_verdict(decision, selection, record.recommended_version)

    requirement_conflict = (
        partial(
            find_requirement_conflict,
            registry=registry,
            declared_ranges=declared_ranges,
            fits=partial(
                find_best_satisfying_package_version,
                registry=registry,
                allow_prerelease=allow_prerelease,
                now=now,
                release_cutoff=release_cutoff,
            ),
        )
        if registry.one_copy_per_name and declared_ranges
        else None
    )
    reconcile_peer_targets(
        decisions,
        registry,
        fixed_versions or {},
        reselect,
        write_verdict,
        fixed_installed,
        requirement_conflict,
        transitive_by_name,
    )
