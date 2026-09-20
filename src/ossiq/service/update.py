"""Update plan service: builds an atomic update plan from solver-enriched scan results."""

from __future__ import annotations

import dataclasses
from collections import Counter
from dataclasses import dataclass, field

from ossiq.domain.common import (
    WIDENING_RUNGS,
    ConstraintType,
    CooldownHold,
    RecommendationRung,
    display_package_name,
)
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.service.update_impact import TransitiveImpact
from ossiq.solver.reason import RecommendationReason
from ossiq.strategy.overrides import StrategyPlan
from ossiq.strategy.pyramid import DEFAULT_STRATEGY, MAX_REACH, RUNG_ORDER, UpdateStrategy


@dataclass(frozen=True)
class UpdateEntry:
    """A single package recommended for update by the solver."""

    package_name: str
    current_version: str
    recommended_version: str
    is_direct: bool
    reason: RecommendationReason | None
    # The key this dependency is declared under in the manifest, when it differs from the registry
    # name — npm aliases (`uuid-v7: "npm:uuid@^7.0.0"`) are the only source of a difference today.
    # None for transitive records, which have no declaration of their own. Read it through
    # `identity`, never directly.
    dependency_name: str | None = None
    transitive_impacts: list[TransitiveImpact] = field(default_factory=list)
    # False when transitive conflicts exist and no conflict-free candidate was found.
    is_actionable: bool = True
    version_defined: str | None = None
    constraint_type: ConstraintType = ConstraintType.DECLARED
    # True when the installed version carries a CVE — exempts the entry from the cooldown hold.
    is_security: bool = False
    # True when the version was forced via --override — bypasses the solver and the cooldown.
    is_forced: bool = False
    # Which version-ladder rung recommended_version came from. IN_MAJOR/LATEST require widening
    # version_defined first — is_held_for_widening holds those out of direct/transitive_entries
    # unless the run's strategy tier authorizes reaching that far.
    from_rung: RecommendationRung | None = None
    # True when recommended_version sits outside version_defined (from_rung is IN_MAJOR/LATEST).
    # Distinct from is_held_for_widening: an entry can widen the constraint and still be written
    # (a `latest`-tier pick) — command_apply uses this to gate a second confirmation regardless.
    widens_constraint: bool = False
    # True when the target's major line is a known API/module-system break. For a direct record this
    # means build_candidates' escape hatch fired: every installable release was gated, so rather
    # than blank the recommendation it admitted the newest anyway. That pick can sit inside the
    # declared range (e.g. `uuid@>11.0.0` admitting ESM-only 14.0.2), in which case
    # widens_constraint is False and nothing else would ask before writing it.
    carries_known_break: bool = False
    # True when select_target knowingly took a release younger than the cooldown because an
    # escalating motive (exploitable CVE, end-of-life) left nothing aged that resolved it. Exempts
    # the entry from the cooldown hold the same way is_security does, but covers the end-of-life
    # case that is_security alone misses.
    cooldown_bypassed: bool = False

    @property
    def identity(self) -> str:
        """The manifest key this entry writes to — the plan's unit of identity.

        Two npm aliases of one package (`uuid-v7` and `uuid-v11`) share a `package_name`, so
        keying the plan's partitions or the manifest rewrite on that name makes them collide:
        holding one for widening dropped the other from the plan entirely, and the npm writer
        matched neither because the manifest key is the alias. `package_name` remains the registry
        name — the solver, OSV and the registry clients all key on it and must keep doing so.
        """
        return self.dependency_name or self.package_name

    @property
    def display_name(self) -> str:
        """How to name this entry to a human — see domain.common.display_package_name."""
        return display_package_name(self.package_name, self.dependency_name)


@dataclass(frozen=True)
class UpdatePlan:
    """Atomic update plan derived from solver recommendations for a scanned project."""

    project_name: str
    project_path: str
    registry_type: str
    package_manager_name: str
    direct_entries: list[UpdateEntry]
    transitive_entries: list[UpdateEntry]
    pin_all: bool = False
    installed_versions: dict[str, str] = field(default_factory=dict)
    # Recommendations withheld because the target version is younger than the cooldown period.
    held_for_cooldown: list[UpdateEntry] = field(default_factory=list)
    cooldown_period: int = 0
    # --override targets that are not present anywhere in the scanned dependency tree.
    unknown_override_packages: tuple[str, ...] = ()
    # Recommendations withheld because the run's strategy tier does not reach that rung yet
    # (from_rung is IN_MAJOR/LATEST) — see is_held_for_widening.
    held_for_widening: list[UpdateEntry] = field(default_factory=list)
    # The tier in force for this run (the default; per-package tiers are strategy_overrides).
    strategy: UpdateStrategy = DEFAULT_STRATEGY
    strategy_overrides: dict[str, UpdateStrategy] = field(default_factory=dict)
    # Packages withheld at the run's tier, counted by the lowest higher tier that would move
    # them — powers the "N more updates available under --update-strategy X" footer.
    available_at_higher_tier: dict[UpdateStrategy, int] = field(default_factory=dict)

    @property
    def all_entries(self) -> list[UpdateEntry]:
        return self.direct_entries + self.transitive_entries


def entry_from_record(record: ScanRecord, is_direct: bool) -> UpdateEntry:
    """Build an UpdateEntry from a ScanRecord that has a solver recommendation."""
    assert record.recommended_version is not None
    return UpdateEntry(
        package_name=record.package_name,
        dependency_name=record.dependency_name,
        current_version=record.installed_version,
        recommended_version=record.recommended_version,
        is_direct=is_direct,
        reason=record.recommended_version_reason,
        transitive_impacts=list(record.update_transitive_impacts),
        is_actionable=all(not i.has_conflict for i in record.update_transitive_impacts),
        # The declaration, not version_constraint's last-writer-wins accumulator: the uv writer
        # rewrites this exact string into pyproject.toml (api_uv.resolve_direct_specifier), so it
        # has to be the root manifest's own spec. Transitive-only records fall back to the LWW value.
        version_defined=record.version_constraint_declared or record.version_constraint,
        constraint_type=record.constraint_info.type,
        is_security=bool(record.cve),
        from_rung=record.recommended_from_rung,
        widens_constraint=record.recommended_from_rung in WIDENING_RUNGS,
        carries_known_break=record.compatibility.breaking_change is not None,
        cooldown_bypassed=record.strategy_selection is not None and record.strategy_selection.cooldown_bypassed,
    )


def cooldown_entry_from_record(record: ScanRecord, hold: CooldownHold) -> UpdateEntry:
    """Build a display-only entry for a record the cooldown left without a recommendation.

    `apply_update_strategy` blanks `recommended_version` when every reachable release is younger
    than the cooldown, so such a record can never become a real `UpdateEntry` — and would drop out
    of the plan silently. This rebuilds just enough of one to keep it listed under "held for
    cooldown". It never enters direct_entries/transitive_entries, so nothing writes it.
    """
    return UpdateEntry(
        package_name=record.package_name,
        dependency_name=record.dependency_name,
        current_version=record.installed_version,
        recommended_version=hold.version,
        is_direct=True,
        reason=RecommendationReason(
            selected_version=hold.version,
            constraint=record.version_constraint,
            hard_rejections=[],
            soft_rejections=[],
            lower_semver_alternatives=[],
            age_days=hold.age_days,
            is_latest=hold.version == record.latest_version,
        ),
        version_defined=record.version_constraint_declared or record.version_constraint,
        constraint_type=record.constraint_info.type,
        is_security=bool(record.cve),
    )


def is_held_for_cooldown(entry: UpdateEntry, cooldown_period: int) -> bool:
    """A non-security recommendation whose target version is younger than the cooldown period.

    A backstop, not the primary enforcement: direct records are already settled by `select_target`
    (see apply_update_strategy), so this mostly catches transitive entries, whose recommendations
    come from the solver's *soft* freshness penalty and can still land on a fresh release.
    """
    if entry.is_forced or entry.is_security or entry.cooldown_bypassed:
        return False
    if entry.reason is None or entry.reason.age_days is None:
        return False
    return entry.reason.age_days < cooldown_period


def is_held_for_widening(entry: UpdateEntry, strategy: UpdateStrategy, *, rewrite_versions: bool = False) -> bool:
    """A recommendation reachable only by widening the declared constraint first, held back
    because the tier in force for this package does not reach that far.

    Held only when the tier's own MAX_REACH sits below the entry's rung — picking `latest` (whose
    MAX_REACH is already LATEST) *is* the authorization to widen, so nothing from that tier is
    ever held here. `--override` is explicit user intent (is_forced=True) and is never held here
    either — the user asked for exactly this version.

    `rewrite_versions` (`--rewrite-versions`) exempts `==x.y.z` pins for the same reason
    `--override` is exempt: widening those pins is the whole point of the flag, and holding them
    here made it a no-op. Mirrors clamp_recommendations' own rewrite_pinned skip, npm aliases
    included — their inner constraint can't be rewritten.
    """
    if entry.is_forced or not entry.widens_constraint or entry.from_rung is None:
        return False
    if (
        rewrite_versions
        and entry.constraint_type == ConstraintType.PINNED
        and not (entry.version_defined or "").startswith("npm:")
    ):
        return False
    return RUNG_ORDER[entry.from_rung] > RUNG_ORDER[MAX_REACH[strategy]]


def forced_entry_from_record(record: ScanRecord, forced_version: str, is_direct: bool) -> UpdateEntry:
    """Build an UpdateEntry for a --override forced version, bypassing solver output.

    Transitive entries are marked OVERRIDE so writers persist them (package.json `overrides` /
    [tool.uv] `override-dependencies`). No impact simulation is attached: compatibility of the
    forced version is deliberately unverified. widens_constraint and carries_known_break both stay
    False: --override is explicit user intent and is exempt from the acknowledgement prompt, same as
    it is exempt from is_held_for_widening.
    """
    if is_direct:
        constraint_type = record.constraint_info.type
    else:
        constraint_type = ConstraintType.OVERRIDE
    return UpdateEntry(
        package_name=record.package_name,
        dependency_name=record.dependency_name,
        current_version=record.installed_version,
        recommended_version=forced_version,
        is_direct=is_direct,
        reason=None,
        version_defined=record.version_constraint_declared or record.version_constraint,
        constraint_type=constraint_type,
        is_security=bool(record.cve),
        is_forced=True,
    )


def find_override_record(scan_result: ScanResult, name: str) -> ScanRecord | None:
    """Resolve a `--override` target to the record it names, or None when nothing matches.

    Accepts either spelling: the manifest key (`uuid-v7`, the only unambiguous way to name one of
    two npm aliases) or the registry name (`uuid`). The manifest key is tried first, so a project
    declaring both `uuid` and `uuid-v7` can address each of them.

    Every caller that acts on a `--override` name must resolve it through this function, including
    those that only want the registry name: `--override uuid-v11==14.0.2` used to be accepted by
    the plan and then crash a sibling validator that asked the registry for a package called
    `uuid-v11`.

    Args:
        scan_result: The scanned tree to resolve against.
        name: The package name as the user spelled it.

    Returns:
        The matching record, direct before transitive, or None.
    """
    direct = scan_result.production_packages + scan_result.optional_packages
    for record in direct:
        if record.dependency_name == name:
            return record
    for pool in (direct, scan_result.transitive_packages):
        for record in pool:
            if record.package_name == name:
                return record
    return None


def override_alias_siblings(scan_result: ScanResult, name: str) -> list[str]:
    """Manifest keys sharing the registry name *name*, when more than one direct record does.

    `--override uuid==14.0.2` on a project declaring both `uuid-v7` and `uuid-v11` names two
    installed copies and can only be applied to one of them. The caller reports the alternatives
    rather than picking silently.
    """
    keys = sorted(
        {
            record.identity_name
            for record in scan_result.production_packages + scan_result.optional_packages
            if record.package_name == name
        }
    )
    return keys if len(keys) > 1 else []


def build_update_plan(
    scan_result: ScanResult,
    package_manager_name: str,
    pin_all: bool = False,
    cooldown_period: int = 0,
    strategy: StrategyPlan | None = None,
    forced_overrides: dict[str, str] | None = None,
    rewrite_versions: bool = False,
) -> UpdatePlan:
    """Filter scan results to packages with solver recommendations that differ from installed.

    Recommendations whose target version is younger than cooldown_period days are withheld into
    held_for_cooldown (unless they fix a CVE), so a freshly published version is never applied.
    Direct records that `apply_update_strategy` already left without a recommendation for that same
    reason are listed there too, rebuilt by cooldown_entry_from_record — the plan has to name them
    even though they carry no target.
    Which packages carry a recommendation at all was already decided upstream, by
    service.project.strategy.apply_update_strategy against `strategy` — this function no longer
    filters by motive itself, only by widening authorization and cooldown.
    forced_overrides ({package: version} from --override) replace any solver recommendation for
    those packages, bypassing the strategy and the cooldown hold; targets absent from the
    dependency tree are collected into unknown_override_packages for the caller to report.
    rewrite_versions (--rewrite-versions) lets `==x.y.z` pins through the widening hold — see
    is_held_for_widening.
    """
    plan = strategy or StrategyPlan(default=DEFAULT_STRATEGY)
    all_records = scan_result.production_packages + scan_result.optional_packages + scan_result.transitive_packages
    installed_versions = {r.package_name: r.installed_version for r in all_records}
    all_direct_names = {r.package_name for r in scan_result.production_packages + scan_result.optional_packages}
    direct_records = scan_result.production_packages + scan_result.optional_packages
    direct = [
        entry_from_record(r, is_direct=True)
        for r in direct_records
        if r.recommended_version and r.recommended_version != r.installed_version
    ]

    available_at_higher_tier: Counter[UpdateStrategy] = Counter(
        r.strategy_selection.available_at
        for r in direct_records
        if r.strategy_selection is not None and r.strategy_selection.available_at is not None
    )

    # The transitive solver uses current-lockfile constraints, so its recommendations may be
    # lower than what a recommended direct dep update will actually require. Impact simulation
    # (Pass 1.5b) computes the correct post-upgrade version for each affected transitive dep.
    # Example: solver says modelsearch 1.2.2, but wagtail 7.4 requires >=1.3,<1.4 → use 1.3.1.
    impact_versions: dict[str, str] = {}
    for record in direct_records:
        for impact in record.update_transitive_impacts:
            if impact.projected_version and not impact.has_conflict:
                impact_versions[impact.package_name] = impact.projected_version

    def with_impact_version(entry: UpdateEntry) -> UpdateEntry:
        impact = impact_versions.get(entry.package_name)
        if impact and impact != entry.recommended_version:
            return dataclasses.replace(entry, recommended_version=impact)
        return entry

    transitive = sorted(
        {
            r.package_name: with_impact_version(entry_from_record(r, is_direct=False))
            for r in scan_result.transitive_packages
            if r.recommended_version
            and r.recommended_version != r.installed_version
            and r.package_name not in all_direct_names
        }.values(),
        key=lambda e: e.package_name,
    )

    unknown_overrides: list[str] = []
    forced_names = set(forced_overrides or {})
    if forced_overrides:
        direct_identities = {r.identity_name for r in direct_records}
        # Drop by whichever spelling the user used: naming an alias replaces only that alias,
        # naming the registry name replaces every entry carrying it.
        direct = [e for e in direct if e.identity not in forced_names and e.package_name not in forced_names]
        transitive = [e for e in transitive if e.package_name not in forced_names]
        for name, version in forced_overrides.items():
            record = find_override_record(scan_result, name)
            if record is None:
                unknown_overrides.append(name)
                continue
            if version == record.installed_version:
                continue
            is_direct = record.identity_name in direct_identities
            entry = forced_entry_from_record(record, version, is_direct)
            if is_direct:
                direct.append(entry)
            else:
                transitive.append(entry)
        transitive.sort(key=lambda e: e.package_name)

    # Widening entries never reach the writers: whether they'd also be held for cooldown is moot,
    # so this must partition before the cooldown hold to avoid double-counting an entry in both.
    widening = sorted(
        [
            e
            for e in direct + transitive
            if is_held_for_widening(e, plan.for_package(e.package_name), rewrite_versions=rewrite_versions)
        ],
        key=lambda e: e.package_name,
    )
    # Subtract by identity, not by registry name: two npm aliases of one package share a
    # package_name, so holding `uuid-v7` for widening used to drop `uuid-v11` from the plan
    # entirely — including its ESM-break acknowledgement prompt.
    widening_ids = {e.identity for e in widening}
    direct = [e for e in direct if e.identity not in widening_ids]
    transitive = [e for e in transitive if e.identity not in widening_ids]

    # Two sources, one list: entries that carry a fresh recommendation (transitive picks from the
    # solver's soft penalty), and direct records select_target left with no recommendation at all
    # because everything reachable was fresh — those never became entries, and would otherwise
    # vanish from the plan without a word.
    cooldown_blanked = [
        cooldown_entry_from_record(r, r.strategy_selection.cooldown_hold)
        for r in direct_records
        if r.strategy_selection is not None
        and r.strategy_selection.cooldown_hold is not None
        and r.package_name not in forced_names
        and r.identity_name not in forced_names
    ]
    held = sorted(
        [e for e in direct + transitive if is_held_for_cooldown(e, cooldown_period)] + cooldown_blanked,
        key=lambda e: e.package_name,
    )
    held_ids = {e.identity for e in held}
    direct = [e for e in direct if e.identity not in held_ids]
    transitive = [e for e in transitive if e.identity not in held_ids]

    return UpdatePlan(
        project_name=scan_result.project_name,
        project_path=scan_result.project_path,
        registry_type=scan_result.packages_registry,
        package_manager_name=package_manager_name,
        direct_entries=direct,
        transitive_entries=transitive,
        pin_all=pin_all,
        installed_versions=installed_versions,
        held_for_cooldown=held,
        cooldown_period=cooldown_period,
        unknown_override_packages=tuple(unknown_overrides),
        held_for_widening=widening,
        strategy=plan.default,
        strategy_overrides=dict(plan.overrides),
        available_at_higher_tier=dict(available_at_higher_tier),
    )
