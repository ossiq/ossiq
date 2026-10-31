"""Build UpdateEntry values from scan records, forced versions and override moves."""

from __future__ import annotations

import dataclasses

from ossiq.domain.common import WIDENING_RUNGS, ConstraintType, CooldownHold
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.service.update.models import UpdateEntry
from ossiq.service.update_impact import ImpactKind, TransitiveImpact
from ossiq.solver.reason import RecommendationReason
from ossiq.solver.version_matchers import parse_npm_version


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
        # The root manifest's own spec, not version_constraint's last-writer-wins value: the uv writer
        # rewrites this exact string into pyproject.toml (api_uv.resolve_direct_specifier). Transitive-only
        # records fall back to version_constraint.
        version_defined=record.version_constraint_declared or record.version_constraint,
        constraint_type=record.constraint_info.type,
        is_security=bool(record.cve),
        from_rung=record.recommended_from_rung,
        widens_constraint=record.recommended_from_rung in WIDENING_RUNGS,
        carries_known_break=record.compatibility.breaking_change is not None,
        cooldown_bypassed=record.strategy_selection is not None and record.strategy_selection.cooldown_bypassed,
        widening_authorized=record.strategy_selection is not None and record.strategy_selection.widening_authorized,
    )


def cooldown_entry_from_record(record: ScanRecord, hold: CooldownHold) -> UpdateEntry:
    """Build a display-only entry for a record that the cooldown left without a recommendation.

    `apply_update_strategy` blanks `recommended_version` when every reachable release is younger than
    the cooldown or past the package manager's release cutoff, so the record can't become a real
    `UpdateEntry`. This rebuilds enough of one to list it under "held for cooldown"; it never enters
    direct_entries or transitive_entries, so nothing writes it.
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
        held_by=hold.enforced_by,
        held_cutoff=hold.cutoff,
    )


def forced_entry_from_record(record: ScanRecord, forced_version: str, is_direct: bool) -> UpdateEntry:
    """Build an UpdateEntry for a --override version, bypassing solver output.

    Transitive entries are marked OVERRIDE so writers persist them (package.json `overrides`,
    [tool.uv] `override-dependencies`). No impact simulation is attached, so the forced version's
    compatibility goes unverified. `widens_constraint` and `carries_known_break` stay False:
    `--override` is explicit intent, exempt from the acknowledgement prompt as it is from
    is_held_for_widening.
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


def override_bump_entry(impact: TransitiveImpact) -> UpdateEntry:
    """Build a transitive entry, written as an override, for a copy that has to move with a candidate.

    It is derived from the candidate, not forced, so it is exempt from nothing. It is keyed to the range
    from the copy's version to the target, not to the copy's version alone: npm applies a keyed rule only
    to edges whose range overlaps the key, and in a family that moves together every edge into the copy
    may come from a member that already asks for the new version. A rule keyed to the old version alone
    would then match nothing, and npm would nest new copies beside the old one (@vue/reactivity under
    runtime-core and runtime-dom), which breaks type identity across the family.
    """
    assert impact.current_version is not None and impact.projected_version is not None
    try:
        low, high = sorted((impact.current_version, impact.projected_version), key=parse_npm_version)
    except ValueError:
        low, high = impact.current_version, impact.projected_version
    return UpdateEntry(
        package_name=impact.package_name,
        current_version=impact.current_version,
        recommended_version=impact.projected_version,
        is_direct=False,
        reason=None,
        constraint_type=ConstraintType.OVERRIDE,
        override_key=f"{low} - {high}" if low != high else None,
    )


def transitive_entries_for(scan_result: ScanResult, direct_records: list[ScanRecord]) -> list[UpdateEntry]:
    """Build the transitive entries: the solver's picks plus the override moves that ride along with updates.

    Packages the project declares directly are excluded; they get their own entries. The result is sorted
    by package name, then installed version.
    """
    direct_names = {r.package_name for r in direct_records}

    # The transitive solver works from the current lockfile, so its picks can sit below what a recommended
    # direct update will require. Impact simulation computes the post-upgrade version per affected
    # transitive dependency instead: the solver says modelsearch 1.2.2, but wagtail 7.4 needs >=1.3,<1.4,
    # so the plan uses 1.3.1.
    # Keyed by copy, not by name: a tree with nested copies can need one override per copy.
    impact_versions: dict[tuple[str, str | None], str] = {}
    override_bumps: dict[tuple[str, str | None], TransitiveImpact] = {}
    for record in direct_records:
        for impact in record.update_transitive_impacts:
            # A further copy leaves the version the solver picked for the installed one alone.
            if impact.kind == ImpactKind.NEW_COPY:
                continue
            if impact.projected_version and not impact.has_conflict:
                impact_versions[(impact.package_name, impact.current_version)] = impact.projected_version
                if impact.kind == ImpactKind.OVERRIDE_BUMP:
                    override_bumps[(impact.package_name, impact.current_version)] = impact
    # A transitive pick drags its own family along the same way a direct update does.
    for record in scan_result.transitive_packages:
        for impact in record.update_transitive_impacts:
            if impact.kind == ImpactKind.OVERRIDE_BUMP and impact.projected_version and not impact.has_conflict:
                override_bumps.setdefault((impact.package_name, impact.current_version), impact)

    def with_impact_version(entry: UpdateEntry) -> UpdateEntry:
        impact = impact_versions.get((entry.package_name, entry.current_version))
        if impact and impact != entry.recommended_version:
            return dataclasses.replace(entry, recommended_version=impact)
        return entry

    transitive = sorted(
        {
            r.package_name: with_impact_version(entry_from_record(r, is_direct=False))
            for r in scan_result.transitive_packages
            if r.recommended_version
            and r.recommended_version != r.installed_version
            and r.package_name not in direct_names
        }.values(),
        key=lambda e: e.package_name,
    )

    # A copy that moves with the candidate needs an override even when the transitive solver had no pick
    # for it.
    solved_copies = {(e.package_name, e.current_version) for e in transitive}
    transitive = sorted(
        [
            *transitive,
            *(
                override_bump_entry(impact)
                for (name, version), impact in override_bumps.items()
                if (name, version) not in solved_copies and name not in direct_names
            ),
        ],
        key=lambda e: (e.package_name, e.current_version),
    )

    # A peer repair's family moves are keyed overrides like any other family move; the package it
    # puts back in reach is added to the manifest by the writer, from plan.peer_repairs.
    known_copies = {(e.package_name, e.current_version) for e in transitive}
    repair_moves = {
        (move.package_name, move.current_version): move
        for repair in scan_result.peer_repairs
        for move in repair.family_moves
        if (move.package_name, move.current_version) not in known_copies and move.package_name not in direct_names
    }
    return sorted(
        [*transitive, *(override_bump_entry(move) for move in repair_moves.values())],
        key=lambda e: (e.package_name, e.current_version),
    )
