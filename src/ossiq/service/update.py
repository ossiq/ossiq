"""Update plan service: builds an atomic update plan from solver-enriched scan results."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field

from ossiq.domain.common import ConstraintType
from ossiq.service.project import ScanRecord, ScanResult
from ossiq.service.update_impact import TransitiveImpact
from ossiq.solver.reason import RecommendationReason


@dataclass(frozen=True)
class UpdateEntry:
    """A single package recommended for update by the solver."""

    package_name: str
    current_version: str
    recommended_version: str
    is_direct: bool
    reason: RecommendationReason | None
    transitive_impacts: list[TransitiveImpact] = field(default_factory=list)
    # False when transitive conflicts exist and no conflict-free candidate was found.
    is_actionable: bool = True
    version_defined: str | None = None
    constraint_type: ConstraintType = ConstraintType.DECLARED
    # True when the installed version carries a CVE — exempts the entry from the cooldown hold.
    is_security: bool = False
    # True when the version was forced via --override — bypasses the solver and the cooldown.
    is_forced: bool = False


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

    @property
    def all_entries(self) -> list[UpdateEntry]:
        return self.direct_entries + self.transitive_entries


def entry_from_record(record: ScanRecord, is_direct: bool) -> UpdateEntry:
    """Build an UpdateEntry from a ScanRecord that has a solver recommendation."""
    assert record.recommended_version is not None
    return UpdateEntry(
        package_name=record.package_name,
        current_version=record.installed_version,
        recommended_version=record.recommended_version,
        is_direct=is_direct,
        reason=record.recommended_version_reason,
        transitive_impacts=list(record.update_transitive_impacts),
        is_actionable=all(not i.has_conflict for i in record.update_transitive_impacts),
        version_defined=record.version_constraint,
        constraint_type=record.constraint_info.type,
        is_security=bool(record.cve),
    )


def is_held_for_cooldown(entry: UpdateEntry, cooldown_period: int) -> bool:
    """A non-security recommendation whose target version is younger than the cooldown period."""
    if entry.is_forced or entry.is_security or entry.reason is None or entry.reason.age_days is None:
        return False
    return entry.reason.age_days < cooldown_period


def forced_entry_from_record(record: ScanRecord, forced_version: str, is_direct: bool) -> UpdateEntry:
    """Build an UpdateEntry for a --override forced version, bypassing solver output.

    Transitive entries are marked OVERRIDE so writers persist them (package.json `overrides` /
    [tool.uv] `override-dependencies`). No impact simulation is attached: compatibility of the
    forced version is deliberately unverified.
    """
    if is_direct:
        constraint_type = record.constraint_info.type
    else:
        constraint_type = ConstraintType.OVERRIDE
    return UpdateEntry(
        package_name=record.package_name,
        current_version=record.installed_version,
        recommended_version=forced_version,
        is_direct=is_direct,
        reason=None,
        version_defined=record.version_constraint,
        constraint_type=constraint_type,
        is_security=bool(record.cve),
        is_forced=True,
    )


def build_update_plan(
    scan_result: ScanResult,
    package_manager_name: str,
    pin_all: bool = False,
    cooldown_period: int = 0,
    security_only: bool = False,
    forced_overrides: dict[str, str] | None = None,
) -> UpdatePlan:
    """Filter scan results to packages with solver recommendations that differ from installed.

    Recommendations whose target version is younger than cooldown_period days are withheld into
    held_for_cooldown (unless they fix a CVE), so a freshly published version is never applied.
    With security_only, the plan keeps only CVE-affected packages — direct and transitive alike.
    forced_overrides ({package: version} from --override) replace any solver recommendation for
    those packages, bypass the security filter and the cooldown hold; targets absent from the
    dependency tree are collected into unknown_override_packages for the caller to report.
    """
    all_records = scan_result.production_packages + scan_result.optional_packages + scan_result.transitive_packages
    installed_versions = {r.package_name: r.installed_version for r in all_records}
    all_direct_names = {r.package_name for r in scan_result.production_packages + scan_result.optional_packages}
    direct = [
        entry_from_record(r, is_direct=True)
        for r in scan_result.production_packages + scan_result.optional_packages
        if r.recommended_version and r.recommended_version != r.installed_version
    ]

    # The transitive solver uses current-lockfile constraints, so its recommendations may be
    # lower than what a recommended direct dep update will actually require. Impact simulation
    # (Pass 1.5b) computes the correct post-upgrade version for each affected transitive dep.
    # Example: solver says modelsearch 1.2.2, but wagtail 7.4 requires >=1.3,<1.4 → use 1.3.1.
    impact_versions: dict[str, str] = {}
    for record in scan_result.production_packages + scan_result.optional_packages:
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

    if security_only:
        direct = [e for e in direct if e.is_security]
        transitive = [e for e in transitive if e.is_security]

    unknown_overrides: list[str] = []
    if forced_overrides:
        direct_records = {r.package_name: r for r in scan_result.production_packages + scan_result.optional_packages}
        transitive_records = {r.package_name: r for r in scan_result.transitive_packages}
        forced_names = set(forced_overrides)
        direct = [e for e in direct if e.package_name not in forced_names]
        transitive = [e for e in transitive if e.package_name not in forced_names]
        for name, version in forced_overrides.items():
            is_direct = name in direct_records
            record = direct_records.get(name) or transitive_records.get(name)
            if record is None:
                unknown_overrides.append(name)
                continue
            if version == record.installed_version:
                continue
            entry = forced_entry_from_record(record, version, is_direct)
            if is_direct:
                direct.append(entry)
            else:
                transitive.append(entry)
        transitive.sort(key=lambda e: e.package_name)

    held = sorted(
        [e for e in direct + transitive if is_held_for_cooldown(e, cooldown_period)],
        key=lambda e: e.package_name,
    )
    held_names = {e.package_name for e in held}
    direct = [e for e in direct if e.package_name not in held_names]
    transitive = [e for e in transitive if e.package_name not in held_names]

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
    )
