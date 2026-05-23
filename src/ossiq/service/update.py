"""Update plan service: builds an atomic update plan from solver-enriched scan results."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field

from ossiq.domain.common import ConstraintType
from ossiq.service.project import ScanRecord, ScanResult
from ossiq.service.update_impact import TransitiveImpact
from ossiq.unit_of_work.solver.reason import RecommendationReason


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
    rewrite_versions: bool = False
    installed_versions: dict[str, str] = field(default_factory=dict)

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
    )


def build_update_plan(
    scan_result: ScanResult,
    package_manager_name: str,
    pin_all: bool = False,
    rewrite_versions: bool = False,
) -> UpdatePlan:
    """Filter scan results to packages with solver recommendations that differ from installed.

    PINNED (==x.y.z) direct entries are excluded unless rewrite_versions=True.
    """
    all_records = scan_result.production_packages + scan_result.optional_packages + scan_result.transitive_packages
    installed_versions = {r.package_name: r.installed_version for r in all_records}
    all_direct_names = {r.package_name for r in scan_result.production_packages + scan_result.optional_packages}
    direct = [
        entry_from_record(r, is_direct=True)
        for r in scan_result.production_packages + scan_result.optional_packages
        if r.recommended_version
        and r.recommended_version != r.installed_version
        and (rewrite_versions or r.constraint_info.type != ConstraintType.PINNED)
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
    return UpdatePlan(
        project_name=scan_result.project_name,
        project_path=scan_result.project_path,
        registry_type=scan_result.packages_registry,
        package_manager_name=package_manager_name,
        direct_entries=direct,
        transitive_entries=transitive,
        pin_all=pin_all,
        rewrite_versions=rewrite_versions,
        installed_versions=installed_versions,
    )
