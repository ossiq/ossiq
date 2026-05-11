"""Update plan service: builds an atomic update plan from solver-enriched scan results."""

from __future__ import annotations

from dataclasses import dataclass

from ossiq.service.project import ScanRecord, ScanResult
from ossiq.unit_of_work.solver.reason import RecommendationReason


@dataclass(frozen=True)
class UpdateEntry:
    """A single package recommended for update by the solver."""

    package_name: str
    current_version: str
    recommended_version: str
    is_direct: bool
    reason: RecommendationReason | None


@dataclass(frozen=True)
class UpdatePlan:
    """Atomic update plan derived from solver recommendations for a scanned project."""

    project_name: str
    project_path: str
    registry_type: str
    package_manager_name: str
    direct_entries: list[UpdateEntry]
    transitive_entries: list[UpdateEntry]

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
    )


def build_update_plan(scan_result: ScanResult, package_manager_name: str) -> UpdatePlan:
    """Filter scan results to packages with solver recommendations that differ from installed."""
    direct = [
        entry_from_record(r, is_direct=True)
        for r in scan_result.production_packages + scan_result.optional_packages
        if r.recommended_version and r.recommended_version != r.installed_version
    ]
    transitive = [
        entry_from_record(r, is_direct=False)
        for r in scan_result.transitive_packages
        if r.recommended_version and r.recommended_version != r.installed_version
    ]
    return UpdatePlan(
        project_name=scan_result.project_name,
        project_path=scan_result.project_path,
        registry_type=scan_result.packages_registry,
        package_manager_name=package_manager_name,
        direct_entries=direct,
        transitive_entries=transitive,
    )
