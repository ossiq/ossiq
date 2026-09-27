"""The single writer of the target half of a ScanRecord's CompatibilityFacts.

`recommended_module_system`, `breaking_change`, `engine_requirement` and `engine_compatible` all
describe one thing: what is true about the version that was picked. The ladder half of the same
value object (`latest_in_range` and friends) is built once at construction, in
`service.project.records.scan_record`, and never touched here.

The target half is written from two places — `service.project.strategy.apply_update_strategy` for
direct records, `service.project.recommendations.apply_recommendations` for transitive ones — and
Architecture rule 5 says a derived field gets exactly one writer. That writer is here; the two call
sites decide *which* records to annotate, not *what* the annotation says.

Deliberately not in the cluster: which source the engine context came from. That is one fact about
the scan, not a fact about each record, and it lives on ScanResult.
"""

from ossiq.domain.common import EngineContext, ProjectPackagesRegistry
from ossiq.domain.version import PackageVersion
from ossiq.service.project.breaking_changes import module_system_label
from ossiq.service.project.models import ScanRecord
from ossiq.solver.version_matchers import engine_compatibility


def annotate_target_facts(
    record: ScanRecord,
    target_version: str,
    releases: list[PackageVersion],
    registry: ProjectPackagesRegistry,
    *,
    engine_context: EngineContext,
    project_declares_esm: bool,
) -> None:
    """Write what is true about *target_version* onto *record*, in place.

    Args:
        record: The record whose recommendation was just decided.
        target_version: The version that was picked.
        releases: Releases of this package, used to find *target_version*'s own metadata.
        registry: Which registry's version scheme applies.
        engine_context: The runtime versions this scan checked against, and where they came from.
            Only the versions matter here - the provenance is a scan-level fact and lives on
            ScanResult, not on every record.
        project_declares_esm: Whether the project itself is `"type": "module"`.
    """
    facts = record.compatibility
    facts.recommended_module_system, facts.breaking_change = module_system_label(
        record.package_name,
        record.installed_version,
        target_version,
        releases,
        registry,
        project_declares_esm,
    )
    picked = next((pv for pv in releases if pv.version == target_version), None)
    facts.engine_requirement = picked.runtime_requirements if picked else None
    facts.engine_compatible = engine_compatibility(facts.engine_requirement, engine_context.versions)


def clear_target_facts(record: ScanRecord) -> None:
    """Reset the cluster when a record ends up with no target at all.

    The counterpart to `annotate_target_facts`: leaving stale facts behind would describe a pick
    that no longer exists.
    """
    facts = record.compatibility
    facts.recommended_module_system = None
    facts.breaking_change = None
    facts.engine_requirement = None
    facts.engine_compatible = None
