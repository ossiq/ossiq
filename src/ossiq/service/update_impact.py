"""Impact simulation service: projects transitive dependency changes from direct package updates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.unit_of_work.solver.version_matchers import satisfies_all_constraints, version_satisfies_constraint

if TYPE_CHECKING:
    from ossiq.service.project import ScanRecord


@dataclass(frozen=True)
class TransitiveImpact:
    """Impact on a single transitive dependency caused by a direct package update."""

    package_name: str
    # None means this is a brand-new transitive dep not currently in the tree.
    current_version: str | None
    # None means no version satisfies all merged constraints (hard conflict).
    projected_version: str | None
    # Constraint the updated direct dep imposes on this transitive dep.
    new_constraint: str
    # Canonical name of the direct dep recommendation driving this impact.
    driven_by: str
    # True when projected_version violates an existing parent constraint (multi-parent diamond).
    has_conflict: bool
    conflict_detail: str | None


@dataclass(frozen=True)
class DirectUpdateImpact:
    """Aggregated transitive impact of updating a single direct dependency."""

    package_name: str
    recommended_version: str
    transitive_impacts: list[TransitiveImpact]
    # False if any existing transitive dep cannot be resolved without a constraint violation.
    is_actionable: bool
    # Populated by Phase 4c fallback logic when the recommended_version is not actionable.
    fallback_version: str | None


def find_best_satisfying_version(
    package_name: str,
    constraints: list[str],
    registry: AbstractPackageRegistryApi,
    allow_prerelease: bool = False,
) -> str | None:
    """Return the newest version of package_name satisfying all constraints.

    Uses registry.package_versions() which is cache-warm after the scan pass — no
    network calls expected. Skips yanked, unpublished, and (by default) prerelease
    versions, matching the hard-filter behaviour of SolvablePool.build().

    Deliberately avoids the SAT solver: we only need hard constraint satisfaction
    (L1 logic), not weighted soft penalties.
    """
    filtered = (
        pv
        for pv in registry.package_versions(package_name)
        if not pv.is_yanked
        and not pv.is_unpublished
        and (allow_prerelease or not pv.is_prerelease)
        and satisfies_all_constraints(pv.version, constraints)
    )
    best = registry.newest_version(filtered)
    return best.version if best else None


def assess_transitive_impact(
    dep_name: str,
    new_constraint: str,
    driven_by: str,
    transitive_by_name: dict[str, ScanRecord],
    registry: AbstractPackageRegistryApi,
    allow_prerelease: bool = False,
    installed_names: set[str] | None = None,
) -> TransitiveImpact | None:
    """Assess whether a new constraint on dep_name creates an impact.

    Returns None when the installed version already satisfies the new constraint,
    or when the package is already installed (present in installed_names) but outside
    the production-path scan scope (e.g. a transitive dep of a dev package).
    Returns TransitiveImpact with current_version=None for brand-new transitive deps.
    Returns TransitiveImpact with has_conflict=True when no version satisfies all constraints.
    """
    record = transitive_by_name.get(dep_name)

    if record is None:
        if installed_names and dep_name in installed_names:
            return None
        return TransitiveImpact(
            package_name=dep_name,
            current_version=None,
            projected_version=None,
            new_constraint=new_constraint,
            driven_by=driven_by,
            has_conflict=False,
            conflict_detail=None,
        )

    if version_satisfies_constraint(record.installed_version, new_constraint):
        return None

    merged_constraints = list(record.all_constraints) + [new_constraint]
    projected = find_best_satisfying_version(dep_name, merged_constraints, registry, allow_prerelease)

    if projected is None:
        return TransitiveImpact(
            package_name=dep_name,
            current_version=record.installed_version,
            projected_version=None,
            new_constraint=new_constraint,
            driven_by=driven_by,
            has_conflict=True,
            conflict_detail=f"no version satisfies: {', '.join(merged_constraints)}",
        )

    violating = [c for c in record.all_constraints if not version_satisfies_constraint(projected, c)]
    return TransitiveImpact(
        package_name=dep_name,
        current_version=record.installed_version,
        projected_version=projected,
        new_constraint=new_constraint,
        driven_by=driven_by,
        has_conflict=bool(violating),
        conflict_detail=f"{projected} violates: {', '.join(violating)}" if violating else None,
    )


def simulate_single(
    package_name: str,
    candidate_version: str,
    transitive_by_name: dict[str, ScanRecord],
    registry: AbstractPackageRegistryApi,
    allow_prerelease: bool = False,
    installed_names: set[str] | None = None,
) -> DirectUpdateImpact:
    """Simulate the transitive impact of updating package_name to candidate_version.

    This is the hot path for Phase 4c's post_solve_validator — registry is cache-warm,
    no network calls expected, no SAT solver invocation.
    """
    new_requires = registry.package_version_requires(package_name, candidate_version)

    impacts: list[TransitiveImpact] = []
    for dep_name, constraint in new_requires.items():
        impact = assess_transitive_impact(
            dep_name, constraint, package_name, transitive_by_name, registry, allow_prerelease, installed_names
        )
        if impact is not None:
            impacts.append(impact)

    # New transitive deps (current_version=None) are informational — they do not block actionability.
    is_actionable = all(
        not i.has_conflict and i.projected_version is not None for i in impacts if i.current_version is not None
    )
    return DirectUpdateImpact(
        package_name=package_name,
        recommended_version=candidate_version,
        transitive_impacts=impacts,
        is_actionable=is_actionable,
        fallback_version=None,
    )


def simulate_update_impacts(
    recommendations: dict[str, str],
    transitive_records: list[ScanRecord],
    registry: AbstractPackageRegistryApi,
    allow_prerelease: bool = False,
    installed_names: set[str] | None = None,
) -> dict[str, DirectUpdateImpact]:
    """Simulate transitive impacts for all recommended direct dep updates.

    recommendations: {canonical_package_name: recommended_version} from the solver
    transitive_records: all transitive ScanRecords from the scan (all_constraints populated)
    installed_names: complete set of canonical package names currently installed in the project
        (including transitive deps of dev packages). When provided, packages present here are
        not flagged as new transitive deps even if absent from the scan's transitive_records.

    Keys in the returned dict match the keys of recommendations.
    """
    transitive_by_name = {r.package_name: r for r in transitive_records}
    return {
        pkg: simulate_single(pkg, ver, transitive_by_name, registry, allow_prerelease, installed_names)
        for pkg, ver in recommendations.items()
    }
