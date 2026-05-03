"""HPDR solver adapter: chains SolvablePool → ConstraintEncoder → HPDRKernel."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.project import ConstraintSource
from ossiq.unit_of_work.solver.driver import ConflictSet
from ossiq.unit_of_work.solver.driver_pysat import PySATDriver
from ossiq.unit_of_work.solver.encoder import ConstraintEncoder
from ossiq.unit_of_work.solver.kernel import HPDRKernel
from ossiq.unit_of_work.solver.universe import SolvablePool
from ossiq.unit_of_work.solver.weights import VERY_FRESH_THRESHOLD_DAYS

logger = logging.getLogger(__name__)


def solve_direct(
    deps: Sequence,
    registry: AbstractPackageRegistryApi,
    engine_context: dict[str, str],
    *,
    allow_prerelease: bool = False,
) -> dict[str, str]:
    """Run HPDR solver over direct dependencies.

    Args:
        deps: Direct dependency descriptors satisfying the _DepLike Protocol
              (canonical_name, version, version_constraint, constraint_info).
        registry: Registry instance with warm cache from the preceding scan pass.
        engine_context: Project engine versions for L2 clause generation.
                        Pass {} in Phase 4 — populating from project metadata is Phase 5+.
        allow_prerelease: When True, include pre-release candidates.

    Returns:
        Mapping of canonical_name → recommended version string.
        Returns {} when the solver cannot select any version or when deps is empty.
    """
    if not deps:
        return {}

    problem = SolvablePool.build(deps, registry, engine_context, allow_prerelease=allow_prerelease)
    encoded = ConstraintEncoder().encode(problem)
    result = HPDRKernel(PySATDriver()).solve(encoded)

    if isinstance(result, ConflictSet):
        logger.debug("HPDR solver returned ConflictSet: %s", result.unsatisfied_clauses)
        return {}

    return dict(result.selected)


class _TransitiveDepLike(Protocol):
    """Structural subset of ScanRecord required for transitive solving.

    Using a Protocol avoids the import cycle: service/ already imports unit_of_work/.
    """

    package_name: str
    installed_version: str
    version_constraint: str | None
    constraint_info: ConstraintSource
    cve: list[Any]  # list[CVE] — only .affected_versions accessed
    version_age_days: int | None


@dataclass(frozen=True)
class _TransitiveDep:
    """Minimal _DepLike adapter built from a transitive ScanRecord."""

    canonical_name: str
    version: str
    version_constraint: str | None
    constraint_info: ConstraintSource


def solve_transitive(
    transitive_records: Sequence[Any],
    registry: AbstractPackageRegistryApi,
    engine_context: dict[str, str],
    *,
    allow_prerelease: bool = False,
) -> dict[str, str]:
    """Run HPDR solver over flagged transitive dependencies.

    Flagged = installed version has ≥1 CVE or version_age_days < VERY_FRESH_THRESHOLD_DAYS.
    CVE-affected candidate versions receive L5 hard-forbidden clauses.
    Candidate versions < VERY_FRESH_THRESHOLD_DAYS old receive L6 (1M) soft penalty.

    Args:
        transitive_records: Sequence satisfying _TransitiveDepLike (i.e. ScanRecord objects).
        registry: Registry instance with warm cache from the preceding scan pass.
        engine_context: Project engine versions. Pass {} — populating deferred to Phase 6+.
        allow_prerelease: When True, include pre-release candidates.

    Returns:
        Mapping of canonical_name → recommended version string.
        Returns {} when no flagged records exist, deps is empty, or solver conflicts.
    """
    # 1. Filter to flagged records only (CVE or very fresh installed version).
    flagged = [
        r
        for r in transitive_records
        if r.cve or (r.version_age_days is not None and r.version_age_days < VERY_FRESH_THRESHOLD_DAYS)
    ]
    if not flagged:
        return {}

    # 2. Deduplicate by package_name — keep first occurrence (same as direct pass).
    seen: set[str] = set()
    unique_flagged: list[Any] = []
    for r in flagged:
        if r.package_name not in seen:
            seen.add(r.package_name)
            unique_flagged.append(r)

    # 3. Build CVE-affected-versions map: {canonical_name: {version, ...}}.
    cve_affected: dict[str, set[str]] = {}
    for r in unique_flagged:
        for cve in r.cve:
            cve_affected.setdefault(r.package_name, set()).update(cve.affected_versions)

    # 4. Convert to _DepLike-compatible adapters.
    deps: list[_TransitiveDep] = [
        _TransitiveDep(
            canonical_name=r.package_name,
            version=r.installed_version,
            version_constraint=r.version_constraint,
            constraint_info=r.constraint_info,
        )
        for r in unique_flagged
    ]

    # 5. Build → encode → solve.
    problem = SolvablePool.build(
        deps,
        registry,
        engine_context,
        cve_affected=cve_affected,
        allow_prerelease=allow_prerelease,
    )
    encoded = ConstraintEncoder(penalize_fresh_days=VERY_FRESH_THRESHOLD_DAYS).encode(problem)
    result = HPDRKernel(PySATDriver()).solve(encoded)

    if isinstance(result, ConflictSet):
        logger.debug("HPDR transitive solver returned ConflictSet: %s", result.unsatisfied_clauses)
        return {}

    return dict(result.selected)
