from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from functools import cmp_to_key
from typing import Protocol

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource
from ossiq.timeutil import age_days_from_iso
from ossiq.unit_of_work.solver.problem import CandidateVersion, PackageConstraint, SolverProblem

# Priority for deduplication when multiple descriptors share the same canonical_name.
# Higher value wins. Mirrors the docstring ordering in domain/common.py.
_CONSTRAINT_PRIORITY: dict[ConstraintType, int] = {
    ConstraintType.DECLARED: 0,
    ConstraintType.NARROWED: 1,
    ConstraintType.PINNED: 2,
    ConstraintType.ADDITIVE: 3,
    ConstraintType.OVERRIDE: 4,
}


class _DepLike(Protocol):
    """Structural interface satisfied by DependencyDescriptor (service/project.py).

    Using a Protocol avoids the import cycle: service/ already imports unit_of_work/.
    Phase 4 should move DependencyDescriptor to domain/ and replace this Protocol.
    """

    canonical_name: str
    version: str
    version_constraint: str | None
    constraint_info: ConstraintSource


class SolvablePool:
    """Builds a SolverProblem from dependency descriptors and a warm registry cache."""

    @classmethod
    def build(
        cls,
        deps: Sequence[_DepLike],
        registry: AbstractPackageRegistryApi,
        engine_context: dict[str, str],
        *,
        allow_prerelease: bool = False,
        _now: datetime | None = None,
    ) -> SolverProblem:
        """Build a SolverProblem from the given dependencies and registry.

        The registry cache is expected to be warm from the preceding scan pass,
        so package_versions() calls will not trigger additional HTTP requests.

        Args:
            deps: Flat sequence of dependency descriptors (direct + transitive).
            registry: Registry instance with warm cache from the scan pass.
            engine_context: Project engine versions, e.g. {"python": "3.11.9"}.
            allow_prerelease: When True, include pre-release candidates.
            _now: Injectable reference time for deterministic age computation in tests.
        """
        # 1. Deduplicate by canonical_name — highest constraint priority wins.
        # TODO: When two descriptors share the same type, resolve by specifier
        #       narrowness rather than insertion order.
        best: dict[str, _DepLike] = {}
        for dep in deps:
            existing = best.get(dep.canonical_name)
            if existing is None:
                best[dep.canonical_name] = dep
            elif _CONSTRAINT_PRIORITY[dep.constraint_info.type] > _CONSTRAINT_PRIORITY[existing.constraint_info.type]:
                best[dep.canonical_name] = dep

        # 2. Build PackageConstraints from winning descriptors.
        constraints = tuple(
            PackageConstraint(
                package_name=dep.canonical_name,
                version_constraint=dep.version_constraint,
                constraint_type=dep.constraint_info.type,
                installed_version=dep.version,
            )
            for dep in best.values()
        )

        # 3. Build CandidateVersion lists per package.
        candidates: dict[str, tuple[CandidateVersion, ...]] = {}
        for canonical_name in best:
            raw = list(registry.package_versions(canonical_name))

            filtered = [
                pv
                for pv in raw
                if not pv.is_yanked and not pv.is_unpublished and (allow_prerelease or not pv.is_prerelease)
            ]

            # Sort descending: b before a in comparator → newest first.
            sorted_pvs = sorted(
                filtered,
                key=cmp_to_key(lambda a, b: registry.compare_versions(b.version, a.version)),
            )

            candidates[canonical_name] = tuple(
                CandidateVersion(
                    version=pv.version,
                    age_days=age_days_from_iso(pv.published_date_iso, now=_now),
                    is_deprecated=pv.is_deprecated,
                    is_prerelease=pv.is_prerelease,
                    is_yanked=pv.is_yanked,
                    runtime_requirements=pv.runtime_requirements,
                )
                for pv in sorted_pvs
            )

        return SolverProblem(
            constraints=constraints,
            candidates=candidates,
            engine_context=dict(engine_context),
        )
