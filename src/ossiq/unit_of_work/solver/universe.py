from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from functools import cmp_to_key
from typing import Protocol

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource
from ossiq.timeutil import age_days_from_iso
from ossiq.unit_of_work.solver.problem import CandidateVersion, PackageConstraint, SolverProblem

CANDIDATE_CAP: int = 30
_UNCONSTRAINED_VALUES: frozenset[str] = frozenset({"*", "latest", ""})

# Priority for deduplication when multiple descriptors share the same canonical_name.
# Higher value wins. Mirrors the docstring ordering in domain/common.py.
_CONSTRAINT_PRIORITY: dict[ConstraintType, int] = {
    ConstraintType.DECLARED: 0,
    ConstraintType.NARROWED: 1,
    ConstraintType.PINNED: 2,
    ConstraintType.ADDITIVE: 3,
    ConstraintType.OVERRIDE: 4,
}


def parse_requires(declared: dict[str, str]) -> dict[str, str | None]:
    """Parse declared_dependencies into a {canonical_pkg_name: constraint_or_None} mapping.

    Handles two formats used by registry adapters:

    npm format: key = package name, value = version constraint string.
        e.g. {"thinc": ">=8.1.8,<8.4.0", "numpy": ">=1.19.0", "attrs": "*"}

    PyPI format: key = PEP 508 dependency string, value = empty string.
        e.g. {"thinc>=8.1.8,<8.4.0": "", "numpy>=1.19.0; python_version>='3.9'": ""}

    Discriminator: non-empty value -> npm format; empty value -> PyPI format.
    Optional extras dependencies (marker contains 'extra') are silently skipped.
    Invalid dependency strings are silently skipped.

    Args:
        declared: Raw declared_dependencies dict from PackageVersion.

    Returns:
        Mapping of canonical package name (PEP 503) to version constraint string,
        or None when the dependency is unconstrained (* / latest / no specifier).
    """
    result: dict[str, str | None] = {}
    for dep_key, dep_val in declared.items():
        if dep_val:  # npm: key=name, val=constraint
            try:
                canonical = canonicalize_name(dep_key)
                stripped = dep_val.strip()
                result[canonical] = stripped if stripped not in _UNCONSTRAINED_VALUES else None
            except Exception:
                pass
        else:  # PyPI: key=PEP 508 dependency string, val=""
            try:
                req = Requirement(dep_key)
                if req.marker and "extra" in str(req.marker):
                    continue
                result[canonicalize_name(req.name)] = str(req.specifier) if req.specifier else None
            except InvalidRequirement:
                pass
    return result


class DepLike(Protocol):
    """Structural interface satisfied by DependencyDescriptor (service/project.py).

    Using a Protocol avoids the import cycle: service/ already imports unit_of_work/.
    Phase 4 should move DependencyDescriptor to domain/ and replace this Protocol.
    """

    canonical_name: str
    version: str
    version_constraint: str | None
    constraint_info: ConstraintSource
    all_constraints: list[str]


class SolvablePool:
    """Builds a SolverProblem from dependency descriptors and a warm registry cache."""

    @classmethod
    def build(
        cls,
        deps: Sequence[DepLike],
        registry: AbstractPackageRegistryApi,
        engine_context: dict[str, str],
        *,
        cve_affected: dict[str, set[str]] | None = None,
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
            cve_affected: Optional mapping of {canonical_name: {affected_version, ...}}.
                          Versions present here get has_cve=True on their CandidateVersion.
            allow_prerelease: When True, include pre-release candidates.
            _now: Injectable reference time for deterministic age computation in tests.
        """
        # 1. Deduplicate by canonical_name — highest constraint priority wins.
        # TODO: When two descriptors share the same type, resolve by specifier
        #       narrowness rather than insertion order.
        best: dict[str, DepLike] = {}
        for dep in deps:
            existing = best.get(dep.canonical_name)
            if existing is None:
                best[dep.canonical_name] = dep
            elif _CONSTRAINT_PRIORITY[dep.constraint_info.type] > _CONSTRAINT_PRIORITY[existing.constraint_info.type]:
                best[dep.canonical_name] = dep

        # 2. Build PackageConstraints from winning descriptors.
        # all_constraints carries every parent specifier so the encoder can apply
        # each as an independent L1 hard rejection (diamond-dep correctness).
        constraints = tuple(
            PackageConstraint(
                package_name=dep.canonical_name,
                version_constraint=dep.version_constraint,
                constraint_type=dep.constraint_info.type,
                installed_version=dep.version,
                all_constraints=tuple(dict.fromkeys(dep.all_constraints)),
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

            # Sort descending: b before a in comparator -> newest first.
            sorted_pvs = sorted(
                filtered,
                key=cmp_to_key(lambda a, b: registry.compare_versions(b.version, a.version)),
            )[:CANDIDATE_CAP]

            affected_versions: set[str] = (cve_affected or {}).get(canonical_name, set())
            candidates[canonical_name] = tuple(
                CandidateVersion(
                    version=pv.version,
                    age_days=age_days_from_iso(pv.published_date_iso, now=_now),
                    is_deprecated=pv.is_deprecated,
                    is_prerelease=pv.is_prerelease,
                    is_yanked=pv.is_yanked,
                    runtime_requirements=pv.runtime_requirements,
                    has_cve=pv.version in affected_versions,
                    requires=parse_requires(pv.declared_dependencies) or None,
                )
                for pv in sorted_pvs
            )

        return SolverProblem(
            constraints=constraints,
            candidates=candidates,
            engine_context=dict(engine_context),
        )
