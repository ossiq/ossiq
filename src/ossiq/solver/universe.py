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
from ossiq.domain.version import PackageVersion
from ossiq.solver.problem import CandidateVersion, PackageConstraint, SolverProblem
from ossiq.solver.version_matchers import version_satisfies_constraint
from ossiq.timeutil import age_days_from_iso, parse_iso_datetime

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


def relevant_constraints(
    installed_version: str,
    raw_constraints: Sequence[str],
    registry: AbstractPackageRegistryApi,
) -> tuple[str, ...]:
    """Keep only specifiers the installed version satisfies.

    A package can be installed at several versions in one tree (nested node_modules). The graph
    walker aggregates every consumer's specifier onto a single node, mixing constraints that
    belong to different physical copies (e.g. ^2.0.2 and ^5.0.5). Those a copy's installed version
    cannot satisfy belong to a different copy, so they are dropped — scoping the solve to the copy
    we are actually looking at. Falls back to the full set when none match (genuine drift), so a
    real constraint is never silently lost.
    """
    deduped = tuple(dict.fromkeys(raw_constraints))
    if not deduped:
        return ()
    satisfied = tuple(
        c for c in deduped if version_satisfies_constraint(installed_version, c, registry.package_registry)
    )
    return satisfied or deduped


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
            except (TypeError, AttributeError):
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


def effective_version_constraint(dep: DepLike, rewrite_pinned: bool) -> str | None:
    """The declared constraint, or None when a PINNED spec is deliberately unfrozen.

    With rewrite_pinned, ==x.y.z deps become solver-eligible: dropping the constraint lets
    the encoder consider newer candidates, and the writers later re-pin the chosen version.
    OVERRIDE and ADDITIVE constraints are never relaxed.
    """
    if rewrite_pinned and dep.constraint_info.type == ConstraintType.PINNED:
        return None
    return dep.version_constraint


def deduplicate_deps(deps: Sequence[DepLike]) -> dict[str, DepLike]:
    """Return highest-priority DepLike per canonical name.

    TODO: When two descriptors share the same type, resolve by specifier
          narrowness rather than insertion order.
    """
    best: dict[str, DepLike] = {}
    for dep in deps:
        existing = best.get(dep.canonical_name)
        if existing is None:
            best[dep.canonical_name] = dep
            continue
        if _CONSTRAINT_PRIORITY[dep.constraint_info.type] > _CONSTRAINT_PRIORITY[existing.constraint_info.type]:
            best[dep.canonical_name] = dep
    return best


def is_published_before(published_date_iso: str | None, now: datetime | None) -> bool:
    """Return True when the version was published at or before `now`, or when either is absent."""
    if now is None or published_date_iso is None:
        return True
    parsed = parse_iso_datetime(published_date_iso)
    return parsed is None or parsed <= now


def filter_eligible_versions(
    raw: list[PackageVersion],
    installed_version: str,
    allow_prerelease: bool,
    registry: AbstractPackageRegistryApi,
    now: datetime | None,
) -> list[PackageVersion]:
    """Return candidates sorted newest-first, capped at CANDIDATE_CAP.

    Drops yanked, unpublished, pre-release (when disallowed), downgrades, and
    versions published after `now`.
    """
    eligible = [
        pv
        for pv in raw
        if not pv.is_yanked
        and not pv.is_unpublished
        and (allow_prerelease or not pv.is_prerelease)
        and (not installed_version or registry.compare_versions(pv.version, installed_version) >= 0)
        and is_published_before(pv.published_date_iso, now)
    ]
    return sorted(
        eligible,
        key=cmp_to_key(lambda a, b: registry.compare_versions(b.version, a.version)),
    )[:CANDIDATE_CAP]


def make_candidate_versions(
    pvs: list[PackageVersion],
    affected_versions: set[str],
    now: datetime | None,
) -> tuple[CandidateVersion, ...]:
    """Assemble CandidateVersion tuples from filtered PackageVersion objects."""
    return tuple(
        CandidateVersion(
            version=pv.version,
            age_days=age_days_from_iso(pv.published_date_iso, now=now),
            is_deprecated=pv.is_deprecated,
            is_prerelease=pv.is_prerelease,
            is_yanked=pv.is_yanked,
            runtime_requirements=pv.runtime_requirements,
            has_cve=pv.version in affected_versions,
            requires=parse_requires(pv.declared_dependencies) or None,
        )
        for pv in pvs
    )


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
        rewrite_pinned: bool = False,
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
            rewrite_pinned: When True, PINNED (==x.y.z) constraints are dropped so the
                            solver can recommend newer versions for deliberate re-pinning.
        """
        best = deduplicate_deps(deps)

        constraints = tuple(
            PackageConstraint(
                package_name=dep.canonical_name,
                version_constraint=effective_version_constraint(dep, rewrite_pinned),
                constraint_type=dep.constraint_info.type,
                installed_version=dep.version,
                all_constraints=relevant_constraints(dep.version, dep.all_constraints, registry),
            )
            for dep in best.values()
        )

        candidates: dict[str, tuple[CandidateVersion, ...]] = {
            name: make_candidate_versions(
                filter_eligible_versions(
                    list(registry.package_versions(name)), dep.version, allow_prerelease, registry, _now
                ),
                (cve_affected or {}).get(name, set()),
                _now,
            )
            for name, dep in best.items()
        }

        return SolverProblem(
            constraints=constraints,
            candidates=candidates,
            engine_context=dict(engine_context),
            registry=registry.package_registry,
        )
