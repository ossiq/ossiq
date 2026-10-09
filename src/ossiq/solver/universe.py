from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from functools import cmp_to_key
from typing import Protocol

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import ConstraintType, ProjectPackagesRegistry
from ossiq.domain.cve import CVE
from ossiq.domain.project import ConstraintSource
from ossiq.domain.release_cutoff import ReleaseCutoff
from ossiq.domain.requirement_scope import RequirementScope
from ossiq.domain.version import PackageVersion
from ossiq.solver.pep508 import applicable_requirements
from ossiq.solver.problem import CandidateVersion, PackageConstraint, SolverProblem
from ossiq.solver.version_matchers import (
    comparable_package_name,
    cve_affects_version,
    version_satisfies_constraint,
)
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

    A package can be installed at several versions in one tree (nested node_modules), and the
    caller hands over every consumer's specifier across all of them (e.g. ^2.0.2 and ^5.0.5).
    Those the installed version cannot satisfy belong to a different copy, so they are dropped —
    scoping the solve to the copy we are actually looking at. What remains is exactly the edges
    an npm override keyed to this version (`name@<installed>`) would rewrite, which is how a
    recommendation for a nested copy is written back. Falls back to the full set when none match
    (genuine drift), so a real constraint is never silently lost.
    """
    deduped = tuple(dict.fromkeys(raw_constraints))
    if not deduped:
        return ()
    satisfied = tuple(
        c for c in deduped if version_satisfies_constraint(installed_version, c, registry.package_registry)
    )
    return satisfied or deduped


def parse_requires(
    declared: dict[str, str],
    scope: RequirementScope | None = None,
    package: str = "",
    registry: ProjectPackagesRegistry = ProjectPackagesRegistry.PYPI,
) -> dict[str, str | None]:
    """Parse declared_dependencies into a {canonical_pkg_name: constraint_or_None} mapping.

    Handles two formats used by registry adapters:

    npm format: key = package name, value = version constraint string.
        e.g. {"thinc": ">=8.1.8,<8.4.0", "numpy": ">=1.19.0", "attrs": "*"}

    PyPI format: key = PEP 508 dependency string, value = empty string.
        e.g. {"thinc>=8.1.8,<8.4.0": "", "numpy>=1.19.0; python_version>='3.9'": ""}

    Discriminator: non-empty value -> npm format; empty value -> PyPI format.
    PyPI requirements are filtered through `scope`: one gated on an extra the package does not
    enable, or on a marker no supported environment reaches, is skipped.
    Invalid dependency strings are silently skipped.

    Args:
        declared: Raw declared_dependencies dict from PackageVersion.
        scope: The project's extras and Python floor; None means no extras and no floor.
        package: Name of the package that declares *declared*, to look its extras up.
        registry: Whose naming rules key the result (`comparable_package_name`): PEP 503 for
            PyPI, the name as written for npm.

    Returns:
        Mapping of comparable package name to version constraint string,
        or None when the dependency is unconstrained (* / latest / no specifier).
    """
    result: dict[str, str | None] = {}
    pypi_lines: list[str] = []
    for dep_key, dep_val in declared.items():
        if dep_val:  # npm: key=name, val=constraint
            try:
                canonical = comparable_package_name(dep_key, registry)
                stripped = dep_val.strip()
                result[canonical] = stripped if stripped not in _UNCONSTRAINED_VALUES else None
            except (TypeError, AttributeError):
                pass
        else:  # PyPI: key=PEP 508 dependency string, val=""
            pypi_lines.append(dep_key)
    scope = scope or RequirementScope()
    for name, specifier in applicable_requirements(pypi_lines, scope.extras_for(package), scope.python_floor).items():
        result[name] = specifier or None
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
    release_cutoff: datetime | None = None,
    *,
    allow_deprecated: bool = True,
) -> list[PackageVersion]:
    """Return candidates sorted newest-first, capped at CANDIDATE_CAP.

    Drops yanked, unpublished, pre-release (when disallowed), deprecated (when disallowed),
    downgrades, versions published after `now`, and versions published after `release_cutoff` —
    the package manager's own limit for this package. The installed version survives that last
    filter: the package manager keeps a locked version past its cutoff, it only refuses to move to
    one.

    Deprecated releases stay eligible by default, where the solver only penalises them: a scan
    meets them deep in dependency trees, and dropping them there would leave packages with no
    candidate. A caller choosing a package from scratch passes `allow_deprecated=False`.
    """
    eligible = [
        pv
        for pv in raw
        if not pv.is_yanked
        and not pv.is_unpublished
        and (allow_deprecated or not pv.is_deprecated)
        and (allow_prerelease or not pv.is_prerelease)
        and (not installed_version or registry.compare_versions(pv.version, installed_version) >= 0)
        and is_published_before(pv.published_date_iso, now)
        and (
            is_published_before(pv.published_date_iso, release_cutoff)
            or (bool(installed_version) and registry.compare_versions(pv.version, installed_version) == 0)
        )
    ]
    return sorted(
        eligible,
        key=cmp_to_key(lambda a, b: registry.compare_versions(b.version, a.version)),
    )[:CANDIDATE_CAP]


def requirements_with_peers(pv: PackageVersion) -> dict[str, str]:
    """A release's declared dependencies plus its peers, a dependency's spec winning on a shared name.

    Optional peers stay in on purpose: the encoder skips any package that is not in the problem,
    which is an absent optional peer binding nothing, while one that is present is held to its range
    as npm holds it. A peer with no range is unconstrained, like an ordinary dependency's `*`.
    """
    if not pv.declared_peer_dependencies:
        return pv.declared_dependencies
    peers = {name: peer.spec or "*" for name, peer in pv.declared_peer_dependencies.items()}
    return {**peers, **pv.declared_dependencies}


def make_candidate_versions(
    pvs: list[PackageVersion],
    cves: tuple[CVE, ...],
    now: datetime | None,
    scope: RequirementScope | None = None,
    package: str = "",
    registry: ProjectPackagesRegistry = ProjectPackagesRegistry.PYPI,
) -> tuple[CandidateVersion, ...]:
    """Assemble CandidateVersion tuples from filtered PackageVersion objects.

    A candidate carries `has_cve` when any of *cves* affects it - by range as well as by
    enumerated version, since npm advisories publish only ranges. Its `requires` are those that
    hold under *scope* for *package*.
    """
    return tuple(
        CandidateVersion(
            version=pv.version,
            age_days=age_days_from_iso(pv.published_date_iso, now=now),
            is_deprecated=pv.is_deprecated,
            is_prerelease=pv.is_prerelease,
            is_yanked=pv.is_yanked,
            runtime_requirements=pv.runtime_requirements,
            has_cve=any(cve_affects_version(cve, pv.version) for cve in cves),
            requires=parse_requires(requirements_with_peers(pv), scope, package, registry) or None,
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
        cves_by_package: dict[str, tuple[CVE, ...]] | None = None,
        allow_prerelease: bool = False,
        allow_deprecated: bool = True,
        _now: datetime | None = None,
        rewrite_pinned: bool = False,
        release_cutoff: ReleaseCutoff | None = None,
    ) -> SolverProblem:
        """Build a SolverProblem from the given dependencies and registry.

        The registry cache is expected to be warm from the preceding scan pass,
        so package_versions() calls will not trigger additional HTTP requests.

        Args:
            deps: Flat sequence of dependency descriptors (direct + transitive).
            registry: Registry instance with warm cache from the scan pass.
            engine_context: Project engine versions, e.g. {"python": "3.11.9"}.
            cves_by_package: Optional mapping of {canonical_name: (CVE, ...)}. A candidate any of
                             its package's CVEs affects gets has_cve=True.
            allow_prerelease: When True, include pre-release candidates.
            allow_deprecated: When False, deprecated releases are not candidates at all, rather
                              than merely penalised.
            _now: Injectable reference time for deterministic age computation in tests.
            rewrite_pinned: When True, PINNED (==x.y.z) constraints are dropped so the
                            solver can recommend newer versions for deliberate re-pinning.
            release_cutoff: The package manager's own limit on release age; a release past it
                            never becomes a candidate, since the installer would refuse it.
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
                    list(registry.package_versions(name)),
                    dep.version,
                    allow_prerelease,
                    registry,
                    _now,
                    release_cutoff.cutoff_for(name) if release_cutoff else None,
                    allow_deprecated=allow_deprecated,
                ),
                (cves_by_package or {}).get(name, ()),
                _now,
                registry.requirement_scope,
                name,
                registry.package_registry,
            )
            for name, dep in best.items()
        }

        return SolverProblem(
            constraints=constraints,
            candidates=candidates,
            engine_context=dict(engine_context),
            registry=registry.package_registry,
        )
