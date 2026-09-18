"""The version ladder: newest installable version reachable at each widening step.

Plain registry facts, not solver-guarded picks: no cooldown, no CVE filtering, no
CANDIDATE_CAP. `recommended_version` falls down this ladder (see
`service.project.recommendations.apply_ladder_fallback`) when the solver found nowhere to go —
the common case of a dependency held back on a major by an API break that still has a newer
patch reachable inside that major
"""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from ossiq.adapters.api_interfaces import VersionRules
from ossiq.domain.common import ProjectPackagesRegistry, RecommendationRung
from ossiq.domain.version import PackageVersion
from ossiq.solver.universe import is_published_before
from ossiq.solver.version_matchers import major_key, version_satisfies_constraint


@dataclass(frozen=True)
class VersionLadder:
    """Newest installable version reachable at each widening step. All rungs are >= installed.

    A rung equals installed_version — never None — when that step admits nothing newer:
    "nothing to do here" is an explicit equality, not an absence. None only when genuinely
    undeterminable: no release data at all, or (for latest_in_range) the declared constraint is
    satisfiable only *below* installed_version, which signals a manifest/lockfile divergence
    rather than "already up to date".
    """

    latest_in_range: str | None
    """Newest installable version satisfying the declared version_constraint."""

    latest_in_major: str | None
    """Newest installable version sharing installed_version's major line (PEP 440 epoch + first
    release segment on PyPI; semver major on npm)."""

    latest_overall: str | None
    """Newest installable version, ignoring both the constraint and the major line."""


def installable_releases(
    releases: Iterable[PackageVersion],
    version_rules: VersionRules,
    *,
    now: datetime | None = None,
    newer_than: str | None = None,
) -> list[PackageVersion]:
    """Return the releases a user could actually install today, in the order they were given.

    The single definition of "installable", shared by the ladder, the candidate builder and the
    compatible-major scan so none of them can drift from the others.

    Args:
        releases: Candidate releases, typically already floored at the installed version.
        version_rules: Registry-specific version semantics (comparison plus registry identity).
        now: Cutoff instant; releases published after it are excluded, so a rung never outruns a
            `--cutoff-date`-adjusted `latest_version`.
        newer_than: When given, keep only releases strictly newer than this version.

    Returns:
        The surviving releases, unsorted — callers needing an order apply their own.
    """
    registry = version_rules.package_registry
    kept = [
        pv
        for pv in releases
        if not pv.is_yanked
        and not pv.is_unpublished
        and is_published_before(pv.published_date_iso, now)
        # major_key returning None means the version didn't parse under this registry's scheme;
        # exclude it so one malformed entry can't blow up a later compare_versions call.
        and major_key(pv.version, registry) is not None
    ]
    if newer_than is None:
        return kept
    return [pv for pv in kept if version_rules.compare_versions(pv.version, newer_than) > 0]


def in_declared_range(version: str, constraint: str | None, registry: ProjectPackagesRegistry) -> bool:
    """The single definition of "inside the declared range"."""
    return version_satisfies_constraint(version, constraint, registry)


def in_installed_major(
    version: str,
    installed_major: tuple[int, int] | None,
    registry: ProjectPackagesRegistry,
) -> bool:
    """The single definition of "inside the installed major line"."""
    return installed_major is not None and major_key(version, registry) == installed_major


def classify_rung(
    version: str,
    constraint: str | None,
    installed_major: tuple[int, int] | None,
    registry: ProjectPackagesRegistry,
) -> RecommendationRung:
    """Place *version* on the widening ladder relative to *constraint*.

    Args:
        version: The release being placed.
        constraint: The constraint the root manifest declares, or None.
        installed_major: `major_key` of the installed version, or None when it doesn't parse.
        registry: Which registry's version scheme applies.

    Returns:
        IN_RANGE, IN_MAJOR or LATEST — the lowest rung that reaches *version*.
    """
    # Composed from the same two predicates compute_version_ladder uses, not the other way round:
    # the ladder's rungs are independent predicates rather than a partition (a version can satisfy
    # the constraint while sitting outside the installed major), so only the predicates can be
    # shared - see strategy/README.md.
    if in_declared_range(version, constraint, registry):
        return RecommendationRung.IN_RANGE
    if in_installed_major(version, installed_major, registry):
        return RecommendationRung.IN_MAJOR
    return RecommendationRung.LATEST


def compute_version_ladder(
    releases_since_installed: list[PackageVersion],
    installed_version: str,
    version_constraint: str | None,
    version_rules: VersionRules,
    *,
    latest_version: str | None = None,
    now: datetime | None = None,
) -> VersionLadder:
    """Compute the version ladder from a package's uncapped release list.

    `releases_since_installed` is expected to already be floored at installed_version (as
    `PrefetchedData.versions_since_map` provides) and prerelease-filtered per the caller's
    allow_prerelease setting — this function applies no further prerelease policy. It excludes
    yanked/unpublished releases and, when `now` is given, releases published after it (so a rung
    never outruns a `--cutoff-date`-adjusted `latest_version`) — a rung must be a version you
    could actually install today.

    `latest_version` (typically `Package.latest_version`, already cutoff-adjusted) is preferred
    for `latest_overall` when known; falls back to the newest installable release otherwise, so a
    cutoff-adjusted "latest" is never contradicted by an uncapped release list.
    """
    registry = version_rules.package_registry
    try:
        installable = installable_releases(releases_since_installed, version_rules, now=now)
        installed_major = major_key(installed_version, registry)
        in_range = [pv for pv in installable if in_declared_range(pv.version, version_constraint, registry)]
        in_major = [pv for pv in installable if in_installed_major(pv.version, installed_major, registry)]

        newest_in_range = version_rules.newest_version(in_range)
        newest_in_major = version_rules.newest_version(in_major)
        newest_overall = version_rules.newest_version(installable)

        return VersionLadder(
            latest_in_range=newest_in_range.version if newest_in_range else None,
            latest_in_major=newest_in_major.version if newest_in_major else None,
            latest_overall=latest_version or (newest_overall.version if newest_overall else None),
        )
    except (ValueError, TypeError):
        # A registry-specific compare_versions/major_key call choked on unparseable data
        # somewhere in the release list. Undeterminable, not "nothing to do" — see the class
        # docstring's None semantics.
        return VersionLadder(latest_in_range=None, latest_in_major=None, latest_overall=latest_version)
