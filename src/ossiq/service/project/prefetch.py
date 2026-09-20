"""
Bulk pre-fetch helpers: package info, repositories, versions-since-installed,
and classification of dependencies that must be excluded from the scan.
"""

from collections.abc import Iterable
from dataclasses import replace
from datetime import datetime
from itertools import chain

from packaging.version import InvalidVersion

from ossiq.adapters.api_epss import EpssApiFirstOrg
from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi, AbstractSourceCodeProviderApi
from ossiq.adapters.detectors import is_git_hosted_source, is_github_url
from ossiq.domain.common import RateLimitBudget, SourceFetch
from ossiq.domain.cve import CVE
from ossiq.domain.exceptions import UnknownPackageVersion
from ossiq.domain.package import Package
from ossiq.domain.project import Dependency
from ossiq.domain.repository import Repository
from ossiq.messages import IGNORE_REASON_IGNORE_FLAG, IGNORE_REASON_NON_REGISTRY
from ossiq.risk.stability import engagement_window_since
from ossiq.service.common import package_versions
from ossiq.service.project.models import DependencyDescriptor, IgnoredDependency
from ossiq.sources.core import AbstractProjectSources
from ossiq.timeutil import age_days_from_iso


def get_package_versions_since(
    packages_registry: AbstractPackageRegistryApi,
    package_name: str,
    installed_version: str,
    *,
    allow_prerelease: bool = False,
    allow_prerelease_packages: tuple[str, ...] = (),
) -> list[package_versions.PackageVersion]:
    """
    Calculate Package versions lag: delta between
    installed package and the latest one.
    """
    try:
        versions = [
            v
            for v in packages_registry.package_versions(package_name)
            if packages_registry.compare_versions(v.version, installed_version) >= 0
        ]
        if not allow_prerelease and package_name not in allow_prerelease_packages:
            # Always retain the installed version so installed_release is never None,
            # even when the installed version itself is a prerelease.
            versions = [v for v in versions if not v.is_prerelease or v.version == installed_version]
        return versions
    except UnknownPackageVersion:
        return []


def update_latest_versions_for_prerelease(
    packages_registry: AbstractPackageRegistryApi,
    packages_info: dict[str, Package],
    *,
    allow_prerelease: bool,
    allow_prerelease_packages: tuple[str, ...],
) -> None:
    """Update latest_version in-place for packages where prerelease should be considered."""
    for pkg in packages_info.values():
        if not allow_prerelease and pkg.name not in allow_prerelease_packages:
            continue
        try:
            best = packages_registry.newest_version(packages_registry.package_versions(pkg.name))
            if best:
                pkg.latest_version = best.version
        except UnknownPackageVersion:
            # Best-effort prefetch: skip packages with unknown/invalid version data
            # so one bad package does not block processing of the rest.
            continue


def prefetch_versions_since(
    packages_registry: AbstractPackageRegistryApi,
    unique_pairs: Iterable[tuple[str, str]],
    *,
    allow_prerelease: bool = False,
    allow_prerelease_packages: tuple[str, ...] = (),
) -> dict[tuple[str, str], list[package_versions.PackageVersion]]:
    """Pre-compute versions-since-installed for all unique (package_name, installed_version) pairs."""
    result: dict[tuple[str, str], list[package_versions.PackageVersion]] = {}
    for name, version in unique_pairs:
        if (name, version) not in result:
            result[(name, version)] = get_package_versions_since(
                packages_registry,
                name,
                version,
                allow_prerelease=allow_prerelease,
                allow_prerelease_packages=allow_prerelease_packages,
            )
    return result


def prefetch_packages_info(
    packages_registry: AbstractPackageRegistryApi, canonical_names: Iterable[str]
) -> dict[str, Package]:
    """Pre-fetch package info for all unique canonical names in parallel."""
    unique = list(dict.fromkeys(canonical_names))
    return packages_registry.packages_info_batch(unique)


def nearest_cve_fix_version(
    fix_versions: Iterable[str],
    installed_version: str,
    registry: AbstractPackageRegistryApi,
) -> str | None:
    """Return the smallest comparable fix strictly newer than the installed version."""
    nearest = None
    for candidate in fix_versions:
        try:
            if registry.compare_versions(candidate, installed_version) <= 0:
                continue
            if nearest is None or registry.compare_versions(candidate, nearest) < 0:
                nearest = candidate
        except (InvalidVersion, UnknownPackageVersion):
            # OSV can include non-registry ranges such as git commit hashes.
            continue
    return nearest


def cve_fix_age_days(
    cve: CVE,
    installed_version: str,
    releases: Iterable[package_versions.PackageVersion],
    registry: AbstractPackageRegistryApi,
    now: datetime | None,
) -> int | None:
    """Return the age of the nearest available fix release, if the registry knows it."""
    selected_fix = nearest_cve_fix_version(cve.fix_versions, installed_version, registry)
    if not selected_fix:
        return None

    for release in releases:
        # Fast path: bypass expensive version parsing if strings match exactly
        if release.version == selected_fix:
            return age_days_from_iso(release.published_date_iso, now=now)

        # Slow path: semantic version equivalence (e.g. "1.0" == "1.0.0")
        try:
            if registry.compare_versions(release.version, selected_fix) == 0:
                return age_days_from_iso(release.published_date_iso, now=now)
        except (InvalidVersion, UnknownPackageVersion):
            continue

    return None


def aggregate_cve_ids(cve_map: dict[tuple[str, str], set[CVE]]) -> dict[str, set[str]]:
    """Map each primary CVE ID to a set of itself and all its alias IDs."""
    return {cve.id: {cve.id} | set(cve.cve_ids)
            for cves in cve_map.values() for cve in cves}  # fmt: off


def enrich_cves_with_epss_and_fix_age(
    cve_map: dict[tuple[str, str], set[CVE]],
    epss_client: EpssApiFirstOrg,
    registry: AbstractPackageRegistryApi,
    now: datetime | None,
) -> SourceFetch[dict[tuple[str, str], set[CVE]]]:
    """Return a copy of cve_map with EPSS scores and fix-release ages populated.

    Returns:
        The enriched map, and whether the EPSS source delivered. An unscored CVE and an
        unreachable first.org both leave `epss` None, so the status is what separates them.
    """
    if not cve_map:
        return SourceFetch({})

    cve_backlink = aggregate_cve_ids(cve_map)
    cve_ids = set(chain.from_iterable(cve_backlink.values()))
    epss_fetch = epss_client.get_epss_batch(cve_ids)
    epss_scores = epss_fetch.data

    release_cache: dict[str, tuple[package_versions.PackageVersion, ...]] = {}
    enriched_map: dict[tuple[str, str], set[CVE]] = {}

    for (package_name, installed_version), cves in cve_map.items():
        releases: tuple[package_versions.PackageVersion, ...] = ()

        if any(cve.fix_versions for cve in cves):
            if package_name not in release_cache:
                try:
                    release_cache[package_name] = tuple(registry.package_versions(package_name))
                except UnknownPackageVersion:
                    release_cache[package_name] = ()
            releases = release_cache[package_name]

        enriched_cves = set()
        for cve in cves:
            # Cleanly gather EPSS scores for the CVE and its aliases
            aliases = cve_backlink.get(cve.id, set())
            cve_epss_scores = [epss_scores[aid] for aid in aliases if aid in epss_scores]
            max_epss = max(cve_epss_scores) if cve_epss_scores else None

            enriched_cves.add(
                replace(
                    cve,
                    epss=max_epss,
                    fix_age_days=cve_fix_age_days(cve, installed_version, releases, registry, now),
                )
            )

        enriched_map[(package_name, installed_version)] = enriched_cves

    return SourceFetch(enriched_map, epss_fetch.status)


def prefetch_source_code_repositories_info(
    provider: AbstractSourceCodeProviderApi,
    repo_urls: Iterable[str],
) -> SourceFetch[dict[str, Repository]]:
    """
    Pre-fetch repository info for all unique GitHub repo URLs in parallel.
    Returns a mapping of url -> Repository; non-GitHub URLs are skipped.

    Takes an already-constructed provider (rather than `sources`) so every GitHub fetch in one
    scan shares a single session instead of opening a fresh one per call.
    """

    github_urls = github_only(repo_urls)
    if not github_urls:
        # Nothing to ask for is not a data-source failure.
        return SourceFetch({})
    return provider.repositories_info_batch(github_urls)


def github_only(repo_urls: Iterable[str]) -> list[str]:
    """Keep only github.com URLs. Everything else (GitLab, Codeberg, no URL at all) stays
    unmeasured rather than being reported as a negative signal.

    What that costs the user is reported by `coverage.classify_signal_coverage`, which shares
    `is_github_url` with this filter so the two agree on who was left out."""

    return [url for url in repo_urls if is_github_url(url)]


# What one scan spends per repository, by quota. REST: one /repos call for every repo in the
# graph, plus a commits and a README call for each direct dependency. GraphQL: one query per
# stream (issues, pulls) per direct dependency, before any pagination. Deliberately an upper
# bound - it ignores the HTTP cache, so a warm scan is forecast to cost more than it will.
REST_REQUESTS_PER_REPO = 1
REST_REQUESTS_PER_DIRECT_REPO = 2
GRAPHQL_REQUESTS_PER_DIRECT_REPO = 2


def forecast_github_budget(
    provider: AbstractSourceCodeProviderApi,
    repo_urls: Iterable[str],
    direct_repo_urls: Iterable[str],
    *,
    stability: bool,
    responsiveness: bool,
) -> tuple[RateLimitBudget, ...]:
    """Read GitHub's remaining quota before the scan spends it, against what the scan will need.

    The quota check itself is free and uncached. Without it, an exhausted quota only shows up
    once the scan has spent minutes pausing and retrying into a wall - and a warm cache can hide
    it entirely, since the run never touches the network to find out.

    Args:
        provider: The GitHub provider the scan's fetches will use.
        repo_urls: Every repository URL in the dependency graph.
        direct_repo_urls: The direct dependencies' repositories, which alone get the stability
            channels.
        stability: Whether the commits and README fetches will run.
        responsiveness: Whether the GraphQL activity fetch will run.

    Returns:
        One budget per metered resource with `needed` filled in, or an empty tuple when there is
        nothing to fetch or GitHub didn't answer.
    """
    repo_count = len(github_only(repo_urls))
    if not repo_count:
        return ()
    direct_count = len(github_only(direct_repo_urls))

    needed = {
        "core": repo_count * REST_REQUESTS_PER_REPO
        + (direct_count * REST_REQUESTS_PER_DIRECT_REPO if stability else 0),
        "graphql": direct_count * GRAPHQL_REQUESTS_PER_DIRECT_REPO if stability and responsiveness else 0,
    }
    return tuple(
        replace(budget, needed=needed.get(budget.resource))
        for budget in provider.rate_limit_budgets()
        if needed.get(budget.resource)
    )


def prefetch_repository_commits(
    provider: AbstractSourceCodeProviderApi, sources: AbstractProjectSources, repo_urls: Iterable[str]
) -> SourceFetch[dict[str, list[dict]]]:
    """
    Pre-fetch the last 100 commits for all unique GitHub repo URLs in parallel.

    One request per repository, cached like every other call. Feeds the gap-based stability
    estimator; see risk/stability.py.
    """

    github_urls = github_only(repo_urls)
    if not github_urls:
        return SourceFetch({})
    until = sources.settings.cutoff_date.strftime("%Y-%m-%dT%H:%M:%SZ") if sources.settings.cutoff_date else None
    return provider.commits_batch(github_urls, until)


def prefetch_repository_activity(
    provider: AbstractSourceCodeProviderApi, sources: AbstractProjectSources, repo_urls: Iterable[str]
) -> SourceFetch[dict[str, dict]]:
    """Pre-fetch issue / PR activity for all unique GitHub repo URLs via GraphQL.

    Covers the engagement look-back window ending at the cutoff date (or now). Feeds the
    engagement-flow trends and the pinned-notice deprecation signal; see risk/stability.py.
    """

    github_urls = github_only(repo_urls)
    if not github_urls:
        return SourceFetch({})
    since = engagement_window_since(sources.settings.cutoff_date)
    return provider.repository_activity_batch(github_urls, since)


def prefetch_repository_readmes(
    provider: AbstractSourceCodeProviderApi, repo_urls: Iterable[str]
) -> SourceFetch[dict[str, str]]:
    """Pre-fetch the top of each GitHub repo's README, for the deprecation-banner scan.

    One request per repository, cached at the stability TTL; see risk/maintenance.py.
    """

    github_urls = github_only(repo_urls)
    if not github_urls:
        return SourceFetch({})
    return provider.readmes_batch(github_urls)


def partition_git_hosted(deps: Iterable[Dependency], enabled: bool) -> tuple[list[Dependency], list[Dependency]]:
    """Split deps into (registry-resolvable, git/URL-hosted).

    Git/URL-hosted deps aren't on the registry, so fetching them crashes the scan; they're
    skipped like --ignore and reported at the end. When disabled (non-npm), all deps are
    treated as registry-resolvable.
    """
    registry: list[Dependency] = []
    git_hosted: list[Dependency] = []
    for dep in deps:
        is_git = enabled and is_git_hosted_source(dep.version_defined, dep.source)
        (git_hosted if is_git else registry).append(dep)
    return registry, git_hosted


def build_ignored_packages(
    git_hosted: list[Dependency],
    direct_descriptors: list[DependencyDescriptor],
    ignore_set: frozenset[str],
) -> list[IgnoredDependency]:
    """Build the ignored-dependencies report: git/URL-hosted deps (auto-skipped) plus explicit
    --ignore deps. Deduplicated by canonical name; git-hosted wins on overlap.
    """
    ignored: dict[str, IgnoredDependency] = {}
    for dep in git_hosted:
        ignored.setdefault(
            dep.canonical_name,
            IgnoredDependency(
                name=dep.name,
                spec=dep.version_defined or dep.source or "",
                reason=IGNORE_REASON_NON_REGISTRY,
            ),
        )
    for descriptor in direct_descriptors:
        if descriptor.canonical_name in ignore_set:
            ignored.setdefault(
                descriptor.canonical_name,
                IgnoredDependency(
                    name=descriptor.name,
                    spec=descriptor.version_constraint or "",
                    reason=IGNORE_REASON_IGNORE_FLAG,
                ),
            )
    return list(ignored.values())
