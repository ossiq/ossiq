"""
Project scan orchestration: fetch from external sources, run the solver, compute a ScanResult.
"""

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.adapters.api_pypi import PackageRegistryApiPypi
from ossiq.adapters.detectors import is_git_hosted_source
from ossiq.adapters.package_managers.dependency_tree import GraphExporter
from ossiq.domain.common import (
    DataCompleteness,
    DataSourceStatus,
    EngineContext,
    FetchDiagnostics,
    RateLimitBudget,
    RepositoryProvider,
    ScanStep,
    combine_statuses,
    merge_diagnostics,
)
from ossiq.domain.exceptions import ProjectPathNotFoundError
from ossiq.domain.package import Package
from ossiq.domain.project import Dependency
from ossiq.service.library_scan import compute_upgrade_paths, resolve_library_constraints
from ossiq.service.project.epss import populate_epss
from ossiq.service.project.models import (
    DependencyDescriptor,
    IgnoredDependency,
    PrefetchedData,
    ScanRecord,
    ScanResult,
)
from ossiq.service.project.prefetch import (
    build_ignored_packages,
    enrich_cves_with_epss_and_fix_age,
    forecast_github_budget,
    partition_git_hosted,
    prefetch_packages_info,
    prefetch_repository_activity,
    prefetch_repository_commits,
    prefetch_repository_readmes,
    prefetch_source_code_repositories_info,
    prefetch_versions_since,
    update_latest_versions_for_prerelease,
)
from ossiq.service.project.recommendations import (
    apply_conflicts,
    apply_recommendations,
    apply_solver_rejections,
    clamp_recommendations,
)
from ossiq.service.project.records import build_records, scan_sort_key
from ossiq.service.project.runtime_context import detect_engine_context
from ossiq.service.project.stability import populate_stability
from ossiq.service.project.strategy import apply_update_strategy
from ossiq.service.update_impact import DirectUpdateImpact, simulate_single, simulate_update_impacts
from ossiq.solver import dependencies_solver
from ossiq.solver.universe import filter_eligible_versions
from ossiq.sources.core import AbstractProjectSources
from ossiq.strategy.pyramid import MINIMAL_DIFF_TIERS
from ossiq.timeutil import parse_iso_datetime

logger = logging.getLogger(__name__)


def ignore_step_start(step: ScanStep) -> None:
    """Default `ScanProgress.on_step_start`: a caller that wants no progress passes nothing."""


class StepOutcome(Protocol):
    """What a scan reports when a step finishes: the outcome, and why it is what it is.

    A protocol rather than a plain `Callable` so `diagnostics` can stay optional - a caller that
    only cares whether the step succeeded still writes a two-argument callback.
    """

    def __call__(
        self, step: ScanStep, status: DataSourceStatus, diagnostics: FetchDiagnostics | None = None
    ) -> None: ...


def ignore_step_done(step: ScanStep, status: DataSourceStatus, diagnostics: FetchDiagnostics | None = None) -> None:
    """Default `ScanProgress.on_step_done`: a caller that wants no progress passes nothing."""


def ignore_budget(budgets: tuple[RateLimitBudget, ...]) -> None:
    """Default `ScanProgress.on_budget`: a caller that wants no progress passes nothing."""


@dataclass(frozen=True)
class ScanProgress:
    """The three distinct events a scan emits, as three callbacks.

    The first two used to be one `on_step(key, status=None)` disambiguated by `status is None` -
    an advance and an outcome report are different events, and every silent caller had to spell
    out a two-argument no-op lambda to say it wanted neither.

    Not every step reports an outcome; see `ScanStep` for which ones can and why.
    """

    on_step_start: Callable[[ScanStep], None] = ignore_step_start
    on_step_done: StepOutcome = ignore_step_done
    on_budget: Callable[[tuple[RateLimitBudget, ...]], None] = ignore_budget
    """A quota reading, forecast against what the scan still needs. Emitted before the fetches
    that spend it, so a doomed run can say so up front instead of after minutes of retries. The
    scan reports the numbers; whether they are worth showing is the renderer's call."""


@dataclass
class ScanDescriptors:
    """Direct/optional/transitive dependency descriptors, the ignored-packages report, and the
    dependency graph walker (re-used later to compute the full set of installed names)."""

    prod_deps: list[DependencyDescriptor]
    opt_deps: list[DependencyDescriptor]
    trans_deps: list[DependencyDescriptor]
    ignored_packages: list[IgnoredDependency]
    ignore_set: frozenset[str]
    walker: GraphExporter


def build_scan_descriptors(project_info, sources: AbstractProjectSources) -> ScanDescriptors:
    """Partition git/URL-hosted deps out, build direct/optional/transitive descriptors, and the
    ignored-dependencies report."""
    ignore_set: frozenset[str] = frozenset(sources.ignore_packages)
    # Only npm hosts deps on git/GitHub; PyPI strips VCS deps upstream, so gate detection
    # to avoid false-positives on a PyPI dep whose metadata happens to mention github.com.
    detect_git_hosted = not isinstance(sources.packages_registry, PackageRegistryApiPypi)

    # Git/URL-hosted deps can't be fetched from the registry — skip them (like --ignore) and
    # collect them for the ignored-dependencies report instead of crashing on prefetch.
    git_hosted_deps: list[Dependency] = []

    prod_source, prod_git = partition_git_hosted(project_info.dependencies.values(), detect_git_hosted)
    git_hosted_deps += prod_git
    prod_deps = [direct_descriptor(dep, is_optional=False) for dep in prod_source]

    opt_deps: list[DependencyDescriptor] = []
    if not sources.production:
        opt_source, opt_git = partition_git_hosted(project_info.optional_dependencies.values(), detect_git_hosted)
        git_hosted_deps += opt_git
        opt_deps = [direct_descriptor(dep, is_optional=True) for dep in opt_source]

    direct_canonical_names = {dep.canonical_name for dep in prod_deps + opt_deps}
    walker = GraphExporter(project_info.dependency_tree)
    trans_descriptors: dict[str, DependencyDescriptor] = {}
    for node, path in walker.walk_all_paths(include_optional_roots=not sources.production):
        if node.canonical_name in direct_canonical_names:
            continue
        if detect_git_hosted and is_git_hosted_source(node.version_defined, node.source):
            git_hosted_deps.append(node)
            continue
        trans_descriptors[node.canonical_name] = DependencyDescriptor(
            name=node.name,
            canonical_name=node.canonical_name,
            version=node.version_installed,
            is_optional=False,
            dependency_path=path,
            version_constraint=node.version_defined,
            constraint_info=node.constraint_info,
            extras=node.extras,
            all_constraints=list(node.parent_constraints),
            peer_requirements=list(node.peer_requirements),
            version_constraint_declared=node.version_constraint_declared,
        )
    trans_deps = list(trans_descriptors.values())

    ignored_packages = build_ignored_packages(git_hosted_deps, prod_deps + opt_deps, ignore_set)

    return ScanDescriptors(
        prod_deps=prod_deps,
        opt_deps=opt_deps,
        trans_deps=trans_deps,
        ignored_packages=ignored_packages,
        ignore_set=ignore_set,
        walker=walker,
    )


def direct_descriptor(dep: Dependency, *, is_optional: bool) -> DependencyDescriptor:
    """Build a descriptor for a root-level dependency.

    all_constraints carries the peer requirements other installed packages place on this package.
    Deliberately not dep.parent_constraints: for a direct dep that list also holds the root
    manifest's own specifier, which as a hard L1 clause would forbid every upgrade past the
    declared range. Peers are what actually bind - npm can nest a duplicate copy to satisfy a
    runtime range, but a peer must be satisfied by the single hoisted instance

    Note, that peers are read from the installed lockfile, so a lockstep family (vue and
    @vue/server-renderer, which peer-pins vue exactly) stays frozen until peerDependencies are
    modelled per candidate version in the registry adapter.
    """
    return DependencyDescriptor(
        name=dep.name,
        canonical_name=dep.canonical_name,
        version=dep.version_installed,
        is_optional=is_optional,
        dependency_path=None,
        version_constraint=dep.version_defined,
        constraint_info=dep.constraint_info,
        extras=dep.extras,
        all_constraints=[req.spec for req in dep.peer_requirements],
        peer_requirements=list(dep.peer_requirements),
        version_constraint_declared=dep.version_constraint_declared,
    )


def apply_cutoff_date(
    packages_info: dict[str, Package], registry: AbstractPackageRegistryApi, now: datetime | None
) -> None:
    """Override latest_version in-place to the newest release published on/before `now`."""
    if now is None:
        return
    for pkg in packages_info.values():
        eligible = [
            v
            for v in registry.package_versions(pkg.name)
            if not v.is_yanked
            and not v.is_unpublished
            and v.published_date_iso is not None
            and (pdt := parse_iso_datetime(v.published_date_iso)) is not None
            and pdt <= now
        ]
        best = registry.newest_version(iter(eligible))
        if best:
            pkg.latest_version = best.version


def prefetch_scan_data(
    sources: AbstractProjectSources,
    all_deps: list[DependencyDescriptor],
    now: datetime | None,
    progress: ScanProgress,
) -> PrefetchedData:
    """Pass 1: pre-fetch package infos, repositories, CVEs, and versions-since for every dependency."""
    t0 = time.perf_counter()
    progress.on_step_start(ScanStep.PACKAGES)
    packages_info = prefetch_packages_info(sources.packages_registry, (dep.canonical_name for dep in all_deps))

    if sources.allow_prerelease or sources.allow_prerelease_packages:
        update_latest_versions_for_prerelease(
            sources.packages_registry,
            packages_info,
            allow_prerelease=sources.allow_prerelease,
            allow_prerelease_packages=sources.allow_prerelease_packages,
        )

    apply_cutoff_date(packages_info, sources.packages_registry, now)

    # Github repository info. One provider instance shared across all 4 fetches below (repo info,
    # commits, activity, readmes): reuses a single session instead of opening a fresh one per call.
    progress.on_step_start(ScanStep.REPOSITORIES)
    provider = sources.get_source_code_provider(RepositoryProvider.PROVIDER_GITHUB)
    repo_urls = {pkg.repo_url for pkg in packages_info.values() if pkg.repo_url is not None}
    direct_packages = (packages_info[dep.canonical_name] for dep in all_deps if dep.dependency_path is None)
    direct_repo_urls = {pkg.repo_url for pkg in direct_packages if pkg.repo_url is not None}

    # Quota first: it costs nothing against the limit it reports, and it is the only way a scan
    # that is about to run out can say so before it starts paying for it.
    forecast = forecast_github_budget(
        provider,
        repo_urls,
        direct_repo_urls,
        stability=sources.settings.stability,
        responsiveness=sources.settings.responsiveness_enabled(),
    )
    progress.on_budget(forecast)

    repositories_fetch = prefetch_source_code_repositories_info(provider, repo_urls)
    repository_statuses = [repositories_fetch.status]
    repository_diagnostics = [FetchDiagnostics(budgets=forecast), repositories_fetch.diagnostics]

    # Stability signals for the direct-dependency repos only - one commit request and one README
    # request each, plus one GraphQL POST per repo per stream (ACTIVITY_CHUNK_SIZE = 1, PR streams
    # paginate) for the issue/PR/engagement channels. Both share the repositories step and switch
    # off where the GitHub quota is tight.
    commits: dict[str, list[dict]] = {}
    activity: dict[str, dict] = {}
    readmes: dict[str, str] = {}
    if sources.settings.stability:
        commits_fetch = prefetch_repository_commits(provider, sources, direct_repo_urls)
        readmes_fetch = prefetch_repository_readmes(provider, direct_repo_urls)
        commits, readmes = commits_fetch.data, readmes_fetch.data
        repository_statuses += [commits_fetch.status, readmes_fetch.status]
        repository_diagnostics += [commits_fetch.diagnostics, readmes_fetch.diagnostics]
        if sources.settings.responsiveness_enabled():
            activity_fetch = prefetch_repository_activity(provider, sources, direct_repo_urls)
            activity = activity_fetch.data
            repository_statuses.append(activity_fetch.status)
            repository_diagnostics.append(activity_fetch.diagnostics)

    # B4: per-step completeness, so a firewalled host or exhausted quota never renders as a
    # silent success. All four GitHub fetches report under one step, combined explicitly here -
    # a step with nothing to fetch (no repo URLs at all) is legitimately ok, not a failure.
    repositories_status = combine_statuses(repository_statuses)
    completeness: dict[ScanStep, DataSourceStatus] = {ScanStep.REPOSITORIES: repositories_status}
    diagnostics: dict[ScanStep, FetchDiagnostics] = {ScanStep.REPOSITORIES: merge_diagnostics(repository_diagnostics)}
    progress.on_step_done(ScanStep.REPOSITORIES, repositories_status, diagnostics[ScanStep.REPOSITORIES])

    # Batch CVE fetch for all unique packages
    # force unique pair package/version regardless position in the graph
    unique_packages = list(set((packages_info[dep.canonical_name], dep.version) for dep in all_deps))

    progress.on_step_start(ScanStep.VULNERABILITIES)
    cve_fetch = sources.cve_database.get_cves_batch(unique_packages)
    completeness[ScanStep.VULNERABILITIES] = cve_fetch.status
    diagnostics[ScanStep.VULNERABILITIES] = cve_fetch.diagnostics
    progress.on_step_done(ScanStep.VULNERABILITIES, cve_fetch.status, cve_fetch.diagnostics)

    progress.on_step_start(ScanStep.EPSS)
    epss_fetch = enrich_cves_with_epss_and_fix_age(
        cve_fetch.data,
        sources.epss_score_database,
        sources.packages_registry,
        now,
    )
    cve_map = epss_fetch.data
    completeness[ScanStep.EPSS] = epss_fetch.status
    diagnostics[ScanStep.EPSS] = epss_fetch.diagnostics
    progress.on_step_done(ScanStep.EPSS, epss_fetch.status, epss_fetch.diagnostics)

    # Pre-compute versions-since-installed for all unique (package, version) pairs
    progress.on_step_start(ScanStep.VERSIONS)
    versions_since_map = prefetch_versions_since(
        sources.packages_registry,
        {(packages_info[dep.canonical_name].name, dep.version) for dep in all_deps},
        allow_prerelease=sources.allow_prerelease,
        allow_prerelease_packages=sources.allow_prerelease_packages,
    )

    logger.debug("Pass 1 prefetch: %.2fs — %d packages", time.perf_counter() - t0, len(packages_info))

    return PrefetchedData(
        packages_info=packages_info,
        cve_map=cve_map,
        versions_since_map=versions_since_map,
        repositories_info=repositories_fetch.data,
        commits=commits,
        activity=activity,
        readmes=readmes,
        data_completeness=DataCompleteness(by_step=completeness, diagnostics=diagnostics),
    )


def warm_pypi_version_requires_cache(
    sources: AbstractProjectSources, solvable_direct_deps: list[DependencyDescriptor], now: datetime | None
) -> None:
    """Warm the PyPI version-requires cache for top solver candidates before solve_direct runs.

    Converts N sequential per-call HTTP fetches (in post_solve_validator) into one parallel batch.
    Only needed for PyPI - NPM embeds all version deps in its main package JSON.
    Warm the same newest-first candidates the solver will consider - raw package_versions()
    yields releases oldest-first on PyPI, which would warm versions the solver never checks.
    """
    if not isinstance(sources.packages_registry, PackageRegistryApiPypi):
        return
    warmup_pairs = [
        (dep.canonical_name, pv.version)
        for dep in solvable_direct_deps
        for pv in filter_eligible_versions(
            list(sources.packages_registry.package_versions(dep.canonical_name)),
            dep.version,
            sources.allow_prerelease,
            sources.packages_registry,
            now,
        )[:10]  # FIXME: questionable solution for high-frequency released packages
    ]
    sources.packages_registry.warmup_version_requires(warmup_pairs)


def solve_direct_phase(
    solvable_direct_deps: list[DependencyDescriptor],
    descriptors: ScanDescriptors,
    sources: AbstractProjectSources,
    prefetched: PrefetchedData,
    transitive_packages: list[ScanRecord],
    engine_context: EngineContext,
    installed_version_by_name: dict[str, str],
    now: datetime | None,
) -> tuple[
    dependencies_solver.SolverOutput, list[ScanRecord], list[ScanRecord], Callable[[str, str], DirectUpdateImpact]
]:
    """Pass 1.5: run the HPDR solver over direct deps, apply its output, and simulate impacts.

    Returns `simulate_recommendation` alongside the usual outputs — `scan()` reuses it to gate the
    candidate ladder `apply_update_strategy` builds, after `populate_stability` runs, retaining
    the full impact (not just its actionability) so a rejected candidate can be explained.
    """
    transitive_by_name = {r.package_name: r for r in transitive_packages}

    def simulate_recommendation(pkg_name: str, candidate_version: str) -> DirectUpdateImpact:
        return simulate_single(
            pkg_name,
            candidate_version,
            transitive_by_name,
            sources.packages_registry,
            sources.allow_prerelease,
            now=now,
            installed_version=installed_version_by_name.get(pkg_name),
        )

    def validate_recommendation(pkg_name: str, candidate_version: str) -> bool:
        return simulate_recommendation(pkg_name, candidate_version).is_actionable

    t1 = time.perf_counter()
    solver_output = dependencies_solver.solve_direct(
        solvable_direct_deps,
        sources.packages_registry,
        engine_context.versions,
        allow_prerelease=sources.allow_prerelease,
        post_solve_validator=validate_recommendation,
        _now=now,
        cooldown_period=sources.settings.cooldown_period,
        rewrite_pinned=sources.rewrite_versions,
    )
    logger.debug(
        "Pass 1.5 solve_direct: %.2fs — %d recommendations",
        time.perf_counter() - t1,
        len(solver_output.recommendations),
    )

    production_packages = sorted(
        build_records(descriptors.prod_deps, sources.packages_registry, prefetched, now=now),
        key=scan_sort_key,
        reverse=True,
    )
    optional_packages = sorted(
        build_records(descriptors.opt_deps, sources.packages_registry, prefetched, now=now),
        key=scan_sort_key,
        reverse=True,
    )

    apply_conflicts(solver_output, production_packages + optional_packages)
    if solver_output.recommendations:
        apply_recommendations(production_packages + optional_packages, solver_output)
        clamp_recommendations(
            production_packages + optional_packages,
            sources.packages_registry,
            allow_prerelease=sources.allow_prerelease,
            now=now,
            rewrite_pinned=sources.rewrite_versions,
            cooldown_period=sources.settings.cooldown_period,
        )

        # Build a complete set of installed canonical names — includes transitive deps
        # of dev/optional packages that walk_all_paths() skips by default. Used to
        # distinguish truly new packages from ones already present in the lock file.
        all_installed_names: set[str] = {dep.canonical_name for dep in descriptors.prod_deps + descriptors.opt_deps} | {
            node.canonical_name for node, _ in descriptors.walker.walk_all_paths(include_optional_roots=True)
        }

        t2 = time.perf_counter()
        impacts = simulate_update_impacts(
            solver_output.recommendations,
            production_packages + optional_packages + transitive_packages,
            sources.packages_registry,
            sources.allow_prerelease,
            installed_names=all_installed_names,
            now=now,
            installed_versions=installed_version_by_name,
        )
        logger.debug("Pass 1.5b simulate_impacts: %.2fs — %d packages", time.perf_counter() - t2, len(impacts))
        for record in production_packages + optional_packages:
            impact = impacts.get(record.package_name)
            # Skip clamped records: impacts were simulated for the unclamped solver pick.
            if impact is not None and record.recommended_version == solver_output.recommendations.get(
                record.package_name
            ):
                record.update_transitive_impacts = impact.transitive_impacts

    return solver_output, production_packages, optional_packages, simulate_recommendation


def solve_transitive_phase(
    transitive_packages: list[ScanRecord],
    ignore_set: frozenset[str],
    sources: AbstractProjectSources,
    engine_context: EngineContext,
    installed_version_by_name: dict[str, str],
    solver_output: dependencies_solver.SolverOutput,
    now: datetime | None,
    *,
    project_declares_esm: bool = False,
) -> None:
    """Pass 1.6: run the HPDR solver over transitive deps and apply its output in place.

    Restricted to CVE-affected packages when the run's tier never exceeds a minimal-diff tier
    (security/deprecation) — the strategy applies only to direct deps (v1 scope), so this is the
    one place a transitive-only run still narrows itself to match.
    """
    if not transitive_packages:
        return
    minimal_diff_run = sources.strategy.max_tier in MINIMAL_DIFF_TIERS
    records_to_solve = [
        r for r in transitive_packages if r.package_name not in ignore_set and (not minimal_diff_run or r.cve)
    ]
    t3 = time.perf_counter()
    transitive_output = dependencies_solver.solve_transitive(
        records_to_solve,
        sources.packages_registry,
        engine_context.versions,
        allow_prerelease=sources.allow_prerelease,
        now=now,
        cooldown_period=sources.settings.cooldown_period,
        external_targets={**installed_version_by_name, **solver_output.recommendations},
    )
    logger.debug(
        "Pass 1.6 solve_transitive: %.2fs — %d records, %d recommendations",
        time.perf_counter() - t3,
        len(records_to_solve),
        len(transitive_output.recommendations),
    )
    apply_conflicts(transitive_output, transitive_packages)
    apply_solver_rejections(transitive_output, transitive_packages)
    if transitive_output.recommendations:
        # The only finalization point for a transitive record's recommendation in this pipeline
        # (direct records get a further pass in apply_update_strategy) - resolve
        # recommended_module_system/breaking_change/engine_* here so it isn't silently left null.
        apply_recommendations(
            transitive_packages,
            transitive_output,
            skip_current=True,
            registry=sources.packages_registry,
            project_declares_esm=project_declares_esm,
            engine_context=engine_context,
        )


def scan(sources: AbstractProjectSources, progress: ScanProgress | None = None) -> ScanResult:
    """
    Project scan service: fetch from external sources, compute and return ScanResult.
    """
    progress = progress or ScanProgress()

    with sources:
        progress.on_step_start(ScanStep.PROJECT)
        project_info = sources.packages_manager.project_info()
        project_info = resolve_library_constraints(project_info, sources.packages_registry)
        # FIXME: catch this issue way before as part of command validation
        if not project_info.project_path:
            raise ProjectPathNotFoundError("Project Path is not Specified")

        descriptors = build_scan_descriptors(project_info, sources)
        all_deps = descriptors.prod_deps + descriptors.opt_deps + descriptors.trans_deps

        now = sources.settings.cutoff_date
        prefetched = prefetch_scan_data(sources, all_deps, now, progress)

        # Ignored packages still get full ScanRecords (status/export/html show the row), but
        # they're excluded from solver input so they never receive a recommended_version.
        solvable_direct_deps = [
            d for d in descriptors.prod_deps + descriptors.opt_deps if d.canonical_name not in descriptors.ignore_set
        ]
        warm_pypi_version_requires_cache(sources, solvable_direct_deps, now)

        # Transitive records built first — the Phase 4c validator needs them to assess impacts.
        transitive_packages = build_records(descriptors.trans_deps, sources.packages_registry, prefetched, now=now)

        engine_context, npm_cli_version = detect_engine_context(
            project_info,
            sources.project_path,
            probe_runtime=sources.settings.probe_runtime,
        )
        installed_version_by_name = {
            dep.canonical_name: dep.version for dep in descriptors.prod_deps + descriptors.opt_deps
        }

        progress.on_step_start(ScanStep.SOLVER)
        solver_output, production_packages, optional_packages, simulate_recommendation = solve_direct_phase(
            solvable_direct_deps,
            descriptors,
            sources,
            prefetched,
            transitive_packages,
            engine_context,
            installed_version_by_name,
            now,
        )

        solve_transitive_phase(
            transitive_packages,
            descriptors.ignore_set,
            sources,
            engine_context,
            installed_version_by_name,
            solver_output,
            now,
            project_declares_esm=project_info.declares_esm,
        )

        all_records = production_packages + optional_packages + transitive_packages
        project_epss = populate_epss(all_records, descriptors.walker)
        project_stability = populate_stability(all_records, prefetched.commits, now, prefetched.activity)

        # Must run after populate_stability: record.maintenance/triage feed classify_motives's
        # END_OF_LIFE check. Ignored packages are excluded, mirroring solve_direct_phase's old
        # apply_ladder_fallback filter — a package the user asked to leave alone never gets a
        # recommendation from any source.
        all_installed_names: set[str] = {dep.canonical_name for dep in descriptors.prod_deps + descriptors.opt_deps} | {
            node.canonical_name for node, _ in descriptors.walker.walk_all_paths(include_optional_roots=True)
        }
        apply_update_strategy(
            [r for r in production_packages + optional_packages if r.package_name not in descriptors.ignore_set],
            sources.packages_registry,
            sources.strategy,
            versions_since=prefetched.versions_since_map,
            transitive_by_name={r.package_name: r for r in transitive_packages},
            installed_names=all_installed_names,
            allow_prerelease=sources.allow_prerelease,
            now=now,
            validator=simulate_recommendation,
            project_declares_esm=project_info.declares_esm,
            engine_context=engine_context,
            cooldown_period=sources.settings.cooldown_period,
        )

        upgrade_paths = compute_upgrade_paths(project_info, sources.packages_registry)
        return ScanResult(
            project_name=project_info.name,
            project_path=project_info.project_path,
            packages_registry=project_info.package_registry.value,
            production_packages=production_packages,
            optional_packages=optional_packages,
            transitive_packages=transitive_packages,
            manifest_lock_divergent=list(project_info.manifest_lock_divergent),
            upgrade_paths=upgrade_paths,
            ignored_packages=descriptors.ignored_packages,
            project_epss=project_epss,
            project_stability=project_stability,
            data_completeness=prefetched.data_completeness,
            declares_esm=project_info.declares_esm,
            engine_context=engine_context,
            npm_cli_version=npm_cli_version,
            source_warnings=list(sources.warnings),
        )
