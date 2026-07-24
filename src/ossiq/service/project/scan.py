"""
Project scan orchestration: fetch from external sources, run the solver, compute a ScanResult.
"""

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.adapters.api_pypi import PackageRegistryApiPypi
from ossiq.adapters.detectors import is_git_hosted_source
from ossiq.adapters.package_managers.dependency_tree import GraphExporter
from ossiq.domain.exceptions import ProjectPathNotFoundError
from ossiq.domain.package import Package
from ossiq.domain.project import Dependency
from ossiq.service.library_scan import compute_upgrade_paths, resolve_library_constraints
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
    partition_git_hosted,
    prefetch_packages_info,
    prefetch_source_code_repositories_info,
    prefetch_versions_since,
    update_latest_versions_for_prerelease,
)
from ossiq.service.project.recommendations import apply_conflicts, apply_recommendations, clamp_recommendations
from ossiq.service.project.records import build_records, scan_sort_key
from ossiq.service.update_impact import simulate_single, simulate_update_impacts
from ossiq.solver import dependencies_solver
from ossiq.solver.universe import filter_eligible_versions
from ossiq.sources.core import AbstractProjectSources
from ossiq.timeutil import parse_iso_datetime

logger = logging.getLogger(__name__)


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
    prod_deps = [
        DependencyDescriptor(
            name=dep.name,
            canonical_name=dep.canonical_name,
            version=dep.version_installed,
            is_optional=False,
            dependency_path=None,
            version_constraint=dep.version_defined,
            constraint_info=dep.constraint_info,
            extras=dep.extras,
            peer_requirements=list(dep.peer_requirements),
        )
        for dep in prod_source
    ]

    opt_deps: list[DependencyDescriptor] = []
    if not sources.production:
        opt_source, opt_git = partition_git_hosted(project_info.optional_dependencies.values(), detect_git_hosted)
        git_hosted_deps += opt_git
        opt_deps = [
            DependencyDescriptor(
                name=dep.name,
                canonical_name=dep.canonical_name,
                version=dep.version_installed,
                is_optional=True,
                dependency_path=None,
                version_constraint=dep.version_defined,
                constraint_info=dep.constraint_info,
                extras=dep.extras,
                peer_requirements=list(dep.peer_requirements),
            )
            for dep in opt_source
        ]

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
    step: Callable[[str], None],
) -> PrefetchedData:
    """Pass 1: pre-fetch package infos, repositories, CVEs, and versions-since for every dependency."""
    t0 = time.perf_counter()
    step("packages")
    packages_info = prefetch_packages_info(sources.packages_registry, (dep.canonical_name for dep in all_deps))

    if sources.allow_prerelease or sources.allow_prerelease_packages:
        update_latest_versions_for_prerelease(
            sources.packages_registry,
            packages_info,
            allow_prerelease=sources.allow_prerelease,
            allow_prerelease_packages=sources.allow_prerelease_packages,
        )

    apply_cutoff_date(packages_info, sources.packages_registry, now)

    # Github repository info
    step("repositories")
    repositories_info = prefetch_source_code_repositories_info(
        sources,
        {pkg.repo_url for pkg in packages_info.values() if pkg.repo_url is not None},
    )
    # Batch CVE fetch for all unique packages
    # force unique pair package/version regardless position in the graph
    unique_packages = list(set((packages_info[dep.canonical_name], dep.version) for dep in all_deps))

    step("vulnerabilities")
    cve_map = sources.cve_database.get_cves_batch(unique_packages)
    step("epss")
    cve_map = enrich_cves_with_epss_and_fix_age(
        cve_map,
        sources.epss_score_database,
        sources.packages_registry,
        now,
    )

    # Pre-compute versions-since-installed for all unique (package, version) pairs
    step("versions")
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
        repositories_info=repositories_info,
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
    engine_context: dict,
    installed_version_by_name: dict[str, str],
    now: datetime | None,
) -> tuple[dependencies_solver.SolverOutput, list[ScanRecord], list[ScanRecord]]:
    """Pass 1.5: run the HPDR solver over direct deps, apply its output, and simulate impacts."""
    transitive_by_name = {r.package_name: r for r in transitive_packages}

    def validate_recommendation(pkg_name: str, candidate_version: str) -> bool:
        return simulate_single(
            pkg_name,
            candidate_version,
            transitive_by_name,
            sources.packages_registry,
            sources.allow_prerelease,
            now=now,
            installed_version=installed_version_by_name.get(pkg_name),
        ).is_actionable

    t1 = time.perf_counter()
    solver_output = dependencies_solver.solve_direct(
        solvable_direct_deps,
        sources.packages_registry,
        engine_context,
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

    return solver_output, production_packages, optional_packages


def solve_transitive_phase(
    transitive_packages: list[ScanRecord],
    ignore_set: frozenset[str],
    sources: AbstractProjectSources,
    engine_context: dict,
    installed_version_by_name: dict[str, str],
    solver_output: dependencies_solver.SolverOutput,
    now: datetime | None,
) -> None:
    """Pass 1.6: run the HPDR solver over transitive deps and apply its output in place.

    security_only: CVE packages only. Default: all transitive packages.
    """
    if not transitive_packages:
        return
    records_to_solve = [
        r for r in transitive_packages if r.package_name not in ignore_set and (not sources.security_only or r.cve)
    ]
    t3 = time.perf_counter()
    transitive_output = dependencies_solver.solve_transitive(
        records_to_solve,
        sources.packages_registry,
        engine_context,
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
    if transitive_output.recommendations:
        apply_recommendations(transitive_packages, transitive_output, skip_current=True)


def scan(sources: AbstractProjectSources, on_step: Callable[[str], None] | None = None) -> ScanResult:
    """
    Project scan service: fetch from external sources, compute and return ScanResult.
    """

    def step(key: str) -> None:
        if on_step:
            on_step(key)

    with sources:
        step("project")
        project_info = sources.packages_manager.project_info()
        project_info = resolve_library_constraints(project_info, sources.packages_registry)
        # FIXME: catch this issue way before as part of command validation
        if not project_info.project_path:
            raise ProjectPathNotFoundError("Project Path is not Specified")

        descriptors = build_scan_descriptors(project_info, sources)
        all_deps = descriptors.prod_deps + descriptors.opt_deps + descriptors.trans_deps

        now = sources.settings.cutoff_date
        prefetched = prefetch_scan_data(sources, all_deps, now, step)

        # Ignored packages still get full ScanRecords (status/export/html show the row), but
        # they're excluded from solver input so they never receive a recommended_version.
        solvable_direct_deps = [
            d for d in descriptors.prod_deps + descriptors.opt_deps if d.canonical_name not in descriptors.ignore_set
        ]
        warm_pypi_version_requires_cache(sources, solvable_direct_deps, now)

        # Transitive records built first — the Phase 4c validator needs them to assess impacts.
        transitive_packages = build_records(descriptors.trans_deps, sources.packages_registry, prefetched, now=now)

        engine_context = project_info.engine_constraints or {}
        installed_version_by_name = {
            dep.canonical_name: dep.version for dep in descriptors.prod_deps + descriptors.opt_deps
        }

        step("solver")
        solver_output, production_packages, optional_packages = solve_direct_phase(
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
        )
