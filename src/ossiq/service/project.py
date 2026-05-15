"""
Service to take care of a Package versions
"""

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from rich.console import Console

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.adapters.package_managers.dependency_tree import GraphExporter
from ossiq.domain.common import RepositoryProvider, build_purl, parse_spdx_expression
from ossiq.domain.cve import CVE
from ossiq.domain.exceptions import ProjectPathNotFoundError, UnknownPackageVersion
from ossiq.domain.package import Package
from ossiq.domain.project import ConstraintSource, PeerRequirement
from ossiq.domain.repository import Repository
from ossiq.domain.version import VersionsDifference
from ossiq.service.common import package_versions
from ossiq.service.update_impact import TransitiveImpact, simulate_single, simulate_update_impacts
from ossiq.unit_of_work import core as unit_of_work
from ossiq.unit_of_work.solver import uow_dependencies_solver
from ossiq.unit_of_work.solver.reason import RecommendationReason
from ossiq.unit_of_work.solver.version_matchers import version_satisfies_constraint

console = Console()


@dataclass(frozen=True)
class DependencyDescriptor:
    name: str
    canonical_name: str
    version: str
    is_optional: bool
    dependency_path: list[str] | None
    version_constraint: str | None
    constraint_info: ConstraintSource
    extras: list[str] | None = None
    # All version specifiers from every direct parent in the dependency graph.
    # Empty for direct (root-level) dependencies; populated for transitive deps.
    all_constraints: list[str] = field(default_factory=list)
    peer_requirements: list[PeerRequirement] = field(default_factory=list)


@dataclass
class ScanRecord:
    """
    Main aggregated output of the OSS IQ tool.
    """

    package_name: str
    dependency_name: str | None
    is_optional_dependency: bool
    installed_version: str
    latest_version: str | None
    versions_diff_index: VersionsDifference
    time_lag_days: int | None
    releases_lag: int | None
    cve: list[CVE]
    constraint_info: ConstraintSource
    version_constraint: str | None = None
    version_age_days: int | None = None
    dependency_path: list[str] | None = None
    extras: list[str] | None = None
    license: list[str] | None = None
    repo_url: str | None = None
    repository: Repository | None = None
    homepage_url: str | None = None
    package_url: str | None = None
    purl: str | None = None
    is_installed_prerelease: bool = False
    is_installed_yanked: bool = False
    is_installed_deprecated: bool = False
    is_installed_package_unpublished: bool = False
    recommended_version: str | None = None
    recommended_version_reason: RecommendationReason | None = None
    # All version specifiers from every direct parent; mirrors DependencyDescriptor.all_constraints.
    # Passed to the transitive solver so each parent constraint is enforced as a separate L1 clause.
    all_constraints: list[str] = field(default_factory=list)
    # Populated by Phase 4c after solve_direct: transitive impacts of the final recommendation.
    update_transitive_impacts: list[TransitiveImpact] = field(default_factory=list)
    # All peer requirements placed on this package by other installed packages.
    peer_requirements: list[PeerRequirement] = field(default_factory=list)
    # Subset of peer_requirements where installed_version doesn't satisfy the spec.
    peer_violations: list[PeerRequirement] = field(default_factory=list)
    # Populated when the solver found no valid version satisfying all constraints.
    constraint_conflict: list[str] = field(default_factory=list)


@dataclass
class PrefetchedData:
    """Data pre-fetched in bulk before building ScanRecords, passed explicitly to build_records."""

    packages_info: dict[str, Package]
    cve_map: dict[tuple[str, str], set[CVE]]
    versions_since_map: dict[tuple[str, str], list[package_versions.PackageVersion]]
    repositories_info: dict[str, Repository]


@dataclass
class ScanResult:
    project_name: str
    packages_registry: str
    project_path: str
    production_packages: list[ScanRecord]
    optional_packages: list[ScanRecord]
    transitive_packages: list[ScanRecord] = field(default_factory=list)


def parse_iso(datetime_str: str | None):
    """
    Parse ISO datetime string to datetime object.
    """
    if datetime_str:
        return datetime.fromisoformat(datetime_str.replace("Z", "+00:00"))

    return None


def calculate_time_lag_in_days(
    versions: list[package_versions.PackageVersion], installed_version: str, latest_version: str | None
) -> int | None:
    """
    Calculates the time difference in days between the installed and latest package versions.
    """
    installed_date = None
    latest_date = None

    if installed_version == latest_version or not latest_version:
        return 0

    for pv in versions:
        if pv.version == installed_version and pv.published_date_iso:
            installed_date = parse_iso(pv.published_date_iso)
        elif pv.version == latest_version and pv.published_date_iso:
            latest_date = parse_iso(pv.published_date_iso)

    if installed_date and latest_date:
        return (latest_date - installed_date).days

    return None


def calculate_version_age_days(versions: list[package_versions.PackageVersion], installed_version: str) -> int | None:
    """
    Calculates how many days ago the installed version was published.
    """
    for pv in versions:
        if pv.version == installed_version and pv.published_date_iso:
            installed_date = parse_iso(pv.published_date_iso)
            if installed_date:
                now = datetime.now(tz=UTC) if installed_date.tzinfo else datetime.now()  # noqa: DTZ005
                return (now - installed_date).days
    return None


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


def scan_record(
    packages_registry: AbstractPackageRegistryApi,
    package_info: Package,
    package_name: str,
    canonical_name: str,
    package_version: str,
    is_optional_dependency: bool,
    prefetched_cves: set[CVE],
    prefetched_versions_since: list[package_versions.PackageVersion],
    constraint_info: ConstraintSource,
    dependency_path: list[str] | None = None,
    version_constraint: str | None = None,
    prefetched_repository: Repository | None = None,
    extras: list[str] | None = None,
    all_constraints: list[str] | None = None,
    peer_requirements: list[PeerRequirement] | None = None,
) -> ScanRecord:
    """
    Factory to generate ScanRecord instances
    """
    releases_since_installed = prefetched_versions_since

    # FIXME: here is pretty large opportunity to improve performance, but it is impractical to do it now.
    time_lag_days = calculate_time_lag_in_days(releases_since_installed, package_version, package_info.latest_version)
    version_age_days = calculate_version_age_days(releases_since_installed, package_version)

    installed_release = next(
        (release for release in releases_since_installed if release.version == package_version), None
    )

    version_diff_index = packages_registry.difference_versions(package_version, package_info.latest_version)

    return ScanRecord(
        package_name=canonical_name,
        dependency_name=package_name,
        installed_version=package_version,
        latest_version=package_info.latest_version,
        time_lag_days=time_lag_days,
        version_age_days=version_age_days,
        releases_lag=len(releases_since_installed) - 1,
        versions_diff_index=version_diff_index,
        cve=list(prefetched_cves) if installed_release else [],
        is_optional_dependency=is_optional_dependency,
        dependency_path=dependency_path,
        version_constraint=version_constraint,
        extras=extras,
        constraint_info=constraint_info,
        repo_url=package_info.repo_url,
        repository=prefetched_repository,
        homepage_url=package_info.homepage_url,
        package_url=package_info.package_url,
        license=parse_spdx_expression(
            package_info.license or (prefetched_repository.license if prefetched_repository else None)
        ),
        purl=build_purl(packages_registry.package_registry, canonical_name, package_version),
        all_constraints=all_constraints or [],
        peer_requirements=list(peer_requirements or []),
        peer_violations=[
            req for req in (peer_requirements or []) if not version_satisfies_constraint(package_version, req.spec)
        ],
        is_installed_prerelease=installed_release.is_prerelease if installed_release else False,
        is_installed_yanked=(
            installed_release is not None and (installed_release.is_yanked or installed_release.is_unpublished)
        ),
        is_installed_deprecated=(
            (installed_release.is_deprecated if installed_release else False) or package_info.is_deprecated
        ),
        is_installed_package_unpublished=package_info.is_unpublished,
    )


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
            pass


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


def prefetch_source_code_repositories_info(
    uow: unit_of_work.AbstractProjectUnitOfWork,
    repo_urls: Iterable[str],
) -> dict[str, Repository]:
    """
    Pre-fetch repository info for all unique GitHub repo URLs in parallel.
    Returns a mapping of url -> Repository; non-GitHub URLs are skipped.
    """
    github_urls = [url for url in repo_urls if "github.com" in url]
    if not github_urls:
        return {}
    return uow.get_source_code_provider(RepositoryProvider.PROVIDER_GITHUB).repositories_info_batch(github_urls)


def build_records(
    descriptors: list[DependencyDescriptor],
    registry: AbstractPackageRegistryApi,
    prefetched: PrefetchedData,
) -> list[ScanRecord]:
    """Build ScanRecord instances from dependency descriptors and pre-fetched data."""
    return [
        scan_record(
            registry,
            prefetched.packages_info[dep.canonical_name],
            dep.name,
            dep.canonical_name,
            dep.version,
            dep.is_optional,
            prefetched.cve_map.get((prefetched.packages_info[dep.canonical_name].name, dep.version), set()),
            prefetched.versions_since_map[(prefetched.packages_info[dep.canonical_name].name, dep.version)],
            dep.constraint_info,
            dep.dependency_path,
            dep.version_constraint,
            prefetched.repositories_info.get(prefetched.packages_info[dep.canonical_name].repo_url or ""),
            dep.extras,
            dep.all_constraints,
            dep.peer_requirements,
        )
        for dep in descriptors
    ]


def _apply_conflicts(
    output: uow_dependencies_solver.SolverOutput,
    records: list[ScanRecord],
) -> None:
    """Write solver conflict info onto ScanRecord instances in-place."""
    if not output.conflicts:
        return
    by_name = {c.package_name: c for c in output.conflicts}
    for record in records:
        conflict = by_name.get(record.package_name)
        if conflict is not None:
            record.constraint_conflict = conflict.conflicting_constraints


def apply_recommendations(
    records: list[ScanRecord],
    output: uow_dependencies_solver.SolverOutput,
    *,
    skip_current: bool = False,
) -> None:
    """Write solver recommendations back onto ScanRecord instances in-place."""
    for record in records:
        rec = output.recommendations.get(record.package_name)
        if rec is not None and (not skip_current or rec != record.installed_version):
            record.recommended_version = rec
            record.recommended_version_reason = output.reasons.get(record.package_name)


def scan(uow: unit_of_work.AbstractProjectUnitOfWork) -> ScanResult:
    """
    Project scan service to leverage Project UoW to gather metrics
    """

    def sort_function(pkg: ScanRecord):
        return (
            pkg.versions_diff_index.diff_index,
            len(pkg.cve),
            pkg.time_lag_days,
            pkg.package_name,
        )

    with uow:
        project_info = uow.packages_manager.project_info()
        # FIXME: catch this issue way before as part of command validation
        if not project_info.project_path:
            raise ProjectPathNotFoundError("Project Path is not Specified")

        # Collect all dependency descriptors
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
            for dep in project_info.dependencies.values()
        ]

        opt_deps: list[DependencyDescriptor] = []
        if not uow.production:
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
                for dep in project_info.optional_dependencies.values()
            ]

        direct_canonical_names = {dep.canonical_name for dep in prod_deps + opt_deps}
        walker = GraphExporter(project_info.dependency_tree)
        trans_deps = list(
            {
                node.canonical_name: DependencyDescriptor(
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
                for node, path in walker.walk_all_paths()
                if node.canonical_name not in direct_canonical_names
            }.values()
        )

        all_deps = prod_deps + opt_deps + trans_deps

        # Pass 1: pre-fetch package infos
        packages_info = prefetch_packages_info(uow.packages_registry, (dep.canonical_name for dep in all_deps))

        if uow.allow_prerelease or uow.allow_prerelease_packages:
            update_latest_versions_for_prerelease(
                uow.packages_registry,
                packages_info,
                allow_prerelease=uow.allow_prerelease,
                allow_prerelease_packages=uow.allow_prerelease_packages,
            )

        # Github repository info
        repositories_info = prefetch_source_code_repositories_info(
            uow,
            {pkg.repo_url for pkg in packages_info.values() if pkg.repo_url is not None},
        )
        # Batch CVE fetch for all unique packages
        # force unique pair package/version regardless position in the graph
        unique_packages = list(set((packages_info[dep.canonical_name], dep.version) for dep in all_deps))

        cve_map = uow.cve_database.get_cves_batch(unique_packages)

        # Pre-compute versions-since-installed for all unique (package, version) pairs
        versions_since_map = prefetch_versions_since(
            uow.packages_registry,
            {(packages_info[dep.canonical_name].name, dep.version) for dep in all_deps},
            allow_prerelease=uow.allow_prerelease,
            allow_prerelease_packages=uow.allow_prerelease_packages,
        )

        prefetched = PrefetchedData(
            packages_info=packages_info,
            cve_map=cve_map,
            versions_since_map=versions_since_map,
            repositories_info=repositories_info,
        )

        # Transitive records built first — the Phase 4c validator needs them to assess impacts.
        transitive_packages = build_records(trans_deps, uow.packages_registry, prefetched)

        # Pass 1.5: optionally run HPDR solver over direct deps (cache is warm after prefetch).
        # engine_context={} in Phase 4 — L2 (engine mismatch) clauses inactive; L3/L4 still fire.
        # TODO (Phase 5): populate engine_context from project_info engine metadata.
        transitive_by_name = {r.package_name: r for r in transitive_packages}

        def validate_recommendation(pkg_name: str, candidate_version: str) -> bool:
            return simulate_single(
                pkg_name,
                candidate_version,
                transitive_by_name,
                uow.packages_registry,
                uow.allow_prerelease,
            ).is_actionable

        solver_output = uow_dependencies_solver.solve_direct(
            prod_deps + opt_deps,
            uow.packages_registry,
            {},
            allow_prerelease=uow.allow_prerelease,
            post_solve_validator=validate_recommendation,
        )

        production_packages = sorted(
            build_records(prod_deps, uow.packages_registry, prefetched), key=sort_function, reverse=True
        )
        optional_packages = sorted(
            build_records(opt_deps, uow.packages_registry, prefetched), key=sort_function, reverse=True
        )

        _apply_conflicts(solver_output, production_packages + optional_packages)
        if solver_output.recommendations:
            apply_recommendations(production_packages + optional_packages, solver_output)

            # Build a complete set of installed canonical names — includes transitive deps
            # of dev/optional packages that walk_all_paths() skips by default. Used to
            # distinguish truly new packages from ones already present in the lock file.
            all_installed_names: set[str] = {dep.canonical_name for dep in prod_deps + opt_deps} | {
                node.canonical_name for node, _ in walker.walk_all_paths(include_optional_roots=True)
            }

            impacts = simulate_update_impacts(
                solver_output.recommendations,
                production_packages + optional_packages + transitive_packages,
                uow.packages_registry,
                uow.allow_prerelease,
                installed_names=all_installed_names,
            )
            for record in production_packages + optional_packages:
                impact = impacts.get(record.package_name)
                if impact is not None:
                    record.update_transitive_impacts = impact.transitive_impacts

        # Pass 1.6: HPDR solver over transitive deps.
        # security_only: CVE packages only. Default: all transitive packages.
        # engine_context={} — populating from project metadata deferred to Phase 6+.
        if transitive_packages:
            records_to_solve = [r for r in transitive_packages if r.cve] if uow.security_only else transitive_packages
            transitive_output = uow_dependencies_solver.solve_transitive(
                records_to_solve,
                uow.packages_registry,
                {},
                allow_prerelease=uow.allow_prerelease,
            )
            _apply_conflicts(transitive_output, transitive_packages)
            if transitive_output.recommendations:
                apply_recommendations(transitive_packages, transitive_output, skip_current=True)

        return ScanResult(
            project_name=project_info.name,
            project_path=project_info.project_path,
            packages_registry=project_info.package_registry.value,
            production_packages=production_packages,
            optional_packages=optional_packages,
            transitive_packages=transitive_packages,
        )
