"""
Building and sorting ScanRecord instances from dependency descriptors and pre-fetched data.
"""

from datetime import UTC, datetime

from ossiq.adapters.api_interfaces import VersionRules
from ossiq.domain.common import build_purl, parse_spdx_expression
from ossiq.domain.cve import CVE
from ossiq.domain.package import Package
from ossiq.domain.project import ConstraintSource, PeerRequirement
from ossiq.domain.repository import Repository
from ossiq.service.common import package_versions
from ossiq.service.project.models import DependencyDescriptor, PrefetchedData, ScanRecord
from ossiq.solver.version_matchers import version_satisfies_constraint


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


def calculate_version_age_days(
    versions: list[package_versions.PackageVersion],
    installed_version: str,
    *,
    now: datetime | None = None,
) -> int | None:
    """
    Calculates how many days ago the installed version was published.
    """
    for pv in versions:
        if pv.version == installed_version and pv.published_date_iso:
            installed_date = parse_iso(pv.published_date_iso)
            if installed_date:
                reference = (
                    now
                    if now is not None
                    else (
                        datetime.now(tz=UTC) if installed_date.tzinfo else datetime.now()  # noqa: DTZ005
                    )
                )
                return (reference - installed_date).days
    return None


def scan_record(
    version_rules: VersionRules,
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
    *,
    now: datetime | None = None,
) -> ScanRecord:
    """
    Factory to generate ScanRecord instances
    """
    releases_since_installed = prefetched_versions_since

    # FIXME: here is pretty large opportunity to improve performance, but it is impractical to do it now.
    time_lag_days = calculate_time_lag_in_days(releases_since_installed, package_version, package_info.latest_version)
    version_age_days = calculate_version_age_days(releases_since_installed, package_version, now=now)

    installed_release = next(
        (release for release in releases_since_installed if release.version == package_version), None
    )

    version_diff_index = version_rules.difference_versions(package_version, package_info.latest_version)

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
        purl=build_purl(version_rules.package_registry, canonical_name, package_version),
        all_constraints=all_constraints or [],
        peer_requirements=list(peer_requirements or []),
        peer_violations=[
            req
            for req in (peer_requirements or [])
            if not version_satisfies_constraint(package_version, req.spec, version_rules.package_registry)
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


def build_records(
    descriptors: list[DependencyDescriptor],
    version_rules: VersionRules,
    prefetched: PrefetchedData,
    *,
    now: datetime | None = None,
) -> list[ScanRecord]:
    """Build ScanRecord instances from dependency descriptors and pre-fetched data."""
    return [
        scan_record(
            version_rules,
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
            now=now,
        )
        for dep in descriptors
    ]


def scan_sort_key(pkg: ScanRecord) -> tuple[int, int, int, str]:
    """Sort key for scan tables: drift severity, CVE count, time lag, then name.

    time_lag_days can be None (e.g. the latest version is invisible under --cutoff-date);
    unknown lag ranks lowest so tuple comparison never mixes None with int.
    """
    time_lag = pkg.time_lag_days if pkg.time_lag_days is not None else -1
    return (
        pkg.versions_diff_index.diff_index,
        len(pkg.cve),
        time_lag,
        pkg.package_name,
    )
