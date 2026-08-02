"""
Dataclasses for the project scan pipeline.
"""

from dataclasses import dataclass, field

from ossiq.domain.cve import CVE
from ossiq.domain.package import Package
from ossiq.domain.project import ConstraintSource, PeerRequirement
from ossiq.domain.repository import Repository
from ossiq.domain.version import VersionsDifference
from ossiq.service.common import package_versions
from ossiq.service.library_scan import UpgradePath
from ossiq.service.update_impact import TransitiveImpact
from ossiq.solver.reason import RecommendationReason


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
    # Computed in ossiq.risk.exposure_window.compute_exposure_window
    exposure_window_days: float | None = None


@dataclass
class PrefetchedData:
    """Data pre-fetched in bulk before building ScanRecords, passed explicitly to build_records."""

    packages_info: dict[str, Package]
    cve_map: dict[tuple[str, str], set[CVE]]
    versions_since_map: dict[tuple[str, str], list[package_versions.PackageVersion]]
    repositories_info: dict[str, Repository]


@dataclass
class IgnoredDependency:
    """A dependency excluded from the scan — either git/URL-hosted (unresolvable) or via --ignore."""

    name: str
    spec: str
    reason: str


@dataclass
class ScanResult:
    project_name: str
    packages_registry: str
    project_path: str
    production_packages: list[ScanRecord]
    optional_packages: list[ScanRecord]
    transitive_packages: list[ScanRecord] = field(default_factory=list)
    manifest_lock_divergent: list[str] = field(default_factory=list)
    upgrade_paths: list[UpgradePath] = field(default_factory=list)
    ignored_packages: list[IgnoredDependency] = field(default_factory=list)
