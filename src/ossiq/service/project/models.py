"""
Dataclasses for the project scan pipeline.
"""

from dataclasses import dataclass, field

from ossiq.domain.cve import CVE
from ossiq.domain.package import Package
from ossiq.domain.project import ConstraintSource, PeerRequirement
from ossiq.domain.repository import Repository
from ossiq.domain.version import VersionsDifference
from ossiq.risk.gate import GateDecision
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
    """Canonical registry name of the package (post alias-resolution). Never None."""

    dependency_name: str | None
    """Name as declared by the importer (may be an npm alias); None when unavailable."""

    is_optional_dependency: bool
    """True if this dependency is only pulled in via an optional/extra group."""

    installed_version: str
    """Version currently resolved in the lockfile (or manifest, if there's no lockfile)."""

    latest_version: str | None
    """Newest version available in the registry; None if it could not be determined."""

    versions_diff_index: VersionsDifference
    """Classification of how far installed_version trails latest_version (major/minor/patch/...)."""

    time_lag_days: int | None
    """Days between the installed and latest release publish dates. None if undeterminable."""

    releases_lag: int | None
    """Count of releases published after installed_version, up to latest_version."""

    cve: list[CVE]
    """Known CVEs affecting installed_version."""

    constraint_info: ConstraintSource
    """Where the active version constraint on this dependency came from (file, scope)."""

    version_constraint: str | None = None
    """Raw version specifier from the manifest, e.g. "^1.2.0"; None for unconstrained deps."""

    version_age_days: int | None = None
    """Days since installed_version was published. None if the publish date is unknown."""

    dependency_path: list[str] | None = None
    """Chain of package names from a root dependency down to this one; None for direct deps."""

    extras: list[str] | None = None
    """PyPI extras requested for this dependency, e.g. ["security", "tests"]."""

    license: list[str] | None = None
    """SPDX license identifiers, parsed from the package's declared license expression."""

    repo_url: str | None = None
    """Source repository URL reported by the package registry."""

    repository: Repository | None = None
    """Fetched repository metadata (stars, activity, etc.) for repo_url, if resolved."""

    homepage_url: str | None = None
    """Project homepage URL reported by the package registry."""

    package_url: str | None = None
    """Canonical package page URL on the registry (e.g. PyPI/npm package page)."""

    purl: str | None = None
    """Package URL (purl spec) identifying this exact package + version."""

    is_installed_prerelease: bool = False
    """True if installed_version is a pre-release (alpha/beta/rc)."""

    is_installed_yanked: bool = False
    """True if installed_version was yanked or unpublished from the registry."""

    is_installed_deprecated: bool = False
    """True if installed_version or the package itself is marked deprecated."""

    is_installed_package_unpublished: bool = False
    """True if the package as a whole has been unpublished from the registry."""

    recommended_version: str | None = None
    """Version the solver recommends upgrading to; None if no upgrade is recommended."""

    recommended_version_reason: RecommendationReason | None = None
    """Human-readable explanation of why recommended_version was chosen."""

    all_constraints: list[str] = field(default_factory=list)
    """All version specifiers from every direct parent; mirrors DependencyDescriptor.all_constraints.
    Passed to the transitive solver so each parent constraint is enforced as a separate L1 clause."""

    update_transitive_impacts: list[TransitiveImpact] = field(default_factory=list)
    """Populated by Phase 4c after solve_direct: transitive impacts of the final recommendation."""

    peer_requirements: list[PeerRequirement] = field(default_factory=list)
    """All peer requirements placed on this package by other installed packages."""

    peer_violations: list[PeerRequirement] = field(default_factory=list)
    """Subset of peer_requirements where installed_version doesn't satisfy the spec."""

    constraint_conflict: list[str] = field(default_factory=list)
    """Populated when the solver found no valid version satisfying all constraints."""

    exposure_window_days: float | None = None
    """Remediation window, in days. Computed in ossiq.risk.exposure_window.compute_exposure_window."""

    gate_decision: GateDecision | None = None
    """Pass/quarantine/block decision. Computed in ossiq.risk.gate.get_gate_decision."""

    p_supplychain: float | None = None
    """Supply-chain hazard probability. Computed in ossiq.risk.p_supplychain.compute_p_supplychain."""

    p_vuln: float | None = None
    """Known-vulnerability exploitation probability. Computed in ossiq.risk.p_vuln.compute_p_vuln."""


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
