"""
Dataclasses for the project scan pipeline.
"""

from dataclasses import dataclass, field

from ossiq.domain.common import (
    DataCompleteness,
    EngineContext,
    RecommendationRung,
    RejectedCandidate,
)
from ossiq.domain.compatibility import CompatibilityFacts
from ossiq.domain.cve import CVE
from ossiq.domain.package import Package
from ossiq.domain.project import ConstraintSource, PeerRequirement
from ossiq.domain.repository import Repository
from ossiq.domain.version import VersionsDifference
from ossiq.risk.maintenance import DeprecationEvidence, MaintenanceAssessment
from ossiq.service.common import package_versions
from ossiq.service.library_scan import UpgradePath
from ossiq.service.project.epss import ProjectEpss
from ossiq.service.project.stability import ProjectStability, RepositoryStability, TriageResult
from ossiq.service.update_impact import TransitiveImpact
from ossiq.solver.reason import RecommendationReason
from ossiq.strategy.targeting import StrategySelection


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
    # Hard version specifiers a candidate must satisfy, beyond version_constraint.
    # Transitive deps: every direct parent's specifier (diamond-dep correctness).
    # Direct deps: the peer requirements other installed packages place on them.
    all_constraints: list[str] = field(default_factory=list)
    peer_requirements: list[PeerRequirement] = field(default_factory=list)
    # The root manifest's own declared specifier for this package, mirroring
    # Dependency.version_constraint_declared. None for transitive-only deps with no
    # root-manifest entry. This, not version_constraint, is what user-facing surfaces
    # should read as "the declared constraint" - see domain/project.py.
    version_constraint_declared: str | None = None


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
    """Effective version specifier used internally for solver/ladder computation, e.g. "^1.2.0".
    Last-writer-wins across every parent that declares a spec for this package (see
    dependency_tree.py Pass 2) - it is NOT guaranteed to be the root manifest's own declaration.
    User-facing surfaces must read version_constraint_declared instead."""

    version_constraint_declared: str | None = None
    """The root manifest's own declared specifier for this package, e.g. "^1.2.0"; None for
    transitive-only deps with no root-manifest entry, or unconstrained direct deps. This is the
    value every user-facing surface (console, export, agent reasons) should show as "the declared
    constraint" - see domain/project.py's Dependency.version_constraint_declared."""

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

    recommended_from_rung: RecommendationRung | None = None
    """Which version-ladder rung recommended_version came from. SOLVER and IN_RANGE sit inside
    version_constraint. None only when recommended_version is None."""

    rejected_candidates: list[RejectedCandidate] = field(default_factory=list)
    """Releases that would have been the recommendation but were held back by a transitive-dependency
    conflict. Capped at one per ladder rung (newest rejected at IN_RANGE/IN_MAJOR/LATEST). Populated by
    service.project.strategy.apply_update_strategy for direct deps, by
    service.project.recommendations.apply_solver_rejections for transitive deps."""

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

    epss: float | None = None
    """Highest EPSS score among this package's CVEs. Computed in ossiq.risk.epss.package_epss."""

    stability: RepositoryStability | None = None
    """Commit-gap dormancy and engagement-flow signals for the upstream repository. None when no
    commit was sampled - no repo URL, a non-GitHub host, or a rate-limited fetch."""

    deprecation: DeprecationEvidence | None = None
    """Explicit end-of-life markers found in registry / repo metadata and the README. Populated
    in service.project.records.scan_record; None only when package metadata was unavailable."""

    maintenance: MaintenanceAssessment | None = None
    """Naive-Bayes maintenance-state posterior (risk/maintenance.py). None when not one
    observation was available. Populated in service.project.stability.populate_stability."""

    triage: TriageResult | None = None
    """Recommended action from the EPSS x maintenance matrix. Populated in service.project.stability."""

    days_since_push: int | None = None
    """Days since the last push to the upstream repository, measured against the scan's cutoff.
    The graded abandonment signal - `Repository.archived` is its saturating case, and covers far
    fewer packages because most dead projects are never formally archived."""

    runs_code_at_install: bool | None = None
    """True if the installed version executes arbitrary code during install
    (pip build backend / npm lifecycle script / node-gyp). Populated in service.project.records.scan_record
    from the installed PackageVersion."""

    install_execution_reason: str | None = None
    """Human-readable reason for runs_code_at_install, e.g. "npm lifecycle: postinstall" or
    "PyPI source distribution build". None when the signal is unknown or execution was not detected."""

    compatibility: CompatibilityFacts = field(default_factory=CompatibilityFacts)
    """Where this record sits on the version ladder and what is true about the version it picked -
    see domain/compatibility.py. Eight fields that answer one question together, lifted off this
    record because ~50 flat fields had made it the bottleneck for every new surface."""

    strategy_selection: StrategySelection | None = None
    """The update-strategy selector's verdict for this record. Populated in
    service.project.strategy.apply_update_strategy, after populate_stability. None for transitive
    records (v1 scope: the strategy applies to direct dependencies only) or an ignored package."""


@dataclass
class PrefetchedData:
    """Data pre-fetched in bulk before building ScanRecords, passed explicitly to build_records."""

    packages_info: dict[str, Package]
    cve_map: dict[tuple[str, str], set[CVE]]
    versions_since_map: dict[tuple[str, str], list[package_versions.PackageVersion]]
    repositories_info: dict[str, Repository]
    commits: dict[str, list[dict]] = field(default_factory=dict)
    """Repo URL -> last 100 commits (event-censored sample), feeding the gap-based stability
    estimator. Absent keys are unmeasured."""
    activity: dict[str, dict] = field(default_factory=dict)
    """Repo URL -> {issues, pulls, mentionable_users, pinned_titles} from the GraphQL activity
    sample, feeding the engagement-flow trends. Absent keys are unmeasured (no token, non-GitHub
    host, or --no-stability-responsiveness)."""
    readmes: dict[str, str] = field(default_factory=dict)
    """Repo URL -> the first few KB of the README, scanned for a deprecation banner. Absent keys
    are unmeasured (no repo, non-GitHub host, or --no-stability)."""
    data_completeness: DataCompleteness = field(default_factory=DataCompleteness)
    """B4: per-step status (ok/partial/unreachable/rate_limited) for the data sources fetched
    above - see prefetch_scan_data. Carried onto ScanResult so the CLI, export, and exit-code
    logic can all tell a genuinely clean result apart from one built on missing data."""


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
    project_epss: ProjectEpss | None = None
    project_stability: ProjectStability | None = None
    data_completeness: DataCompleteness = field(default_factory=DataCompleteness)
    """Per-step data-source status for this scan. See PrefetchedData.data_completeness."""
    declares_esm: bool = False
    """Whether the project's own manifest declares `"type": "module"` (npm only)"""
    engine_context: EngineContext = field(default_factory=EngineContext)
    """Runtime versions every record's engine_compatible was checked against, and where they came
    from. The sole home for both: the provenance used to be copied onto every ScanRecord as well,
    and the two copies drifted."""
    npm_cli_version: str | None = None
    """Best-effort detected npm CLI version, display-only"""
    source_warnings: list[str] = field(default_factory=list)
    """Non-fatal problems found while assembling the project's sources, e.g. a tree containing more
    than one registry. Carried as a value so each surface decides how to show it - `sources/` used
    to print these itself, which reached stderr even for the JSON front doors."""
