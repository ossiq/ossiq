"""
Data models and service functions for the single-package deep-dive (info/add commands).
"""

from dataclasses import dataclass, field

from ossiq.domain.common import ConstraintType
from ossiq.domain.cve import CVE
from ossiq.domain.package import Package
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion
from ossiq.service.project import DependencyDescriptor, ScanRecord, calculate_version_age_days
from ossiq.settings import Settings
from ossiq.solver import dependencies_solver
from ossiq.solver.reason import RecommendationReason
from ossiq.sources.core import AbstractProjectSources

RULE_SINGLE_VERSION = "SINGLE_VERSION"
RULE_SINGLE_MAINTAINER = "SINGLE_MAINTAINER"
RULE_COOLDOWN_PERIOD = "COOLDOWN_PERIOD"


@dataclass
class TransitiveCVEGroup:
    name: str
    version: str
    cves: list[CVE]


@dataclass(frozen=True)
class PackageWarning:
    """A warning produced by the package rule evaluator."""

    rule_id: str
    message: str
    severity: str  # "warning" | "critical"


@dataclass
class PackageInsight:
    """Health metrics computed for the info/add command flow."""

    versions_count: int
    maintainers_count: int | None
    downloads_recent: int | None
    latest_version: str | None
    latest_version_age_days: int | None
    recommended_version: str | None
    recommended_version_age_days: int | None
    cooldown_days_remaining: int | None


@dataclass
class PackageDetailResult:
    """Result passed to the info/add renderer."""

    records: list[ScanRecord]
    transitive_cve_groups: list[TransitiveCVEGroup]
    project_name: str
    packages_registry: str
    insight: PackageInsight | None = None
    warnings: list[PackageWarning] = field(default_factory=list)
    is_prospective: bool = False
    prospective_name: str | None = None
    prospective_cves: list[CVE] = field(default_factory=list)
    prospective_package: Package | None = None
    prospective_reason: RecommendationReason | None = None


def build_package_insight(
    package: Package,
    versions: list[PackageVersion],
    settings: Settings,
    recommended_version: str | None = None,
    recommended_version_age_days: int | None = None,
) -> PackageInsight:
    """Compute health metrics from a package's metadata and full version list."""
    non_prerelease = [v for v in versions if not v.is_prerelease]
    versions_count = len(non_prerelease)

    latest_version_age_days = (
        calculate_version_age_days(versions, package.latest_version) if package.latest_version else None
    )

    cooldown_days_remaining = None
    if latest_version_age_days is not None and latest_version_age_days < settings.cooldown_period:
        cooldown_days_remaining = settings.cooldown_period - latest_version_age_days

    return PackageInsight(
        versions_count=versions_count,
        maintainers_count=package.maintainers_count,
        downloads_recent=package.downloads_recent,
        latest_version=package.latest_version,
        latest_version_age_days=latest_version_age_days,
        recommended_version=recommended_version,
        recommended_version_age_days=recommended_version_age_days,
        cooldown_days_remaining=cooldown_days_remaining,
    )


def evaluate_package_rules(insight: PackageInsight, settings: Settings) -> list[PackageWarning]:
    """Evaluate package health rules and return a list of warnings."""
    warnings: list[PackageWarning] = []

    if insight.versions_count == 1:
        warnings.append(
            PackageWarning(
                rule_id=RULE_SINGLE_VERSION,
                message="Only one version published — possible typosquatting risk",
                severity="critical",
            )
        )

    if insight.maintainers_count is not None and insight.maintainers_count == 1:
        warnings.append(
            PackageWarning(
                rule_id=RULE_SINGLE_MAINTAINER,
                message="Single maintainer — bus factor risk (package depends on one person)",
                severity="warning",
            )
        )

    if insight.cooldown_days_remaining and insight.cooldown_days_remaining > 0:
        remaining = insight.cooldown_days_remaining
        msg = f"Latest version is new — {remaining} days until {settings.cooldown_period}-day cooldown expires"
        warnings.append(PackageWarning(rule_id=RULE_COOLDOWN_PERIOD, message=msg, severity="warning"))

    return warnings


def fetch_prospective_detail(
    package_name: str,
    sources: AbstractProjectSources,
    settings: Settings,
) -> PackageDetailResult:
    """Fetch health insights for a package not yet installed in the project."""
    package = sources.packages_registry.package_info(package_name)
    versions = list(sources.packages_registry.package_versions(package_name))

    # Separate HTTP call — only done for targeted info/add, not the full scan
    package.downloads_recent = sources.packages_registry.fetch_downloads_recent(package_name)

    pkg_canonical = package.canonical_name or package.name

    cves: list[CVE] = []
    if package.latest_version:
        cve_map = sources.cve_database.get_cves_batch([(package, package.latest_version)])
        cves = list(cve_map.get((package.name, package.latest_version), set()))

    # Run solver (unconstrained) to get proper recommendation + full rationale.
    # "0.0.0" as installed version ensures solver always finds a recommendation.
    descriptor = DependencyDescriptor(
        name=pkg_canonical,
        canonical_name=pkg_canonical,
        version="0.0.0",
        is_optional=False,
        dependency_path=None,
        version_constraint=None,
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=""),
        all_constraints=[],
    )
    solver_output = dependencies_solver.solve_direct(
        [descriptor],
        sources.packages_registry,
        {},
        allow_prerelease=sources.allow_prerelease,
        cooldown_period=settings.cooldown_period,
    )
    recommended_version = solver_output.recommendations.get(pkg_canonical) or package.latest_version
    prospective_reason = solver_output.reasons.get(pkg_canonical)
    recommended_age = calculate_version_age_days(versions, recommended_version) if recommended_version else None

    insight = build_package_insight(
        package=package,
        versions=versions,
        settings=settings,
        recommended_version=recommended_version,
        recommended_version_age_days=recommended_age,
    )
    warnings = evaluate_package_rules(insight, settings)

    return PackageDetailResult(
        records=[],
        transitive_cve_groups=[],
        project_name="",
        packages_registry=sources.packages_registry.package_registry.value.lower(),
        insight=insight,
        warnings=warnings,
        is_prospective=True,
        prospective_name=pkg_canonical,
        prospective_cves=cves,
        prospective_package=package,
        prospective_reason=prospective_reason,
    )
