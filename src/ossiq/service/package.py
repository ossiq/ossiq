"""
Data models and service functions for the single-package deep-dive (info/add commands).
"""

from dataclasses import dataclass, field

from ossiq.domain.common import ConstraintType
from ossiq.domain.cve import CVE
from ossiq.domain.package import Package
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion
from ossiq.service.project.models import DependencyDescriptor, ScanRecord, ScanResult
from ossiq.service.project.recommendations import apply_recommendations, clamp_recommendations
from ossiq.service.project.records import calculate_version_age_days
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
        cve_map = sources.cve_database.get_cves_batch([(package, package.latest_version)]).data
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


SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def matches(record: ScanRecord, package_name: str) -> bool:
    """Case-insensitive exact match on dependency_name or package_name (canonical)."""
    needle = package_name.lower()
    return (
        record.dependency_name is not None and record.dependency_name.lower() == needle
    ) or record.package_name.lower() == needle


def collect_transitive_cve_groups(scan_result: ScanResult, package_name: str) -> list[TransitiveCVEGroup]:
    """
    Find all transitive packages downstream of `package_name`
    (i.e. `package_name` appears in their dependency_path) and have CVEs.
    Group by (name, version), sort by worst CVE severity.
    """
    acc: dict[str, TransitiveCVEGroup] = {}
    needle = package_name.lower()

    for record in scan_result.transitive_packages:
        if not record.cve:
            continue
        path = record.dependency_path or []
        if any(p.lower() == needle for p in path):
            key = f"{record.package_name}@{record.installed_version}"
            if key not in acc:
                acc[key] = TransitiveCVEGroup(
                    name=record.package_name,
                    version=record.installed_version,
                    cves=list(record.cve),
                )

    def worst_severity(group: TransitiveCVEGroup) -> int:
        return min(SEVERITY_ORDER.get(c.severity, 99) for c in group.cves)

    return sorted(acc.values(), key=worst_severity)


def build_installed_detail(
    matched: list[ScanRecord],
    scan_result: ScanResult,
    package_name: str,
    sources: AbstractProjectSources,
    settings: Settings,
) -> PackageDetailResult:
    """Build a PackageDetailResult for a package already installed in the project.

    Lives here rather than in `commands/info.py` because both front doors need it: the CLI's
    `info`/`update-context` and the MCP server's `ossiq_evaluate_dependency`/
    `ossiq_evaluate_update_context`. A front door importing from another front door is what
    Architecture rule 6 forbids.
    """
    record = matched[0]
    canonical_name = record.package_name

    # Transitive records are solved with skip_current=True during the scan, so an up-to-date one
    # never gets recommended_version set and `info`'s [03]/[07] blocks would render blank. Solving
    # those here fills the display gap; the registry cache is warm, so no extra HTTP calls.
    #
    # Deliberately transitive-only, and deliberately without apply_update_strategy. Every record
    # with no recommendation used to land here, direct ones included - and be re-run through the
    # whole selector with degraded inputs: a versions_since built from unfiltered
    # package_versions() (prereleases and all, unlike prefetch_versions_since), no
    # transitive_by_name, no installed_names, no validator and no engine context. So `ossiq info`
    # could report a different recommendation from `ossiq status` for the same package, and could
    # surface a prerelease, and could resurrect a recommendation the selector had deliberately
    # withheld. The scan's verdict for a direct record is the verdict; this function does not
    # re-decide it. (The strategy is direct-dependencies-only in v1 anyway - see
    # ScanRecord.strategy_selection - so running it over transitive records was out of scope too.)
    transitive_names = {r.package_name for r in scan_result.transitive_packages}
    needs_solve = [
        r
        for r in matched
        if r.recommended_version is None and r.dependency_path is not None and r.package_name in transitive_names
    ]
    if needs_solve:
        solo_output = dependencies_solver.solve_transitive(
            needs_solve,
            sources.packages_registry,
            scan_result.engine_context.versions,
            allow_prerelease=sources.allow_prerelease,
            cooldown_period=settings.cooldown_period,
        )
        # registry/engine_context/project_declares_esm so the compatibility cluster is written by
        # the same single writer (target_facts.annotate_target_facts) the scan uses, on the same
        # evidence, instead of being left stale.
        apply_recommendations(
            needs_solve,
            solo_output,
            skip_current=False,
            registry=sources.packages_registry,
            project_declares_esm=scan_result.declares_esm,
            engine_context=scan_result.engine_context,
        )
        clamp_recommendations(
            needs_solve,
            sources.packages_registry,
            allow_prerelease=sources.allow_prerelease,
            cooldown_period=settings.cooldown_period,
        )

    # These fetches hit the already-warm in-process cache — no extra HTTP round-trips.
    package = sources.packages_registry.package_info(canonical_name)
    versions = list(sources.packages_registry.package_versions(canonical_name))
    package.downloads_recent = sources.packages_registry.fetch_downloads_recent(canonical_name)

    rec_version = record.recommended_version
    rec_age = record.recommended_version_reason.age_days if record.recommended_version_reason else None

    insight = build_package_insight(
        package=package,
        versions=versions,
        settings=settings,
        recommended_version=rec_version,
        recommended_version_age_days=rec_age,
    )
    warnings = evaluate_package_rules(insight, settings)

    return PackageDetailResult(
        records=matched,
        transitive_cve_groups=collect_transitive_cve_groups(scan_result, package_name),
        project_name=scan_result.project_name,
        packages_registry=scan_result.packages_registry,
        insight=insight,
        warnings=warnings,
    )
