"""
Pydantic models for JSON export schema.

These models define the structure of exported project metrics data.
"""

from datetime import UTC, datetime

from pydantic import BaseModel, Field, field_serializer

from ossiq.domain.common import (
    ConstraintType,
    ExportCsvSchemaVersion,
    ExportJsonSchemaVersion,
    ExportUnknownSchemaVersion,
)
from ossiq.domain.cve import CVE, Severity
from ossiq.service.project import ScanResult


class ExportMetadata(BaseModel):
    """Metadata about the export itself."""

    schema_version: ExportUnknownSchemaVersion | ExportJsonSchemaVersion | ExportCsvSchemaVersion = Field(
        default=ExportUnknownSchemaVersion.UNKNOWN,
        description="Version of the export schema format",
    )
    export_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when the export was generated",
    )

    @field_serializer("export_timestamp")
    def serialize_timestamp(self, dt: datetime) -> str:
        """Serialize datetime to ISO format string."""
        return dt.isoformat()


class ProjectInfo(BaseModel):
    """Basic project information."""

    name: str = Field(description="Project name")
    path: str = Field(description="Absolute path to the project")
    registry: str = Field(description="Package registry type (npm, pypi, etc.)")

    @field_serializer("registry")
    def serialize_registry(self, registry: str) -> str:
        """Serialize registry to lowercase to match schema enum."""
        return registry.lower()


class ProjectSummary(BaseModel):
    """Summary statistics for the scanned project."""

    total_packages: int = Field(description="Total number of packages (production + development)")
    production_packages: int = Field(description="Number of production dependencies")
    development_packages: int = Field(description="Number of development dependencies")
    packages_with_cves: int = Field(description="Number of packages with known CVEs")
    total_cves: int = Field(description="Total number of CVEs across all packages")
    packages_outdated: int = Field(description="Number of packages behind the latest version")


class CVEInfo(BaseModel):
    """CVE information for a package."""

    id: str = Field(description="Primary CVE identifier")
    cve_ids: list[str] = Field(description="All aliases (CVE, GHSA, OSV)")
    source: str = Field(description="CVE database source")
    package_name: str = Field(description="Affected package name")
    package_registry: str = Field(description="Package registry (npm, pypi, etc.)")
    summary: str = Field(description="Vulnerability description")
    severity: Severity = Field(description="Severity level")
    affected_versions: list[str] = Field(description="List of affected versions")
    published: str | None = Field(description="Publication date")
    link: str = Field(description="URL to upstream advisory")

    @classmethod
    def from_domain(cls, cve: CVE) -> "CVEInfo":
        """Convert domain CVE to export model."""
        return cls(
            id=cve.id,
            cve_ids=list(cve.cve_ids),
            source=cve.source.value,
            package_name=cve.package_name,
            package_registry=cve.package_registry.value,
            summary=cve.summary,
            severity=cve.severity,
            affected_versions=list(cve.affected_versions),
            published=cve.published,
            link=cve.link,
        )


class PackageMetrics(BaseModel):
    """Metrics for a single package (schema v1.0–1.2)."""

    package_name: str = Field(description="Package name (canonical registry name)")
    dependency_name: str | None = Field(
        default=None,
        description="Alias name as declared in the project manifest (None when no alias is used)",
    )
    is_optional_dependency: bool = Field(description="Whether this is a development/optional dependency")
    installed_version: str = Field(description="Currently installed version")
    latest_version: str | None = Field(description="Latest available version")
    time_lag_days: int | None = Field(description="Days between installed and latest version")
    releases_lag: int | None = Field(description="Number of releases between installed and latest")
    cve: list[CVEInfo] = Field(default_factory=list, description="Known CVEs for this package")
    dependency_path: list[str] | None = Field(
        default=None,
        description="Ancestor chain leading to this package (None for direct dependencies)",
    )
    version_constraint: str | None = Field(
        default=None,
        description="Version constraint declared in the project manifest (e.g. '^1.2.3', '>=1.0,<2.0')",
    )
    repo_url: str | None = Field(default=None, description="Source code repository URL")
    homepage_url: str | None = Field(default=None, description="Package homepage URL")
    package_url: str | None = Field(default=None, description="Package registry page URL")
    license: list[str] | None = Field(
        default=None, description="SPDX license identifiers parsed from the package license expression"
    )
    purl: str | None = Field(default=None, description="Package URL (PURL) per ECMA-386, e.g. pkg:pypi/requests@2.25.1")
    constraint_type: str = Field(
        default=ConstraintType.DECLARED,
        description=(
            "How the version constraint was applied: DECLARED (loose/default spec), "
            "NARROWED (explicit range with bounds), PINNED (exact version), "
            "ADDITIVE (narrows via constraints file), or OVERRIDE (forces a version "
            "regardless of other requirements)"
        ),
    )
    constraint_source_file: str | None = Field(
        default=None,
        description="File that introduced a non-DECLARED constraint (e.g. 'package.json', 'pyproject.toml')",
    )
    extras: list[str] | None = Field(
        default=None,
        description=(
            "PyPI extras requested for this dependency "
            "(e.g. ['security', 'tests'] from requests[security,tests]); "
            "None for non-PyPI or when no extras are used"
        ),
    )

    @classmethod
    def from_domain(cls, record) -> "PackageMetrics":
        """Convert domain ScanRecord to export model."""
        return cls(
            package_name=record.package_name,
            dependency_name=record.dependency_name,
            is_optional_dependency=record.is_optional_dependency,
            installed_version=record.installed_version,
            latest_version=record.latest_version,
            time_lag_days=record.time_lag_days,
            releases_lag=record.releases_lag,
            cve=[CVEInfo.from_domain(cve) for cve in record.cve],
            dependency_path=record.dependency_path,
            version_constraint=record.version_constraint,
            repo_url=record.repo_url,
            homepage_url=record.homepage_url,
            package_url=record.package_url,
            license=record.license,
            purl=record.purl,
            constraint_type=record.constraint_info.type.value,
            constraint_source_file=(
                record.constraint_info.source_file
                if record.constraint_info and record.constraint_info.type != ConstraintType.DECLARED
                else None
            ),
            extras=record.extras,
        )


# ── v1.3 models ──────────────────────────────────────────────────────────────


class DependencyPath(BaseModel):
    """One traversal path through which a transitive package is reached (schema v1.3+)."""

    path: list[str] = Field(
        description=(
            "Ancestor names from the root's direct child down to (but not including) "
            "this package — e.g. ['react-dom'] for scheduler reached via react-dom"
        )
    )
    dependency_name: str | None = Field(
        default=None,
        description="Alias name declared by the immediate parent (None when no alias is used)",
    )
    version_constraint: str | None = Field(
        default=None,
        description="Version constraint declared by the immediate parent",
    )
    constraint_type: str = Field(
        default=ConstraintType.DECLARED,
        description="How the version constraint was applied: DECLARED, NARROWED, PINNED, ADDITIVE, or OVERRIDE",
    )
    constraint_source_file: str | None = Field(
        default=None,
        description="File that introduced a non-DECLARED constraint",
    )
    extras: list[str] | None = Field(
        default=None,
        description="PyPI extras for this path (None for non-PyPI or when unused)",
    )


class TransitivePackageMetrics(BaseModel):
    """
    Metrics for a transitive package (schema v1.3+).

    One entry per unique (package_name, installed_version). All path-specific
    data is grouped into the dependency_paths list, eliminating duplication of
    invariant fields (CVEs, URLs, version info) across multiple traversal paths.
    """

    package_name: str = Field(description="Package name (canonical registry name)")
    is_optional_dependency: bool = Field(
        description="Whether this is a development/optional dependency; always False for transitive deps"
    )
    installed_version: str = Field(description="Currently installed version")
    latest_version: str | None = Field(description="Latest available version")
    time_lag_days: int | None = Field(description="Days between installed and latest version")
    releases_lag: int | None = Field(description="Number of releases between installed and latest")
    cve: list[CVEInfo] = Field(default_factory=list, description="Known CVEs for this package")
    repo_url: str | None = Field(default=None, description="Source code repository URL")
    homepage_url: str | None = Field(default=None, description="Package homepage URL")
    package_url: str | None = Field(default=None, description="Package registry page URL")
    license: list[str] | None = Field(
        default=None, description="SPDX license identifiers parsed from the package license expression"
    )
    purl: str | None = Field(default=None, description="Package URL (PURL) per ECMA-386")
    dependency_paths: list[DependencyPath] = Field(
        default_factory=list,
        description="All traversal paths through which this package is reached",
    )

    @classmethod
    def from_domain_group(cls, records: list) -> "TransitivePackageMetrics":
        """
        Build one TransitivePackageMetrics from a group of ScanRecords that all share
        the same (package_name, installed_version). Invariant fields are read from
        the first record; path-specific fields are extracted from each record.
        """
        first = records[0]
        return cls(
            package_name=first.package_name,
            is_optional_dependency=first.is_optional_dependency,
            installed_version=first.installed_version,
            latest_version=first.latest_version,
            time_lag_days=first.time_lag_days,
            releases_lag=first.releases_lag,
            cve=[CVEInfo.from_domain(cve) for cve in first.cve],
            repo_url=first.repo_url,
            homepage_url=first.homepage_url,
            package_url=first.package_url,
            license=first.license,
            purl=first.purl,
            dependency_paths=[
                DependencyPath(
                    path=rec.dependency_path or [],
                    dependency_name=rec.dependency_name,
                    version_constraint=rec.version_constraint,
                    constraint_type=rec.constraint_info.type.value,
                    constraint_source_file=(
                        rec.constraint_info.source_file
                        if rec.constraint_info and rec.constraint_info.type != ConstraintType.DECLARED
                        else None
                    ),
                    extras=rec.extras,
                )
                for rec in records
            ],
        )


# ── Export data containers ────────────────────────────────────────────────────


class ExportDataBase(BaseModel):
    """Common fields shared across all export schema versions."""

    metadata: ExportMetadata = Field(description="Export metadata")
    project: ProjectInfo = Field(description="Project information")
    summary: ProjectSummary = Field(description="Summary statistics")
    production_packages: list[PackageMetrics] = Field(
        default_factory=list,
        description="Production dependency metrics",
    )
    development_packages: list[PackageMetrics] = Field(
        default_factory=list,
        description="Development dependency metrics",
    )


class ExportData(ExportDataBase):
    """Root export data structure (schema v1.0–1.2)."""

    transitive_packages: list[PackageMetrics] = Field(
        default_factory=list,
        description="Transitive dependency metrics (all paths, production edges only)",
    )


class ExportDataV13(ExportDataBase):
    """Root export data structure (schema v1.3+)."""

    transitive_packages: list[TransitivePackageMetrics] = Field(
        default_factory=list,
        description="Transitive dependency metrics, one entry per unique (package_name, installed_version)",
    )


# ── Factory ───────────────────────────────────────────────────────────────────


def _build_v1_3_transitive(records) -> list[TransitivePackageMetrics]:
    groups: dict[tuple[str, str], list] = {}
    for r in records:
        groups.setdefault((r.package_name, r.installed_version), []).append(r)
    return [TransitivePackageMetrics.from_domain_group(g) for g in groups.values()]


def build_export_data(
    data: ScanResult,
    schema_version: ExportJsonSchemaVersion | ExportCsvSchemaVersion,
) -> ExportData | ExportDataV13:
    """
    Create export data from ScanResult domain model.

    Returns ExportDataV13 for schema v1.3+; ExportData (v1.0–1.2) otherwise.
    """
    all_direct = data.production_packages + data.optional_packages
    total_cves = sum(len(pkg.cve) for pkg in all_direct)
    packages_with_cves = sum(1 for pkg in all_direct if len(pkg.cve) > 0)
    packages_outdated = sum(1 for pkg in all_direct if pkg.versions_diff_index.diff_index > 0)

    metadata = ExportMetadata(schema_version=schema_version)
    project = ProjectInfo(
        name=data.project_name,
        path=data.project_path,
        registry=data.packages_registry,
    )
    summary = ProjectSummary(
        total_packages=len(all_direct),
        production_packages=len(data.production_packages),
        development_packages=len(data.optional_packages),
        packages_with_cves=packages_with_cves,
        total_cves=total_cves,
        packages_outdated=packages_outdated,
    )
    production = [PackageMetrics.from_domain(pkg) for pkg in data.production_packages]
    development = [PackageMetrics.from_domain(pkg) for pkg in data.optional_packages]

    if schema_version == ExportJsonSchemaVersion.V1_3:
        return ExportDataV13(
            metadata=metadata,
            project=project,
            summary=summary,
            production_packages=production,
            development_packages=development,
            transitive_packages=_build_v1_3_transitive(data.transitive_packages),
        )

    return ExportData(
        metadata=metadata,
        project=project,
        summary=summary,
        production_packages=production,
        development_packages=development,
        transitive_packages=[PackageMetrics.from_domain(pkg) for pkg in data.transitive_packages],
    )
