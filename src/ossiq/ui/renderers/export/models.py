"""
Pydantic models for JSON export schema.

These models define the structure of exported project metrics data.
Version 1.0 schema includes metadata, project info, summary statistics,
and detailed package information.
"""

from datetime import UTC, datetime

from pydantic import BaseModel, Field, field_serializer

from ossiq.domain.common import ExportJsonSchemaVersion
from ossiq.domain.cve import CVE, Severity

CURRENT_SCHEMA_VERSION = ExportJsonSchemaVersion.V1_0


class ExportMetadata(BaseModel):
    """Metadata about the export itself."""

    schema_version: ExportJsonSchemaVersion = Field(
        default=CURRENT_SCHEMA_VERSION,
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
    """Metrics for a single package."""

    package_name: str = Field(description="Package name")
    is_optional_dependency: bool = Field(description="Whether this is a development/optional dependency")
    installed_version: str = Field(description="Currently installed version")
    latest_version: str | None = Field(description="Latest available version")
    time_lag_days: int | None = Field(description="Days between installed and latest version")
    releases_lag: int | None = Field(description="Number of releases between installed and latest")
    cve: list[CVEInfo] = Field(default_factory=list, description="Known CVEs for this package")

    @classmethod
    def from_domain(cls, record) -> "PackageMetrics":
        """Convert domain ProjectMetricsRecord to export model."""
        return cls(
            package_name=record.package_name,
            is_optional_dependency=record.is_dev_dependency,
            installed_version=record.installed_version,
            latest_version=record.latest_version,
            time_lag_days=record.time_lag_days,
            releases_lag=record.releases_lag,
            cve=[CVEInfo.from_domain(cve) for cve in record.cve],
        )


class ExportData(BaseModel):
    """Root export data structure (schema version 1.0)."""

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

    @classmethod
    def from_project_metrics(cls, data) -> "ExportData":
        """
        Create ExportData from ProjectMetrics domain model.

        Args:
            data: ProjectMetrics instance from scan service

        Returns:
            ExportData with all fields populated
        """
        # Calculate summary statistics
        all_packages = data.production_packages + data.development_packages
        total_cves = sum(len(pkg.cve) for pkg in all_packages)
        packages_with_cves = sum(1 for pkg in all_packages if len(pkg.cve) > 0)
        packages_outdated = sum(1 for pkg in all_packages if pkg.versions_diff_index.diff_index > 0)

        return cls(
            metadata=ExportMetadata(),
            project=ProjectInfo(
                name=data.project_name,
                path=data.project_path,
                registry=data.packages_registry,
            ),
            summary=ProjectSummary(
                total_packages=len(all_packages),
                production_packages=len(data.production_packages),
                development_packages=len(data.development_packages),
                packages_with_cves=packages_with_cves,
                total_cves=total_cves,
                packages_outdated=packages_outdated,
            ),
            production_packages=[PackageMetrics.from_domain(pkg) for pkg in data.production_packages],
            development_packages=[PackageMetrics.from_domain(pkg) for pkg in data.development_packages],
        )
