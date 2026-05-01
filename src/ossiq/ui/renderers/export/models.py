"""
Pydantic models for JSON export schema.

These models define the structure of exported project metrics data.
"""

from datetime import UTC, datetime

from pydantic import BaseModel, Field, field_serializer, model_serializer

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
    is_prerelease: bool = Field(default=False, description="Whether the installed version is a pre-release")
    is_yanked: bool = Field(default=False, description="Whether the installed version is yanked or unpublished")
    is_deprecated: bool = Field(
        default=False, description="Whether the installed package or version is deprecated (npm-only)"
    )  # noqa: E501
    is_package_unpublished: bool = Field(
        default=False, description="Whether the entire package has been removed from the registry (npm-only)"
    )  # noqa: E501

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
            is_prerelease=record.is_installed_prerelease,
            is_yanked=record.is_installed_yanked,
            is_deprecated=record.is_installed_deprecated,
            is_package_unpublished=record.is_installed_package_unpublished,
        )


# ── v1.3 models ──────────────────────────────────────────────────────────────

CONSTRAINT_TYPE_MAP: list[str] = ["DECLARED", "NARROWED", "PINNED", "ADDITIVE", "OVERRIDE"]
_CT_INDEX: dict[str, int] = {v: i for i, v in enumerate(CONSTRAINT_TYPE_MAP)}


class DependencyTreeNode(BaseModel):
    """One node in the dependency tree, carrying edge-specific constraint data."""

    ref: int = Field(description="Index into the transitive_packages array")
    ct: int = Field(description="Index into the top-level constraint_type_map array")
    version_constraint: str | None = Field(
        default=None,
        description="Version constraint declared by the immediate parent",
    )
    dependency_name: str | None = Field(
        default=None,
        description="Alias name declared by the immediate parent (None when no alias is used)",
    )
    extras: list[str] | None = Field(
        default=None,
        description="PyPI extras for this dependency (None for non-PyPI or when unused)",
    )
    children: list["DependencyTreeNode"] = Field(
        default_factory=list,
        description="Transitive packages directly required by this package",
    )

    @model_serializer(mode="wrap")
    def _compact(self, handler):
        d = handler(self)
        return {k: v for k, v in d.items() if not (v is None or (isinstance(v, list) and len(v) == 0))}


DependencyTreeNode.model_rebuild()


class DependencyTreeRoot(BaseModel):
    """Root entry in the dependency tree, anchored at a direct production dependency."""

    package_name: str = Field(description="Name of the direct production dependency")
    children: list[DependencyTreeNode] = Field(
        default_factory=list,
        description="Transitive packages directly required by this production dependency",
    )

    @model_serializer(mode="wrap")
    def _compact(self, handler):
        d = handler(self)
        return {k: v for k, v in d.items() if not (v is None or (isinstance(v, list) and len(v) == 0))}


class TransitivePackageMetrics(BaseModel):
    """
    Metrics for a transitive package (schema v1.3+).

    One entry per unique (package_name, installed_version). Path-specific data
    (constraint type, version constraint, ancestry) lives in the dependency_tree
    top-level field; this model holds only package metrics.
    """

    id: int = Field(description="Zero-based index into the transitive_packages array (used for ref cross-reference)")
    package_name: str = Field(description="Package name (canonical registry name)")
    is_optional_dependency: bool = Field(
        description="Whether this is a development/optional dependency; always False for transitive deps"
    )
    installed_version: str = Field(description="Currently installed version")
    latest_version: str | None = Field(description="Latest available version")
    time_lag_days: int | None = Field(description="Days between installed and latest version")
    releases_lag: int | None = Field(description="Number of releases between installed and latest")
    cve: list[CVEInfo] = Field(default_factory=list, description="Known CVEs for this package")
    constraint_source_file: str | None = Field(
        default=None,
        description="File that introduced a non-DECLARED constraint for this package",
    )
    repo_url: str | None = Field(default=None, description="Source code repository URL")
    homepage_url: str | None = Field(default=None, description="Package homepage URL")
    package_url: str | None = Field(default=None, description="Package registry page URL")
    license: list[str] | None = Field(
        default=None, description="SPDX license identifiers parsed from the package license expression"
    )
    purl: str | None = Field(default=None, description="Package URL (PURL) per ECMA-386")
    is_prerelease: bool = Field(default=False, description="Whether the installed version is a pre-release")
    is_yanked: bool = Field(default=False, description="Whether the installed version is yanked or unpublished")
    is_deprecated: bool = Field(
        default=False, description="Whether the installed package or version is deprecated (npm-only)"
    )  # noqa: E501
    is_package_unpublished: bool = Field(
        default=False, description="Whether the entire package has been removed from the registry (npm-only)"
    )  # noqa: E501

    @classmethod
    def from_domain_group(
        cls, idx: int, records: list, constraint_source_file: str | None
    ) -> "TransitivePackageMetrics":
        """Build one TransitivePackageMetrics from a group of ScanRecords sharing (package_name, installed_version)."""
        first = records[0]
        return cls(
            id=idx,
            package_name=first.package_name,
            is_optional_dependency=first.is_optional_dependency,
            installed_version=first.installed_version,
            latest_version=first.latest_version,
            time_lag_days=first.time_lag_days,
            releases_lag=first.releases_lag,
            cve=[CVEInfo.from_domain(cve) for cve in first.cve],
            constraint_source_file=constraint_source_file,
            repo_url=first.repo_url,
            homepage_url=first.homepage_url,
            package_url=first.package_url,
            license=first.license,
            purl=first.purl,
            is_prerelease=first.is_installed_prerelease,
            is_yanked=first.is_installed_yanked,
            is_deprecated=first.is_installed_deprecated,
            is_package_unpublished=first.is_installed_package_unpublished,
        )

    @model_serializer(mode="wrap")
    def _compact(self, handler):
        d = handler(self)
        return {k: v for k, v in d.items() if not (v is None or (isinstance(v, list) and len(v) == 0))}


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

    constraint_type_map: list[str] = Field(
        default_factory=lambda: list(CONSTRAINT_TYPE_MAP),
        description="Lookup table for ct integer field in dependency_tree nodes",
    )
    transitive_packages: list[TransitivePackageMetrics] = Field(
        default_factory=list,
        description="Transitive dependency metrics, one entry per unique (package_name, installed_version)",
    )
    dependency_tree: list[DependencyTreeRoot] = Field(
        default_factory=list,
        description="Dependency tree rooted at direct production dependencies; nodes carry edge constraint data",
    )


# ── Factory ───────────────────────────────────────────────────────────────────


def _build_v1_3_data(
    records: list,
) -> tuple[list[TransitivePackageMetrics], list[DependencyTreeRoot]]:
    """Build the deduplicated transitive list and the dependency tree from raw ScanRecords."""
    groups: dict[tuple[str, str], list] = {}
    first_csf: dict[tuple[str, str], str | None] = {}
    for r in records:
        key = (r.package_name, r.installed_version)
        groups.setdefault(key, []).append(r)
        if key not in first_csf:
            first_csf[key] = None
        if first_csf[key] is None and r.constraint_info and r.constraint_info.type != ConstraintType.DECLARED:
            first_csf[key] = r.constraint_info.source_file

    pkg_to_idx = {key: i for i, key in enumerate(groups.keys())}
    transitive = [
        TransitivePackageMetrics.from_domain_group(i, g, first_csf[key]) for i, (key, g) in enumerate(groups.items())
    ]
    tree = _build_dependency_tree(records, pkg_to_idx)
    return transitive, tree


def _build_dependency_tree(
    records: list,
    pkg_to_idx: dict[tuple[str, str], int],
) -> list[DependencyTreeRoot]:
    """Build a tree of DependencyTreeRoot from flat ScanRecords sorted by path length."""
    roots: dict[str, DependencyTreeRoot] = {}
    node_registry: dict[str, DependencyTreeNode] = {}

    for rec in sorted(records, key=lambda r: len(r.dependency_path or [])):
        path = rec.dependency_path or []
        if not path:
            continue

        idx = pkg_to_idx.get((rec.package_name, rec.installed_version))
        if idx is None:
            continue

        leaf_path_key = "/".join(path + [rec.package_name])
        if leaf_path_key in node_registry:
            continue

        direct_dep = path[0]
        if direct_dep not in roots:
            roots[direct_dep] = DependencyTreeRoot(package_name=direct_dep, children=[])

        dep_name = rec.dependency_name if rec.dependency_name != rec.package_name else None
        leaf_node = DependencyTreeNode(
            ref=idx,
            ct=_CT_INDEX[rec.constraint_info.type.value],
            version_constraint=rec.version_constraint,
            dependency_name=dep_name,
            extras=rec.extras,
            children=[],
        )

        if len(path) == 1:
            roots[direct_dep].children.append(leaf_node)
        else:
            parent_node = node_registry.get("/".join(path))
            if parent_node is None:
                continue
            parent_node.children.append(leaf_node)

        node_registry[leaf_path_key] = leaf_node

    return list(roots.values())


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

    if schema_version in (ExportJsonSchemaVersion.V1_3, ExportJsonSchemaVersion.V1_4):
        transitive, tree = _build_v1_3_data(data.transitive_packages)
        return ExportDataV13(
            metadata=metadata,
            project=project,
            summary=summary,
            production_packages=production,
            development_packages=development,
            transitive_packages=transitive,
            dependency_tree=tree,
        )

    return ExportData(
        metadata=metadata,
        project=project,
        summary=summary,
        production_packages=production,
        development_packages=development,
        transitive_packages=[PackageMetrics.from_domain(pkg) for pkg in data.transitive_packages],
    )
