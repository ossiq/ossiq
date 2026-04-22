import { markRaw } from 'vue'
import type { OSSIQExportSchemaV13, CVEInfo, DependencyTreeNode } from '@/types/report'
import type { ConstraintType, DirectEntry, EdgeData, PackageRegistry, RegistryEntry, Severity } from '@/types/registry'

const SEVERITY_RANK: Record<string, number> = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }

function maxSeverity(cves: CVEInfo[]): Severity | null {
  if (!cves.length) return null
  return cves.reduce((best, c) =>
    (SEVERITY_RANK[c.severity] ?? 0) > (SEVERITY_RANK[best.severity] ?? 0) ? c : best,
  ).severity as Severity
}

export function buildPackageRegistry(report: OSSIQExportSchemaV13): PackageRegistry {
  const constraintTypeMap = report.constraint_type_map

  // Step 1: Build transitive package lookup by id
  const byId = new Map<number, RegistryEntry>()
  for (const pkg of report.transitive_packages) {
    byId.set(pkg.id, {
      id: pkg.id,
      package_name: pkg.package_name,
      installed_version: pkg.installed_version,
      latest_version: pkg.latest_version ?? null,
      time_lag_days: pkg.time_lag_days ?? null,
      releases_lag: pkg.releases_lag ?? null,
      cve: pkg.cve ?? [],
      severity: maxSeverity(pkg.cve ?? []),
      constraint_source_file: pkg.constraint_source_file,
      repo_url: pkg.repo_url ?? null,
      homepage_url: pkg.homepage_url ?? null,
      package_url: pkg.package_url ?? null,
      license: pkg.license ?? null,
      purl: pkg.purl ?? null,
      childEdges: new Map(),
    })
  }

  // Precompute highest CVE severity per package name (across all package types)
  const cveMap = new Map<string, Severity>()
  for (const pkg of [...report.production_packages, ...report.development_packages, ...report.transitive_packages]) {
    const cves = pkg.cve ?? []
    if (!cves.length) continue
    const sev = maxSeverity(cves)
    if (!sev) continue
    const existing = cveMap.get(pkg.package_name)
    if (!existing || (SEVERITY_RANK[sev] ?? 0) > (SEVERITY_RANK[existing] ?? 0)) {
      cveMap.set(pkg.package_name, sev)
    }
  }

  // Step 2: Build direct (production) entries
  const directEntries = new Map<string, DirectEntry>()
  for (const pkg of report.production_packages) {
    directEntries.set(pkg.package_name, {
      package_name: pkg.package_name,
      installed_version: pkg.installed_version,
      latest_version: pkg.latest_version ?? null,
      time_lag_days: pkg.time_lag_days ?? null,
      releases_lag: pkg.releases_lag ?? null,
      cve: pkg.cve ?? [],
      severity: cveMap.get(pkg.package_name) ?? null,
      constraint_type: (pkg.constraint_type ?? null) as ConstraintType | null,
      constraint_source_file: pkg.constraint_source_file ?? null,
      version_constraint: pkg.version_constraint ?? null,
      childRefs: [],
    })
  }

  // Step 3: Walk dependency_tree to populate childEdges and childRefs
  function walkNode(treeNode: DependencyTreeNode, parentRegistryId: number | null, parentDirectName: string | null) {
    const ct = (constraintTypeMap[treeNode.ct] ?? 'DECLARED') as ConstraintType
    const edgeData: EdgeData = { ct }
    if (treeNode.version_constraint) edgeData.version_constraint = treeNode.version_constraint
    if (treeNode.dependency_name) edgeData.dependency_name = treeNode.dependency_name
    if (treeNode.extras?.length) edgeData.extras = treeNode.extras

    if (parentDirectName !== null) {
      directEntries.get(parentDirectName)?.childRefs.push({ ref: treeNode.ref, edgeData })
    } else if (parentRegistryId !== null) {
      byId.get(parentRegistryId)?.childEdges.set(treeNode.ref, edgeData)
    }

    for (const child of treeNode.children ?? []) {
      walkNode(child, treeNode.ref, null)
    }
  }

  for (const treeRoot of report.dependency_tree ?? []) {
    for (const child of treeRoot.children ?? []) {
      walkNode(child, null, treeRoot.package_name)
    }
  }

  return markRaw({ byId, directEntries, constraintTypeMap })
}
