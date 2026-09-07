import { ref, computed } from 'vue'
import { useOssiqStore } from '@/stores/ossiq'
import type { DependencyTreeNode, PackageMetrics, TransitivePackageMetrics } from '@/types/report'

export type DriftStatus = 'LATEST' | 'DIFF_MAJOR' | 'DIFF_MINOR' | 'DIFF_PATCH'
export type SortDirection = 'none' | 'asc' | 'desc'
export type SortColumn =
  | 'name'
  | 'cve'
  | 'drift'
  | 'installed'
  | 'latest'
  | 'releases'
  | 'timeLag'
  | 'versionAge'
  | 'epss'

export type WhatsNext =
  | 'Check for the Fix'
  | 'Find alternative'
  | 'Consider alternative'
  | 'Check Release Notes'
  | 'Update Immediately'
  | 'Constrained. Check newer version'
  | null

export interface ReportRow {
  pkg: PackageMetrics
  isDev: boolean
  driftStatus: DriftStatus
  whatsNext: WhatsNext
  timeLagDisplay: string
  versionAgeDisplay: string
  cveCount: number
  registryUrl: string
  license: string[]
  hasTransitiveCve: boolean
  isPrerelease: boolean
  isYanked: boolean
  isDeprecated: boolean
  isPackageUnpublished: boolean
}

export function computeDriftStatus(
  installed: string,
  latest: string | null,
): DriftStatus {
  if (!latest || installed === latest) return 'LATEST'
  const [iMaj, iMin] = installed.split('.').map(Number)
  const [lMaj, lMin] = latest.split('.').map(Number)
  if (iMaj !== lMaj) return 'DIFF_MAJOR'
  if (iMin !== lMin) return 'DIFF_MINOR'
  return 'DIFF_PATCH'
}

// At or above a 10% chance of exploitation a CVE is an active threat (mirrors
// EPSS_EXPLOIT_THRESHOLD in the CLI's risk/triage.py).
const EPSS_EXPLOIT_THRESHOLD = 0.1

export const WHATS_NEXT_CLASS: Record<string, string> = {
  'Check for the Fix': 'text-red-700',
  'Find alternative': 'text-red-700',
  'Consider alternative': 'text-amber-600',
  'Check Release Notes': 'text-slate-600',
  'Update Immediately': 'text-slate-600',
  'Constrained. Check newer version': 'text-amber-600',
}

// The single next action for a package, first match wins. Mirrors whats_next() in the CLI's
// ui/renderers/impact_utils.py: an exploitable CVE outranks a dying upstream, which outranks drift.
export function computeWhatsNext(opts: {
  driftStatus: DriftStatus
  cveCount: number
  epss: number | null | undefined
  maintenanceState: string | null | undefined
  installedVersion: string
  recommendedVersion: string | null | undefined
  versionConstraint: string | null | undefined
}): WhatsNext {
  const {
    driftStatus,
    cveCount,
    epss,
    maintenanceState,
    installedVersion,
    recommendedVersion,
    versionConstraint,
  } = opts
  if (cveCount > 0 && epss != null && epss >= EPSS_EXPLOIT_THRESHOLD) return 'Check for the Fix'
  if (driftStatus === 'LATEST' && (maintenanceState === 'abandoned' || maintenanceState === 'deprecated'))
    return 'Find alternative'
  if (maintenanceState === 'winding_down') return 'Consider alternative'
  if (driftStatus === 'DIFF_MAJOR') return 'Check Release Notes'
  if (driftStatus === 'DIFF_MINOR' || driftStatus === 'DIFF_PATCH') {
    // Recommended is the solver's pick clamped into the declared range; when it is not a move
    // away from what's installed, "Update Immediately" would name no target.
    if (recommendedVersion != null && recommendedVersion !== installedVersion) return 'Update Immediately'
    if (recommendedVersion == null && !versionConstraint) return 'Update Immediately'
    return 'Constrained. Check newer version'
  }
  return null
}

// Whether a package needs the reader's attention. Mirrors needs_action() in the CLI's
// ui/renderers/status/console.py (constraint_conflict is not in the export, so it is omitted).
export function isActionable(row: ReportRow): boolean {
  const p = row.pkg
  return (
    row.driftStatus !== 'LATEST' ||
    row.cveCount > 0 ||
    p.maintenance_state === 'abandoned' ||
    p.maintenance_state === 'deprecated' ||
    (p.recommended_version != null && p.recommended_version !== p.installed_version)
  )
}

export function formatTimeLag(days: number | null): string {
  if (days === null || days === 0) return '0d'
  if (days >= 365) return `${Math.round(days / 365)}y`
  if (days >= 30) return `${Math.round(days / 30)}m`
  return `${days}d`
}

function registryUrl(registry: string, packageName: string): string {
  if (registry === 'npm') return `https://npmjs.com/package/${packageName}`
  if (registry === 'pypi') return `https://pypi.org/project/${packageName}`
  return '#'
}

const DRIFT_SORT_ORDER: Record<DriftStatus, number> = {
  DIFF_MAJOR: 0,
  DIFF_MINOR: 1,
  DIFF_PATCH: 2,
  LATEST: 3,
}

export function useReportFilters() {
  const store = useOssiqStore()

  // Filter state
  const searchText = ref('')
  const showAll = ref(false) // false = only packages that need action
  const packageTypeFilter = ref<'all' | 'production' | 'development'>('all')
  const driftStatusFilter = ref<DriftStatus | 'all'>('all')
  const releaseDistanceFilter = ref<number | null>(null) // min threshold
  const timeLagFilter = ref<{ min?: number; max?: number } | null>(null)

  // Sort state
  const sortColumn = ref<SortColumn | null>(null)
  const sortDirection = ref<SortDirection>('none')

  // Build set of direct package names that have transitive deps with CVEs
  const transitiveCveSet = computed<Set<string>>(() => {
    const set = new Set<string>()
    const packages = store.transitivePackages as TransitivePackageMetrics[]

    function collect(nodes: DependencyTreeNode[], rootName: string) {
      for (const node of nodes) {
        if ((packages[node.ref]?.cve?.length ?? 0) > 0) set.add(rootName)
        collect(node.children ?? [], rootName)
      }
    }

    for (const root of store.report?.dependency_tree ?? []) {
      collect(root.children ?? [], root.package_name)
    }
    return set
  })

  // Build unified row list
  const allRows = computed<ReportRow[]>(() => {
    const registry = store.report?.project.registry ?? 'npm'
    const toRow = (pkg: PackageMetrics, isDev: boolean): ReportRow => {
      const driftStatus = computeDriftStatus(pkg.installed_version, pkg.latest_version)
      return {
        pkg,
        isDev,
        driftStatus,
        whatsNext: computeWhatsNext({
          driftStatus,
          cveCount: pkg.cve.length,
          epss: pkg.epss,
          maintenanceState: pkg.maintenance_state,
          installedVersion: pkg.installed_version,
          recommendedVersion: pkg.recommended_version,
          versionConstraint: pkg.version_constraint,
        }),
        timeLagDisplay: formatTimeLag(pkg.time_lag_days),
        versionAgeDisplay: formatTimeLag(pkg.version_age_days),
        cveCount: pkg.cve.length,
        registryUrl: registryUrl(registry, pkg.package_name),
        license: pkg.license ?? [],
        hasTransitiveCve: transitiveCveSet.value.has(pkg.package_name),
        isPrerelease: pkg.is_prerelease ?? false,
        isYanked: pkg.is_yanked ?? false,
        isDeprecated: pkg.is_deprecated ?? false,
        isPackageUnpublished: pkg.is_package_unpublished ?? false,
      }
    }
    return [
      ...(store.productionPackages as PackageMetrics[]).map((pkg) => toRow(pkg, false)),
      ...(store.developmentPackages as PackageMetrics[]).map((pkg) => toRow(pkg, true)),
    ]
  })

  // Apply filters
  const filteredRows = computed<ReportRow[]>(() => {
    let rows = allRows.value

    // Actionable-only (default): hide up-to-date, maintained packages with nothing to do
    if (!showAll.value) {
      rows = rows.filter(isActionable)
    }

    // Text search
    if (searchText.value) {
      const term = searchText.value.toLowerCase()
      rows = rows.filter((r) => r.pkg.package_name.toLowerCase().includes(term))
    }

    // Package type
    if (packageTypeFilter.value === 'production') {
      rows = rows.filter((r) => !r.isDev)
    } else if (packageTypeFilter.value === 'development') {
      rows = rows.filter((r) => r.isDev)
    }

    // Drift status
    if (driftStatusFilter.value !== 'all') {
      rows = rows.filter((r) => r.driftStatus === driftStatusFilter.value)
    }

    // Release distance
    if (releaseDistanceFilter.value !== null) {
      const min = releaseDistanceFilter.value
      rows = rows.filter((r) => (r.pkg.releases_lag ?? 0) >= min)
    }

    // Time lag
    if (timeLagFilter.value !== null) {
      const { min, max } = timeLagFilter.value
      rows = rows.filter((r) => {
        const days = r.pkg.time_lag_days ?? 0
        if (min !== undefined && days < min) return false
        if (max !== undefined && days > max) return false
        return true
      })
    }

    return rows
  })

  // Apply sorting
  const sortedRows = computed<ReportRow[]>(() => {
    const rows = [...filteredRows.value]
    if (!sortColumn.value || sortDirection.value === 'none') return rows

    const col = sortColumn.value
    const dir = sortDirection.value

    rows.sort((a, b) => {
      let cmp = 0
      switch (col) {
        case 'name':
          cmp = a.pkg.package_name.localeCompare(b.pkg.package_name)
          break
        case 'cve':
          cmp = a.cveCount - b.cveCount
          break
        case 'drift':
          cmp = DRIFT_SORT_ORDER[a.driftStatus] - DRIFT_SORT_ORDER[b.driftStatus]
          break
        case 'installed':
          cmp = a.pkg.installed_version.localeCompare(b.pkg.installed_version)
          break
        case 'latest':
          cmp = (a.pkg.latest_version ?? '').localeCompare(b.pkg.latest_version ?? '')
          break
        case 'releases':
          cmp = (a.pkg.releases_lag ?? 0) - (b.pkg.releases_lag ?? 0)
          break
        case 'timeLag':
          cmp = (a.pkg.time_lag_days ?? 0) - (b.pkg.time_lag_days ?? 0)
          break
        case 'versionAge':
          cmp = (a.pkg.version_age_days ?? 0) - (b.pkg.version_age_days ?? 0)
          break
        case 'epss':
          // -1 keeps unscored packages at the bottom of a descending sort, same as Fitness did.
          // The direction flips though: a high EPSS is bad where a high Fitness was good.
          cmp = (a.pkg.epss ?? -1) - (b.pkg.epss ?? -1)
          break
      }
      return dir === 'asc' ? cmp : -cmp
    })

    return rows
  })

  function toggleSort(column: SortColumn) {
    if (sortColumn.value !== column) {
      sortColumn.value = column
      sortDirection.value = 'asc'
    } else {
      const progression: SortDirection[] = ['none', 'asc', 'desc']
      const idx = progression.indexOf(sortDirection.value)
      sortDirection.value = progression[(idx + 1) % progression.length] as SortDirection
      if (sortDirection.value === 'none') {
        sortColumn.value = null
      }
    }
  }

  function resetFilters() {
    searchText.value = ''
    showAll.value = false
    packageTypeFilter.value = 'all'
    driftStatusFilter.value = 'all'
    releaseDistanceFilter.value = null
    timeLagFilter.value = null
    sortColumn.value = null
    sortDirection.value = 'none'
  }

  return {
    searchText,
    showAll,
    packageTypeFilter,
    driftStatusFilter,
    releaseDistanceFilter,
    timeLagFilter,
    sortColumn,
    sortDirection,
    sortedRows,
    toggleSort,
    resetFilters,
  }
}
