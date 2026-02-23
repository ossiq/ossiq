import { ref, computed } from 'vue'
import { useOssiqStore } from '@/stores/ossiq'
import type { PackageMetrics } from '@/types/report'

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

export interface ReportRow {
  pkg: PackageMetrics
  isDev: boolean
  driftStatus: DriftStatus
  timeLagDisplay: string
  cveCount: number
  registryUrl: string
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
  const packageTypeFilter = ref<'all' | 'production' | 'development'>('all')
  const driftStatusFilter = ref<DriftStatus | 'all'>('all')
  const releaseDistanceFilter = ref<number | null>(null) // min threshold
  const timeLagFilter = ref<{ min?: number; max?: number } | null>(null)

  // Sort state
  const sortColumn = ref<SortColumn | null>(null)
  const sortDirection = ref<SortDirection>('none')

  // Build unified row list
  const allRows = computed<ReportRow[]>(() => {
    const registry = store.report?.project.registry ?? 'npm'
    const prodRows: ReportRow[] = store.productionPackages.map((pkg) => ({
      pkg,
      isDev: false,
      driftStatus: computeDriftStatus(pkg.installed_version, pkg.latest_version),
      timeLagDisplay: formatTimeLag(pkg.time_lag_days),
      cveCount: pkg.cve.length,
      registryUrl: registryUrl(registry, pkg.package_name),
    }))
    const devRows: ReportRow[] = store.developmentPackages.map((pkg) => ({
      pkg,
      isDev: true,
      driftStatus: computeDriftStatus(pkg.installed_version, pkg.latest_version),
      timeLagDisplay: formatTimeLag(pkg.time_lag_days),
      cveCount: pkg.cve.length,
      registryUrl: registryUrl(registry, pkg.package_name),
    }))
    return [...prodRows, ...devRows]
  })

  // Apply filters
  const filteredRows = computed<ReportRow[]>(() => {
    let rows = allRows.value

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
    packageTypeFilter.value = 'all'
    driftStatusFilter.value = 'all'
    releaseDistanceFilter.value = null
    timeLagFilter.value = null
    sortColumn.value = null
    sortDirection.value = 'none'
  }

  return {
    searchText,
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
