import { describe, it, expect, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { isActionable, useReportFilters, type ReportRow } from '../composables/useReportFilters'
import { useOssiqStore } from '../stores/ossiq'
import type { OSSIQExportSchemaV15, PackageMetrics } from '../types/report'

function row(over: Partial<PackageMetrics>, rowOver: Partial<ReportRow> = {}): ReportRow {
  const pkg = {
    package_name: 'demo',
    installed_version: '1.0.0',
    latest_version: '1.0.0',
    cve: [],
    is_optional_dependency: false,
    is_prerelease: false,
    is_yanked: false,
    is_deprecated: false,
    is_package_unpublished: false,
    ...over,
  } as PackageMetrics
  return {
    pkg,
    isDev: false,
    driftStatus: 'LATEST',
    whatsNext: null,
    timeLagDisplay: '',
    versionAgeDisplay: '',
    cveCount: pkg.cve?.length ?? 0,
    registryUrl: '',
    license: [],
    hasTransitiveCve: false,
    isPrerelease: false,
    isYanked: false,
    isDeprecated: false,
    isPackageUnpublished: false,
    ...rowOver,
  }
}

function reportWith(pkg: Partial<PackageMetrics>): OSSIQExportSchemaV15 {
  return {
    project: { name: 'demo', registry: 'npm' },
    production_packages: [
      {
        package_name: 'demo',
        installed_version: '1.0.0',
        latest_version: '1.9.0',
        cve: [],
        is_optional_dependency: false,
        is_prerelease: false,
        is_yanked: false,
        is_deprecated: false,
        is_package_unpublished: false,
        ...pkg,
      },
    ],
    development_packages: [],
    transitive_packages: [],
    dependency_tree: [],
  } as unknown as OSSIQExportSchemaV15
}

describe("the report's What's Next column", () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('shows the label the scan decided, not one re-derived here', () => {
    useOssiqStore().setReport(reportWith({ next_action: 'Check Release Notes' }))
    expect(useReportFilters().sortedRows.value[0].whatsNext).toBe('Check Release Notes')
  })

  it('says constrained for a recommendation that needs the declared range widened', () => {
    // The regression this field exists for: a hand-written copy of the CLI's rules lived here and
    // had no notion of ladder rungs, so it called this one "Update Immediately" — naming a target
    // the reader cannot apply without editing the manifest first.
    useOssiqStore().setReport(
      reportWith({
        next_action: 'Constrained. Check newer version',
        recommended_version: '1.9.0',
        recommended_from_rung: 'in_major',
        requires_constraint_widening: true,
        version_constraint_declared: '~1.0.0',
      }),
    )
    expect(useReportFilters().sortedRows.value[0].whatsNext).toBe('Constrained. Check newer version')
  })

  it('leaves the column empty when nothing is due', () => {
    useOssiqStore().setReport(reportWith({ latest_version: '1.0.0', next_action: null }))
    const filters = useReportFilters()
    filters.showAll.value = true
    expect(filters.sortedRows.value[0].whatsNext).toBeNull()
  })
})

describe('isActionable', () => {
  it('hides a clean, current, maintained package', () => {
    expect(isActionable(row({ maintenance_state: 'maintained' }))).toBe(false)
  })

  it('keeps a package that is a minor version behind', () => {
    expect(isActionable(row({ latest_version: '1.1.0' }, { driftStatus: 'DIFF_MINOR' }))).toBe(true)
  })

  it('keeps an abandoned package even at the latest version', () => {
    expect(isActionable(row({ maintenance_state: 'abandoned' }))).toBe(true)
  })

  it('keeps a package with a CVE', () => {
    expect(isActionable(row({}, { cveCount: 1 }))).toBe(true)
  })

  it('keeps a package with a pending recommendation', () => {
    expect(isActionable(row({ recommended_version: '1.0.1' }))).toBe(true)
  })
})
