import { describe, it, expect } from 'vitest'
import { computeWhatsNext, isActionable, type ReportRow } from '../composables/useReportFilters'
import type { PackageMetrics } from '../types/report'

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

describe('computeWhatsNext', () => {
  it('flags an exploitable CVE ahead of everything else', () => {
    expect(
      computeWhatsNext({ driftStatus: 'DIFF_MINOR', cveCount: 1, epss: 0.2, maintenanceState: 'winding_down' }),
    ).toBe('Check for the Fix')
  })

  it('falls through a low-EPSS CVE to the version-drift advice', () => {
    expect(
      computeWhatsNext({ driftStatus: 'DIFF_MINOR', cveCount: 1, epss: 0.05, maintenanceState: null }),
    ).toBe('Update Immediately')
  })

  it('says find an alternative for a current but dead package', () => {
    expect(
      computeWhatsNext({ driftStatus: 'LATEST', cveCount: 0, epss: null, maintenanceState: 'deprecated' }),
    ).toBe('Find alternative')
  })

  it('says consider an alternative for a winding-down upstream', () => {
    expect(
      computeWhatsNext({ driftStatus: 'DIFF_MINOR', cveCount: 0, epss: null, maintenanceState: 'winding_down' }),
    ).toBe('Consider alternative')
  })

  it('points to the release notes for a major bump', () => {
    expect(
      computeWhatsNext({ driftStatus: 'DIFF_MAJOR', cveCount: 0, epss: null, maintenanceState: null }),
    ).toBe('Check Release Notes')
  })

  it('returns null for a clean, current package', () => {
    expect(
      computeWhatsNext({ driftStatus: 'LATEST', cveCount: 0, epss: null, maintenanceState: 'maintained' }),
    ).toBeNull()
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
