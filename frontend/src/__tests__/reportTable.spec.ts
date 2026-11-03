import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import ReportTable from '../components/ReportTable.vue'
import type { ReportRow } from '../composables/useReportFilters'
import type { PackageMetrics } from '../types/report'

function row(over: Partial<PackageMetrics>): ReportRow {
  const pkg = {
    package_name: 'demo',
    installed_version: '1.0.0',
    latest_version: '1.0.0',
    cve: [],
    is_optional_dependency: false,
    ...over,
  } as PackageMetrics
  return {
    pkg,
    isDev: false,
    driftStatus: 'LATEST',
    whatsNext: pkg.next_action ?? null,
    timeLagDisplay: '0d',
    versionAgeDisplay: '0d',
    cveCount: 0,
    registryUrl: '',
    license: [],
    hasTransitiveCve: false,
    isPrerelease: false,
    isYanked: false,
    isDeprecated: false,
    registryStatus: null,
    isPackageUnpublished: false,
  }
}

function mountTable(rows: ReportRow[]) {
  return mount(ReportTable, { props: { rows, sortColumn: null, sortDirection: 'none', registry: 'npm' } })
}

function headers(wrapper: ReturnType<typeof mountTable>): string[] {
  return wrapper.findAll('thead th').map((th) => th.text().replace(/\s+/g, ' ').trim())
}

describe('ReportTable provenance columns', () => {
  it('has a Build and a Source column, between EPSS and the recommendation', () => {
    const names = headers(mountTable([row({})]))

    expect(names.some((n) => n.startsWith('EPSS'))).toBe(true)
    const build = names.indexOf('Build')
    expect(build).toBeGreaterThan(-1)
    expect(names[build + 1]).toBe('Source')
    expect(names[build + 2]).toBe('Rec. Version')
  })

  it('writes the tier and the level in the console wording', () => {
    const cells = mountTable([row({ build_provenance: 'trusted-publisher', source_level: 'protected-history' })])
      .findAll('tbody tr')[0]
      .findAll('td')
      .map((td) => td.text())

    expect(cells).toContain('trusted')
    expect(cells).toContain('protected')
  })

  it('draws a dash where the registry or GitHub could not be read', () => {
    const cells = mountTable([row({ build_provenance: null, source_level: null })])
      .findAll('tbody tr')[0]
      .findAll('td')
      .map((td) => td.text())

    expect(cells.filter((text) => text === '—').length).toBeGreaterThanOrEqual(2)
    expect(cells).not.toContain('none')
  })

  it('has one cell per header, so no column shifts into the next', () => {
    const wrapper = mountTable([row({ build_provenance: 'none' })])

    expect(wrapper.findAll('tbody tr')[0].findAll('td').length).toBe(headers(wrapper).length)
  })

  it('marks a package that breaks the policy and says why on hover', () => {
    const wrapper = mountTable([
      row({ build_provenance: 'none', policy_violations: ['trust downgrade: no provenance'], next_action: 'Review provenance' }),
    ])
    const pill = wrapper.findAll('span').find((s) => s.text() === 'policy')

    expect(pill?.attributes('title')).toBe('trust downgrade: no provenance')
    expect(wrapper.text()).toContain('✗ none')
    expect(wrapper.text()).toContain('Review provenance')
  })

  it('shows no policy pill for a clean package', () => {
    const wrapper = mountTable([row({ build_provenance: 'provenance', policy_violations: [] })])

    expect(wrapper.findAll('span').some((s) => s.text() === 'policy')).toBe(false)
  })

  it('spans every column on the empty state', () => {
    const wrapper = mountTable([])

    expect(wrapper.find('tbody td[colspan]').attributes('colspan')).toBe(String(headers(wrapper).length))
  })
})

describe('ReportTable on a narrow window', () => {
  it('scrolls sideways instead of clipping the right-hand columns', () => {
    const wrapper = mountTable([row({})])
    const classes = wrapper.find('table').element.parentElement!.className

    expect(classes).toContain('overflow-x-auto')
    expect(classes).not.toContain('overflow-hidden')
  })
})
