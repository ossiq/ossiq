import { describe, it, expect, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import ReportBanner from '../components/ReportBanner.vue'
import { useOssiqStore } from '../stores/ossiq'
import type { OSSIQExportSchemaV15 } from '../types/report'

type Metadata = OSSIQExportSchemaV15['metadata']

function mountWithMetadata(metadata: Partial<Metadata>) {
  const store = useOssiqStore()
  store.setReport({
    project: { name: 'demo', registry: 'npm' },
    metadata: { export_timestamp: '2026-01-01T00:00:00Z', ...metadata },
    production_packages: [],
    development_packages: [],
    transitive_packages: [],
  } as unknown as OSSIQExportSchemaV15)
  return mount(ReportBanner)
}

describe('ReportBanner', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('draws nothing for a clean scan', () => {
    const wrapper = mountWithMetadata({
      data_completeness: { overall: 'ok', sources: [{ step: 'vulnerabilities', status: 'ok' }] },
    })
    expect(wrapper.text()).toBe('')
  })

  it('names each degraded source', () => {
    const wrapper = mountWithMetadata({
      data_completeness: {
        overall: 'unreachable',
        sources: [
          { step: 'vulnerabilities', status: 'unreachable' },
          { step: 'repositories', status: 'partial' },
          { step: 'epss', status: 'ok' },
        ],
      },
    })

    const text = wrapper.text()
    expect(text).toContain('Incomplete data')
    expect(text).toContain('OSV.dev')
    expect(text).toContain('unreachable — no data')
    expect(text).toContain('GitHub')
    expect(text).toContain('partial — some data missing')
    // A source that came back ok is not a degradation to report.
    expect(text).not.toContain('api.first.org')
  })

  it('renders metadata warnings, which had no reader either', () => {
    const wrapper = mountWithMetadata({
      data_completeness: { overall: 'ok', sources: [] },
      warnings: ['Rate limit quota exhausted for GithubRepoBatchStrategy'],
    })

    expect(wrapper.text()).toContain('Rate limit quota exhausted')
  })

  it('survives a report with no completeness block at all', () => {
    const wrapper = mountWithMetadata({})
    expect(wrapper.text()).toBe('')
  })
})
