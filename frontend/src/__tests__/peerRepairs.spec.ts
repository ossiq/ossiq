import { describe, it, expect, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import PeerRepairs from '../components/PeerRepairs.vue'
import { useOssiqStore } from '../stores/ossiq'
import type { OSSIQExportSchemaV16 } from '../types/report'

type Repair = NonNullable<OSSIQExportSchemaV16['peer_repairs']>[number]

function mountWithRepairs(repairs: Repair[] | undefined) {
  useOssiqStore().setReport({
    project: { name: 'demo', registry: 'npm' },
    metadata: { export_timestamp: '2026-01-01T00:00:00Z' },
    production_packages: [],
    development_packages: [],
    transitive_packages: [],
    ...(repairs === undefined ? {} : { peer_repairs: repairs }),
  } as unknown as OSSIQExportSchemaV16)
  return mount(PeerRepairs)
}

const serverRenderer: Repair = {
  package_name: '@vue/server-renderer',
  suggested_constraint: '~3.5.43',
  is_dev_dependency: true,
  requirers: ['@vue/test-utils'],
  family_moves: [{ package_name: '@vue/shared', current_version: '3.5.42', projected_version: '3.5.43' }],
}

describe('PeerRepairs', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('draws nothing when there is nothing to repair', () => {
    expect(mountWithRepairs([]).text()).toBe('')
  })

  it('draws nothing for a report made before schema 1.6, which has no such field', () => {
    expect(mountWithRepairs(undefined).text()).toBe('')
  })

  it('names the package to add, how, and for whom', () => {
    const text = mountWithRepairs([serverRenderer]).text()

    expect(text).toContain('Peer repairs')
    expect(text).toContain('@vue/server-renderer ~3.5.43')
    expect(text).toContain('devDependency')
    expect(text).toContain('@vue/test-utils')
  })

  it('lists the stale copies that move with it', () => {
    const text = mountWithRepairs([serverRenderer]).text()

    expect(text).toContain('@vue/shared')
    expect(text).toContain('3.5.42')
    expect(text).toContain('3.5.43')
  })

  it('says dependency for a production package, and tolerates a repair with no family moves', () => {
    const wrapper = mountWithRepairs([
      { package_name: 'host', suggested_constraint: '~1.2.0', is_dev_dependency: false, requirers: ['a', 'b'] },
    ])

    expect(wrapper.text()).toContain('host ~1.2.0')
    expect(wrapper.text()).toContain('a, b')
    expect(wrapper.text()).not.toContain('devDependency')
    expect(wrapper.find('li ul').exists()).toBe(false)
  })
})
