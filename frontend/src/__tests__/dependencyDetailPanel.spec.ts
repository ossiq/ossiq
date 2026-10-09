import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import DependencyDetailPanel from '../components/DependencyDetailPanel.vue'
import type { SelectedNodeDetail } from '../types/dependency-tree'

function mountNode(over: Partial<SelectedNodeDetail> = {}) {
  const node: SelectedNodeDetail = {
    name: '@vue/test-utils',
    version_installed: '2.5.1',
    isDuplicate: false,
    ...over,
  }
  return mount(DependencyDetailPanel, { props: { node, isOpen: true } })
}

describe('DependencyDetailPanel unresolved peers', () => {
  it('draws no section for a package whose peers all resolve', () => {
    expect(mountNode().find('[data-testid="unresolved-peers"]').exists()).toBe(false)
    expect(mountNode({ unresolved_peers: [] }).find('[data-testid="unresolved-peers"]').exists()).toBe(false)
  })

  it('names an optional peer installed only out of reach, and where', () => {
    const section = mountNode({
      unresolved_peers: [
        { package_name: '@vue/server-renderer', spec: '3.x', optional: true, installed_elsewhere: ['3.5.43'] },
      ],
    }).find('[data-testid="unresolved-peers"]')

    expect(section.exists()).toBe(true)
    expect(section.text()).toContain('Unresolved Peers')
    expect(section.text()).toContain('@vue/server-renderer')
    expect(section.text()).toContain('3.x')
    expect(section.text()).toContain('optional')
    expect(section.text()).toContain('installed only out of reach: 3.5.43')
  })

  it('says not installed when the peer is nowhere in the tree', () => {
    const section = mountNode({
      unresolved_peers: [{ package_name: 'host', spec: '^1', optional: false, installed_elsewhere: [] }],
    }).find('[data-testid="unresolved-peers"]')

    expect(section.text()).toContain('not installed')
    expect(section.text()).not.toContain('optional')
  })

  it('counts them', () => {
    const section = mountNode({
      unresolved_peers: [
        { package_name: 'a', spec: '*', optional: false, installed_elsewhere: [] },
        { package_name: 'b', spec: '*', optional: true, installed_elsewhere: ['1.0.0'] },
      ],
    }).find('[data-testid="unresolved-peers"]')

    expect(section.text()).toContain('2')
  })
})

describe('DependencyDetailPanel registry verdict', () => {
  it('says nothing for a package the registry did not retire', () => {
    const text = mountNode({ registry_status: 'active' }).text()

    expect(text).not.toContain('Archived')
    expect(text).not.toContain('Deprecated')
    expect(text).not.toContain('Registry note')
  })

  it('badges a deprecated package and quotes what the registry said about it', () => {
    const wrapper = mountNode({
      registry_status: 'deprecated',
      is_deprecated: true,
      deprecation_message: 'use String.prototype.padStart()',
    })

    expect(wrapper.text()).toContain('Deprecated')
    expect(wrapper.text()).toContain('Registry note')
    expect(wrapper.text()).toContain('use String.prototype.padStart()')
  })

  it('names an archived package as archived, not deprecated', () => {
    const text = mountNode({ registry_status: 'archived', is_deprecated: true }).text()

    expect(text).toContain('Archived')
    expect(text).not.toContain('Deprecated')
  })

  it('flags a quarantined package as quarantined', () => {
    expect(mountNode({ registry_status: 'quarantined' }).text()).toContain('Quarantined')
  })

  it('shows the registry note as text, never as markup', () => {
    const wrapper = mountNode({ registry_status: 'deprecated', deprecation_message: '<b>use got</b>' })

    expect(wrapper.find('b').exists()).toBe(false)
    expect(wrapper.text()).toContain('<b>use got</b>')
  })
})
