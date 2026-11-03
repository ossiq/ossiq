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

describe('DependencyDetailPanel provenance', () => {
  const section = (over: Partial<SelectedNodeDetail> = {}) => mountNode(over).find('[data-testid="provenance"]')

  it('is always drawn, so an unread value is visible as a dash rather than missing', () => {
    const wrapper = section()

    expect(wrapper.exists()).toBe(true)
    expect(wrapper.find('[data-testid="provenance-build"]').text()).toContain('—')
    expect(wrapper.find('[data-testid="provenance-source"]').text()).toContain('—')
  })

  it('says why a value is missing instead of leaving it blank', () => {
    const wrapper = section({ build_provenance: null, source_level: null })

    expect(wrapper.find('[data-testid="provenance-build"]').text()).toContain('registry could not say')
    expect(wrapper.find('[data-testid="provenance-source"]').text()).toContain('transitive dependency')
  })

  it('names the build tier and the source level, and what each means', () => {
    const wrapper = section({ build_provenance: 'trusted-publisher', source_level: 'reviewed' })

    expect(wrapper.find('[data-testid="provenance-build"]').text()).toContain('trusted')
    expect(wrapper.find('[data-testid="provenance-build"]').text()).toContain("registry's trusted-publisher flow")
    expect(wrapper.find('[data-testid="provenance-source"]').text()).toContain('reviewed')
    expect(wrapper.find('[data-testid="provenance-source"]').text()).toContain('requires an approved pull request')
  })

  it('does not paint "none" as a problem', () => {
    const badge = section({ build_provenance: 'none' }).find('[data-testid="provenance-build"] span.inline-block')

    expect(badge.classes().join(' ')).not.toMatch(/red/)
  })

  it('lists every policy reason and counts them', () => {
    const wrapper = section({
      build_provenance: 'none',
      source_level: 'version-controlled',
      policy_violations: ['no provenance, below the required provenance', 'source repository is version-controlled, below the required reviewed'],
    })

    const reasons = wrapper.find('[data-testid="provenance-violations"]').text()
    expect(reasons).toContain('no provenance, below the required provenance')
    expect(reasons).toContain('source repository is version-controlled, below the required reviewed')
    expect(wrapper.find('[data-testid="provenance-policy-count"]').text()).toContain('2')
  })

  it('reddens only the cell whose rule failed', () => {
    const wrapper = section({
      build_provenance: 'none',
      source_level: 'protected-history',
      policy_violations: ['no provenance, below the required provenance'],
    })

    expect(wrapper.find('[data-testid="provenance-build"] span.inline-block').classes().join(' ')).toMatch(/red/)
    expect(wrapper.find('[data-testid="provenance-source"] span.inline-block').classes().join(' ')).not.toMatch(/red/)
  })

  it('shows no violation block for a package that passes', () => {
    const wrapper = section({ build_provenance: 'provenance', policy_violations: [] })

    expect(wrapper.find('[data-testid="provenance-violations"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="provenance-policy-count"]').exists()).toBe(false)
  })
})
