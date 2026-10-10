import { describe, it, expect } from 'vitest'
import { buildPackageRegistry } from '../explorer/registry'
import { effectiveConstraintType } from '../explorer/nodeStyle'
import type { OSSIQExportSchemaV16, PackageMetrics, TransitivePackageMetrics } from '../types/report'

// Only the fields buildPackageRegistry reads. The stability block is what this test guards:
// gap_cv / silence_days / silence_p / commits_sampled / archived must survive the transform.
function pkg(over: Partial<PackageMetrics>): PackageMetrics {
  return {
    package_name: 'demo',
    installed_version: '1.0.0',
    is_yanked: false,
    is_prerelease: false,
    ...over,
  } as PackageMetrics
}

function transitive(over: Partial<TransitivePackageMetrics>): TransitivePackageMetrics {
  return {
    id: 1,
    package_name: 'demo-transitive',
    installed_version: '2.0.0',
    is_yanked: false,
    is_prerelease: false,
    is_package_unpublished: false,
    ...over,
  } as TransitivePackageMetrics
}

const report = {
  constraint_type_map: ['DECLARED'],
  production_packages: [
    pkg({
      package_name: 'ruff',
      gap_cv: 2.21,
      silence_days: 0.6,
      silence_p: 0.41,
      commits_sampled: 98,
      archived: false,
      dependency_health_action: 'retain',
      maintenance_coverage: 0.6,
      maintenance_risk: 0.18,
      maintenance_state: 'maintained',
      flow_trend: 'stable',
      deprecation_signals: [],
    }),
  ],
  development_packages: [],
  transitive_packages: [
    transitive({
      id: 7,
      package_name: 'six',
      gap_cv: null,
      silence_days: 183.8,
      silence_p: 0.061,
      commits_sampled: 12,
      archived: true,
    }),
  ],
  dependency_tree: [],
} as unknown as OSSIQExportSchemaV16

describe('buildPackageRegistry', () => {
  it('carries the repository-stability fields onto direct entries', () => {
    const { directEntries } = buildPackageRegistry(report)
    const ruff = directEntries.get('ruff')!
    expect(ruff.gap_cv).toBe(2.21)
    expect(ruff.silence_days).toBe(0.6)
    expect(ruff.silence_p).toBe(0.41)
    expect(ruff.commits_sampled).toBe(98)
    expect(ruff.archived).toBe(false)
    expect(ruff.maintenance_state).toBe('maintained')
    expect(ruff.maintenance_risk).toBe(0.18)
    expect(ruff.flow_trend).toBe('stable')
    expect(ruff.maintenance_coverage).toBe(0.6)
  })

  it('carries them onto transitive entries, keeping null gap_cv distinct from unmeasured', () => {
    const { byId } = buildPackageRegistry(report)
    const six = byId.get(7)!
    expect(six.gap_cv).toBeNull()
    expect(six.commits_sampled).toBe(12)
    expect(six.silence_p).toBe(0.061)
    expect(six.archived).toBe(true)
  })
})

describe('buildPackageRegistry and unresolved peers (schema 1.6)', () => {
  const peer = { package_name: '@vue/server-renderer', spec: '3.x', optional: true, installed_elsewhere: ['3.5.43'] }

  function reportWith(direct: Partial<PackageMetrics>, trans: Partial<TransitivePackageMetrics>) {
    return {
      constraint_type_map: ['DECLARED'],
      production_packages: [pkg({ package_name: 'a', ...direct })],
      development_packages: [],
      transitive_packages: [transitive({ id: 3, ...trans })],
      dependency_tree: [],
    } as unknown as OSSIQExportSchemaV16
  }

  it('carries them onto direct and transitive entries', () => {
    const { directEntries, byId } = buildPackageRegistry(
      reportWith({ unresolved_peers: [peer] }, { unresolved_peers: [peer] }),
    )
    expect(directEntries.get('a')!.unresolved_peers).toEqual([peer])
    expect(byId.get(3)!.unresolved_peers).toEqual([peer])
  })

  it('reads a report made before 1.6, which has no such field, as none', () => {
    const { directEntries, byId } = buildPackageRegistry(reportWith({}, {}))
    expect(directEntries.get('a')!.unresolved_peers).toEqual([])
    expect(byId.get(3)!.unresolved_peers).toEqual([])
  })
})

describe('an override OSS IQ wrote (schema 1.6)', () => {
  function reportWith(direct: Partial<PackageMetrics>) {
    return {
      constraint_type_map: ['DECLARED'],
      production_packages: [pkg({ package_name: 'a', ...direct })],
      development_packages: [],
      transitive_packages: [],
      dependency_tree: [],
    } as unknown as OSSIQExportSchemaV16
  }

  it('reads as declared on a direct entry, so it is not drawn as overridden', () => {
    const { directEntries } = buildPackageRegistry(
      reportWith({ constraint_type: 'OVERRIDE', constraint_ossiq_authored: true }),
    )
    expect(directEntries.get('a')!.constraint_type).toBe('DECLARED')
  })

  it('stays an override when the user wrote it', () => {
    const { directEntries } = buildPackageRegistry(reportWith({ constraint_type: 'OVERRIDE' }))
    expect(directEntries.get('a')!.constraint_type).toBe('OVERRIDE')
  })
})

describe('effectiveConstraintType', () => {
  it('turns only an OSS IQ-authored OVERRIDE into DECLARED', () => {
    expect(effectiveConstraintType('OVERRIDE', true)).toBe('DECLARED')
    expect(effectiveConstraintType('OVERRIDE', false)).toBe('OVERRIDE')
    expect(effectiveConstraintType('OVERRIDE')).toBe('OVERRIDE')
  })

  it('leaves every other type alone, whatever the flag says', () => {
    for (const type of ['DECLARED', 'NARROWED', 'PINNED', 'ADDITIVE', null, undefined] as const) {
      expect(effectiveConstraintType(type, true)).toBe(type)
    }
  })
})
