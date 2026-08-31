import { describe, it, expect } from 'vitest'
import { buildPackageRegistry } from '../explorer/registry'
import type { OSSIQExportSchemaV15, PackageMetrics, TransitivePackageMetrics } from '../types/report'

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
      triage_action: 'retain',
      stability_csi: 0.82,
      stability_coverage: 0.6,
      stability_risk: 0.18,
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
} as unknown as OSSIQExportSchemaV15

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
    expect(ruff.stability_risk).toBe(0.18)
    expect(ruff.flow_trend).toBe('stable')
    expect(ruff.stability_coverage).toBe(0.6)
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
