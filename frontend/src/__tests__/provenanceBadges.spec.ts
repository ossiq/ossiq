import { describe, it, expect } from 'vitest'
import { buildBadge, sourceBadge } from '../composables/provenanceBadges'
import type { PackageMetrics } from '../types/report'

function pkg(over: Partial<PackageMetrics>): PackageMetrics {
  return { package_name: 'demo', installed_version: '1.0.0', cve: [], ...over } as PackageMetrics
}

describe('buildBadge', () => {
  it('names each tier in the console wording', () => {
    expect(buildBadge(pkg({ build_provenance: 'trusted-publisher' }))?.label).toBe('trusted')
    expect(buildBadge(pkg({ build_provenance: 'provenance' }))?.label).toBe('attested')
    expect(buildBadge(pkg({ build_provenance: 'none' }))?.label).toBe('none')
  })

  it('draws nothing when the registry could not be read, which is not the same as none', () => {
    expect(buildBadge(pkg({ build_provenance: null }))).toBeNull()
    expect(buildBadge(pkg({}))).toBeNull()
  })

  it('does not paint "none" as a warning', () => {
    expect(buildBadge(pkg({ build_provenance: 'none' }))?.classes).not.toMatch(/red|amber|yellow/)
  })

  it('turns red and lists every reason when the policy is broken', () => {
    const badge = buildBadge(
      pkg({ build_provenance: 'none', policy_violations: ['trust downgrade', 'below the required provenance'] }),
    )

    expect(badge?.label).toBe('✗ none')
    expect(badge?.classes).toMatch(/red/)
    expect(badge?.title).toBe('trust downgrade\nbelow the required provenance')
  })

  it('stays as it was with an empty violation list', () => {
    expect(buildBadge(pkg({ build_provenance: 'provenance', policy_violations: [] }))?.label).toBe('attested')
  })
})

describe('sourceBadge', () => {
  it('names each level in the console wording', () => {
    expect(sourceBadge(pkg({ source_level: 'reviewed' }))?.label).toBe('reviewed')
    expect(sourceBadge(pkg({ source_level: 'protected-history' }))?.label).toBe('protected')
    expect(sourceBadge(pkg({ source_level: 'version-controlled' }))?.label).toBe('vcs')
  })

  it('draws nothing for an unmeasured repository', () => {
    expect(sourceBadge(pkg({ source_level: null }))).toBeNull()
    expect(sourceBadge(pkg({}))).toBeNull()
  })

  it('turns red when the policy is broken', () => {
    const badge = sourceBadge(pkg({ source_level: 'version-controlled', policy_violations: ['source repository is version-controlled, below the required reviewed'] }))

    expect(badge?.label).toBe('✗ vcs')
    expect(badge?.classes).toMatch(/red/)
  })
})

describe('which cell a violation reddens', () => {
  const build = 'no provenance, below the required provenance'
  const source = 'source repository is version-controlled, below the required protected-history'

  it('reddens only the Build badge for a build reason', () => {
    const p = pkg({ build_provenance: 'none', source_level: 'protected-history', policy_violations: [build] })

    expect(buildBadge(p)?.classes).toMatch(/red/)
    expect(sourceBadge(p)?.classes).not.toMatch(/red/)
    expect(sourceBadge(p)?.label).toBe('protected')
  })

  it('reddens only the Source badge for a repository reason', () => {
    const p = pkg({ build_provenance: 'provenance', source_level: 'version-controlled', policy_violations: [source] })

    expect(buildBadge(p)?.classes).not.toMatch(/red/)
    expect(sourceBadge(p)?.classes).toMatch(/red/)
    expect(sourceBadge(p)?.label).toBe('✗ vcs')
  })

  it('puts each reason on the badge it belongs to', () => {
    const p = pkg({ build_provenance: 'none', source_level: 'version-controlled', policy_violations: [build, source] })

    expect(buildBadge(p)?.title).toBe(build)
    expect(sourceBadge(p)?.title).toBe(source)
  })
})

describe('badge meaning', () => {
  it('keeps the plain meaning even when a violation replaces the hover text with the reasons', () => {
    const badge = buildBadge(pkg({ build_provenance: 'none', policy_violations: ['too weak'] }))

    expect(badge?.title).toBe('too weak')
    expect(badge?.meaning).toContain('No build attestation')
  })

  it('reads a value it does not know as unknown rather than guessing', () => {
    expect(buildBadge({ build_provenance: 'sigstore-gold' })).toBeNull()
    expect(sourceBadge({ source_level: 'two-party' })).toBeNull()
  })
})
