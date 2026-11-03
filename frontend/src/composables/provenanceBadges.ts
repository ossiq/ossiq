// How a package's build and source evidence is drawn in the report: the table's badges and the detail panel.
// Wording and colour only: the values themselves are the export's contract (build_provenance, source_level).

// What a badge needs from its package. Any object carrying these fields will do, so the table's rows and the
// detail panel's selected node (whose values are plain strings, not the export's unions) can both use it.
export interface ProvenanceFields {
  build_provenance?: string | null
  source_level?: string | null
  policy_violations?: string[] | null
}

export interface Badge {
  label: string
  classes: string
  // Hover text: the reasons when the policy is broken, otherwise what the value means.
  title: string
  // What the value means, whatever the policy says. The detail panel prints it under the badge.
  meaning: string
}

const BASE = 'px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wide border'
const GOOD = `${BASE} bg-green-100 text-green-700 border-green-300`
// Muted rather than a warning colour: most packages publish without provenance today, so painting "none" would
// colour the whole table. Only a policy violation turns a cell red.
const QUIET = `${BASE} bg-zinc-100 text-zinc-500 border-zinc-200`
const VIOLATION = `${BASE} bg-red-100 text-red-700 border-red-300`

function badge(label: string, classes: string, meaning: string): Badge {
  return { label, classes, title: meaning, meaning }
}

const BUILD: Record<string, Badge> = {
  'trusted-publisher': badge(
    'trusted',
    GOOD,
    "Published through the registry's trusted-publisher flow, with a signed build attestation",
  ),
  provenance: badge(
    'attested',
    GOOD,
    'Has a signed build attestation, but was not published through a trusted publisher',
  ),
  none: badge('none', QUIET, 'No build attestation: published with a plain registry token'),
}

const SOURCE: Record<string, Badge> = {
  reviewed: badge(
    'reviewed',
    GOOD,
    'The default branch blocks force-pushes and deletion, and requires an approved pull request',
  ),
  'protected-history': badge('protected', GOOD, 'The default branch blocks force-pushes and deletion'),
  'version-controlled': badge(
    'vcs',
    QUIET,
    'The source is on GitHub, but its default branch does not protect its history',
  ),
}

// A badge for the installed release's build evidence; null when the registry could not be read, which is not
// the same as "none". A build-rule violation turns the badge red and says why.
export function buildBadge(pkg: ProvenanceFields): Badge | null {
  const known = pkg.build_provenance ? BUILD[pkg.build_provenance] : undefined
  return known ? violationBadge(known, buildViolations(pkg)) : null
}

// A badge for the package's source repository; null for transitives and for repositories GitHub could not say.
export function sourceBadge(pkg: ProvenanceFields): Badge | null {
  const known = pkg.source_level ? SOURCE[pkg.source_level] : undefined
  return known ? violationBadge(known, sourceViolations(pkg)) : null
}

// Every reason about the repository begins like this (SOURCE_REASON_PREFIX in domain/provenance.py); any other
// reason is about how the release was built. A cell goes red only for the rule that failed it: a package can
// pass its source floor and still fail its build floor, and the reverse.
const SOURCE_REASON_PREFIX = 'source repository is'

function sourceViolations(pkg: ProvenanceFields): string[] {
  return (pkg.policy_violations ?? []).filter((reason) => reason.startsWith(SOURCE_REASON_PREFIX))
}

function buildViolations(pkg: ProvenanceFields): string[] {
  return (pkg.policy_violations ?? []).filter((reason) => !reason.startsWith(SOURCE_REASON_PREFIX))
}

function violationBadge(known: Badge, violations: string[]): Badge {
  if (violations.length === 0) return known
  return { ...known, label: `✗ ${known.label}`, classes: VIOLATION, title: violations.join('\n') }
}
