// Regenerates node_semver_conformance.json: node-semver's own verdicts, in loose mode, on its
// range fixtures, on every range a manifest under testdata/npm declares, and on a grid of
// operator × version forms. tests/solver/test_npm_range.py holds ossiq.solver.npm_range to it.
//
// Run from the repository root against a node-semver checkout:
//
//   git clone --depth 1 --branch v7.8.5 https://github.com/npm/node-semver /tmp/node-semver
//   node tests/solver/node_semver_conformance.js /tmp/node-semver > tests/solver/node_semver_conformance.json
'use strict'

const fs = require('fs')
const path = require('path')

const checkout = path.resolve(process.argv[2])
const semver = require(checkout)
const fixture = (name) => require(path.join(checkout, 'test', 'fixtures', name))
const options = (includePrerelease) => ({ loose: true, includePrerelease })

// Keys whose values are version ranges in package.json and package-lock.json.
const RANGE_KEYS = new Set([
  'dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies', 'requires', 'engines',
])

const manifestRanges = () => {
  const ranges = new Set()
  const collect = (node) => {
    if (Array.isArray(node)) {
      node.forEach(collect)
    } else if (node && typeof node === 'object') {
      for (const [key, value] of Object.entries(node)) {
        if (RANGE_KEYS.has(key) && value && typeof value === 'object' && !Array.isArray(value)) {
          Object.values(value).filter((v) => typeof v === 'string').forEach((v) => ranges.add(v))
        }
        collect(value)
      }
    }
  }
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name)
      if (entry.isDirectory() && entry.name !== 'node_modules') {
        walk(full)
      } else if (entry.name === 'package.json' || entry.name === 'package-lock.json') {
        collect(JSON.parse(fs.readFileSync(full, 'utf8')))
      }
    }
  }
  walk(path.join('testdata', 'npm'))
  return [...ranges]
}

const OPERATORS = ['', '=', '>', '>=', '<', '<=', '~', '~>', '^', '>= ', '< ', '^ ']
const FORMS = [
  '1', '1.2', '1.2.3', '1.x', '1.X', '1.*', '1.2.x', '1.x.x', '1.*.*', 'x', 'X', '*', '0', '0.x', '0.0',
  '0.0.x', '0.1', '0.1.x', '0.0.3', '0.1.2', 'v1.2.3', '1.2.3-rc.1', '1.2.3-0', '0.0.3-beta', '1.2.3beta',
  '1.x.5', 'x.1', '01.02.03',
]
const COMPOUND = [
  '', '||', ' ', '1.x - 2.x', '1.2 - 2', '1.2.3 - 2.3', '1.2.3-rc.1 - 2.0.0', 'x - 1.2.3',
  '>=1.x <3', '>=0.x <1.x', '>=1.2.3 || <1.x', '^1.x || ^3', '>= 1.2.3 < 2.x', '~1.2.3 >=1.2.5',
  '>x 2.x || * || <x', '<x <* || >* 2.x', 'latest', 'latest || ^1', '^1 || garbage', '!=1.0.0',
  '>=1.0.0 <1.0.0', '>2 <1', 'npm:pkg@^1.0.0', '1.2.3 || 1.2.4 || 1.2.5', '>=14.x', '>= 14.x', '>=14.*',
  '>=v14.x', '>=14.x.x', '>14.x', '<=14.x', '^14.x', '^0.x', '^0.0.x', '~0.0', '^0',
  // A word that starts like a version and turns to junk: loose mode drops just that word.
  '1.2.3.4 || ^1', '>=latest || ^1', '^foo || 2', '^1 1.2.3.4', '1.2.3 - 2 3', '== 1.0.0 || foo',
  '~>=1.2', '>=1.2.3 junk <2', '>= latest ^1', 'xyz || 1', 'vue || 1', '1 | 2', '1.2.3| || 2', '1 ||| 2',
]

const ranges = [...new Set([
  ...fixture('range-include.js').map(([range]) => range),
  ...fixture('range-exclude.js').map(([range]) => range),
  ...fixture('range-parse.js').map(([range]) => range),
  ...manifestRanges(),
  ...OPERATORS.flatMap((op) => FORMS.map((form) => op + form)),
  ...COMPOUND,
])].filter((range) => typeof range === 'string').sort()

// Versions at and around every bound the range desugars to, where an off-by-one would show,
// plus a fixed spread so a range whose bounds all vanish (ANY, the null set) still gets checked.
const SPREAD = ['0.0.0', '0.0.0-0', '0.0.1', '0.1.0', '1.0.0', '1.0.0-rc.1', '1.2.3', '1.2.3-beta', '2.0.0', '99.0.0']
const probes = (range) => {
  const found = new Set(SPREAD)
  for (const includePrerelease of [false, true]) {
    for (const comparators of new semver.Range(range, options(includePrerelease)).set) {
      for (const { semver: bound } of comparators) {
        if (bound === semver.Comparator.ANY) continue
        const { major, minor, patch } = bound
        found.add(bound.version)
        found.add(`${major}.${minor}.${patch}`)
        for (const release of ['patch', 'minor', 'major']) found.add(semver.inc(bound.version, release))
        if (patch > 0) found.add(`${major}.${minor}.${patch - 1}`)
        if (minor > 0) found.add(`${major}.${minor - 1}.9`)
        if (major > 0) found.add(`${major - 1}.9.9`)
        for (const pre of ['0', 'alpha', 'rc.1']) found.add(`${major}.${minor}.${patch}-${pre}`)
        if (bound.prerelease.length) found.add(`${bound.version}.1`)
      }
    }
  }
  return [...found].filter((v) => semver.valid(v)).sort(semver.compare)
}

const validRange = (range, includePrerelease) => semver.validRange(range, options(includePrerelease))
const verdicts = (range, versions, includePrerelease) =>
  versions.map((v) => (semver.satisfies(v, range, options(includePrerelease)) ? '1' : '0')).join('')

const fixturePairs = [...fixture('range-include.js'), ...fixture('range-exclude.js')]
  .filter(([range, version]) => typeof range === 'string' && typeof version === 'string')
  .map(([range, version, opts]) => {
    const includePrerelease = !!(opts && typeof opts === 'object' && opts.includePrerelease)
    return { range, version, include_prerelease: includePrerelease, satisfies: semver.satisfies(version, range, options(includePrerelease)) }
  })

const versionStrings = [...new Set(fixturePairs.map(({ version }) => version).concat(
  ['1.2.3', 'v1.2.3', '=1.2.3', ' = v 1.2.3 ', '01.02.03', '1.2.3beta', '1.2.3-rc.01', '1.2.3+build.1',
    '1.2', '1', 'x', '1.2.3.4', '', 'not a version', `${Number.MAX_SAFE_INTEGER}.0.0`, '9007199254740992.0.0'],
))].sort()

const output = {
  node_semver: require(path.join(checkout, 'package.json')).version,
  versions: Object.fromEntries(versionStrings.map((v) => [v, semver.valid(v, { loose: true })])),
  fixture_pairs: fixturePairs,
  ranges: ranges.map((range) => {
    const entry = { range, parsed: validRange(range, false), parsed_prerelease: validRange(range, true) }
    if (entry.parsed === null) return entry
    const versions = probes(range)
    const min = semver.minVersion(range, { loose: true })
    return {
      ...entry,
      min_version: min && min.version,
      versions,
      satisfies: verdicts(range, versions, false),
      satisfies_prerelease: verdicts(range, versions, true),
    }
  }),
}

// One entry per line, so a regeneration diffs as the entries that changed.
const lines = (items) => items.map((item) => `  ${JSON.stringify(item)}`).join(',\n')
process.stdout.write(`{
 "node_semver": ${JSON.stringify(output.node_semver)},
 "versions": ${JSON.stringify(output.versions)},
 "fixture_pairs": [
${lines(output.fixture_pairs)}
 ],
 "ranges": [
${lines(output.ranges)}
 ]
}
`)
