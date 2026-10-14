---
title: Update rules
description: "The rules that decide which version OSS IQ recommends: the five update strategy tiers, the version ladder, and the solver's cooldown, CVE, peer and override rules."
---

# Update rules

`plan` picks at most one target version for each direct dependency. Three sets of rules decide
it, in this order: the update strategy tier, the version ladder, and the solver. Part of the
[reference](../reference.md).

| You have | Go to |
|---|---|
| A tier name, `--update-strategy` or `--strategy-override` | [Update strategy](#update-strategy) |
| `latest_in_range`, `latest_in_major` or `recommended_from_rung` | [Version ladder](#version-ladder) |
| A recommendation older than the latest version, or none | [Cooldown](#cooldown) |
| `↳ cooldown bypassed` | [CVE and end-of-life bypass](#cve-and-end-of-life-bypass) |
| A release rejected for a peer, on npm | [Peer dependencies](#peer-dependencies-npm) |
| `--override pkg==version` | [Forced versions](#forced-versions) |

For the reasoning behind these rules, see
[How a recommendation is decided](../recommendations.md).

(update-strategy)=
## Update strategy

`--update-strategy` picks which tier of the update pyramid a run targets. Each tier includes
everything the tiers before it do:

| Tier | Moves a package for |
|---|---|
| `security` | An exploitable CVE, with the smallest diff that clears it |
| `deprecation` | Also an end-of-life package |
| `standard` (default) | Also plain drift |
| `latest` | Also the newest version, widening the declared range to reach it |
| `cutting-edge` | Also pre-releases |

`--strategy-override pkg=tier` runs one package at a different tier than the rest of the run
(repeatable). `--override pkg==version` wins over both when given for the same package.

[How OSS IQ picks a target version](../recommendations/target-selection.md) lists what each tier
does with a package: when it withholds it, bumps it in range, widens the range or crosses a
major. The design and a worked example across all five tiers are in
[`src/ossiq/strategy/README.md`](https://github.com/ossiq/ossiq/blob/main/src/ossiq/strategy/README.md).

### Where the tier shows

| Output | Where |
|---|---|
| `status`, `plan`, `html` | The report header |
| `export` | `metadata.update_strategy`, plus a `strategy` object on each `PackageMetrics` entry: `motives`, `withheld_reason`, `requires_widening`, `escalation`, `widening_authorized`. `null` when the selector never ran for the package |
| `--format agent`, MCP tools | `update_strategy`, plus `motives` on each entry |

When a tier withholds a package, `plan` and `status` name the lowest tier that would move it:
`N more updates available under --update-strategy X`.

### Incomplete security data

`security` and `deprecation` move a package only for a qualifying CVE or end-of-life marker. If
the vulnerability data did not arrive, a run at either tier would print "nothing to do", exactly
as a clean project does.

`status`, `plan` and `export` refuse that answer. They exit non-zero with a "Security Data
Incomplete" error, and the MCP tools return the same error, unless you pass `--allow-partial`
(MCP: `allow_partial`).

Every other tier still exits 0, because drift alone justifies a move there: a degraded run gives
a thinner answer, not an empty one. A degraded `repositories` step never causes a refusal; it
thins `deprecation`'s coverage. See [Partial data](../recommendations/partial-data.md).

### Widening confirmation

At `latest` and `cutting-edge`, `apply` can rewrite a package's declared range to reach the
target. It asks for a second confirmation before it does, after the usual "proceed with N
updates?" prompt. `--yes` skips both.

(version-ladder)=
## Version ladder

Every `ScanRecord` carries the ladder of versions the package can reach, so a package held back
on an old major still shows the newest patch it can take:

| Field | Meaning |
|---|---|
| `latest_in_range` | Newest version that satisfies the declared `version_constraint` |
| `latest_in_major` | Newest version on the same major line as `installed_version` |
| `latest_version` | Newest version overall |

Each rung is a version newer than `installed_version`, or equal to it when that step admits
nothing newer. A rung is `None` only when it cannot be determined: no release data, or a declared
range that is satisfiable only *below* `installed_version`, which signals that the manifest and
lockfile disagree.

The ladder reports plain registry facts, with no cooldown, CVE filter or strategy applied. So
`latest_in_range` and `latest_in_major` can differ from the `recommended_version` that those
rules settle on.

### Which rung the recommendation came from

The [update strategy](#update-strategy) selector sets `recommended_version` by picking a rung:
`latest_in_range`, then `latest_in_major`, then `latest_version`. It takes the first rung the
tier reaches, or the newest for the freshness tiers. `recommended_from_rung` records the result:

| `recommended_from_rung` | Where the target sits | What `plan` and `apply` do |
|---|---|---|
| `SOLVER`, `IN_RANGE` | Inside `version_constraint` | Write it |
| `IN_MAJOR`, `LATEST` | Outside `version_constraint`; the range must be widened first | Hold it under *Requires constraint widening*, unless the tier is `latest` or `cutting-edge`, or a CVE or end-of-life motive carried the pick past its tier |

`--override` bypasses the widening hold, as it bypasses the cooldown.

(update-solver)=
## Solver rules

The solver recommends a version only when the whole dependency tree still resolves with it.
These rules apply to `plan` and `apply`, and to the *Recommended* column of `status`.

### Single pass

The solver recommends versions against the *current* lockfile. Applying a plan re-resolves the
tree, which can surface further recommendations. Re-run `plan` until it reports no updates; most
projects converge in one or two passes.

(cooldown-rule)=
### Cooldown

A direct dependency is recommended the newest version that is at least `--cooldown-period` days
old (default 7). A settled `0.9.0` is preferred over a two-day-old `0.10.0`.

| Case | Result |
|---|---|
| Every reachable version is younger than the cooldown | No version is recommended. `status` shows a blank *Recommended* cell and **Wait for cooldown**; `plan` lists the package under *Held for cooldown* |
| A transitive candidate is younger than the cooldown | The solver penalizes it heavily. If it is still the pick after solving, it is withheld the same way |
| A version has no publish date in the registry | It is never withheld |

See [Cooldown](../explanation/cooldown.md) for why.

### CVE and end-of-life bypass

When the installed version carries a CVE, or the package is abandoned or deprecated, the cooldown
does not apply. OSS IQ recommends the newest reachable version even if it is fresh, and the plan
marks it `↳ cooldown bypassed`.

A candidate version that is itself affected by a CVE is never recommended.

### New transitive dependencies

A package that enters the tree for the first time is resolved by the native package manager at
apply time, outside the cooldown. The plan projects its version and age, and flags an entry
younger than the cooldown with `⚠`. Under `--cutoff-date`, projections leave out versions
published after the cutoff.

### Peer dependencies (npm)

Every release declares its own `peerDependencies`, and which of them are optional. The solver
reads them from the registry metadata the scan already fetched, so they cost no extra requests.
A release is refused when:

- **An installed package peer-requires this one outside the release's version**, unless that
  package moves in the same plan. `vue` pins `@vue/server-renderer` to its own version, and
  `@vue/server-renderer` peer-pins `vue` back, so the two move together or not at all.
- **Its own peers cannot be met by what the tree will hold.** A peer that is already installed
  must be in range. A *required* peer that is not installed is installed by npm, so it must
  exist, and so must whatever *it* peer-requires (four levels deep). An *optional* peer that is
  not installed binds nothing; one that is installed is enforced, as npm enforces it.
- **Two picks contradict each other.** Two direct picks end on versions that peer-require each
  other out, or a pick contradicts where a transitive or `--ignore`d package ends up. The
  conflicting pick gives way to the newest release that does not conflict.

A range that the installed versions already violate is existing drift, not a reason to refuse a
bump. The refusal is named, for example
`↳ 7.0.2 rejected: @typescript-eslint/utils peer-requires typescript`, and the plan lists the
package under *Held by peer dependencies*.

PyPI has no peer dependencies, so none of this applies there.

### Lockstep families (npm)

When a package pins its dependencies exactly, bumping it moves them too. If an older copy of one
of them stays hoisted because something else still wants it, npm nests the new family under the
bumped package and leaves two copies of each side by side. That installs, but it breaks anything
that loads the hoisted copy: this is how `@vue/test-utils` lost `@vue/server-renderer`.

Where the pinned copy has to move, the plan moves it in place with an `overrides` entry keyed to
the copy, and nests no second one. When another user of the shared copy cannot take the new
version, the plan refuses the bump and names the specifiers.

### Peer repairs (npm)

The plan repairs an already-split tree the same way. See
[Unresolved peers](#unresolved-peers).

### Forced versions

`--override pkg==version` bypasses the solver and the cooldown for one package. How the version
persists depends on the package manager:

| Package manager | Direct dependency | Transitive dependency |
|---|---|---|
| npm | Specifier rewritten to the exact version | Persistent `overrides` entry in `package.json` |
| uv | Specifier rewritten to `==version` | Persistent `override-dependencies` entry under `[tool.uv]` |
| pip | Constraints-file pin for the run | Constraints-file pin for the run (not persistent) |

Later scans report a forced package with `ConstraintType.OVERRIDE`, so it stays visible until
you remove the override. See [Constraints, overrides and aliases](constraints.md).
