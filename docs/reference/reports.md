---
title: Console and HTML reports
description: "What ossiq status, ossiq info and the HTML report show: every section, column, status marker and sub-row, and what each one means."
---

(console-reports)=
# Console and HTML reports

Every section, column, marker and `↳` row that `ossiq status`, `ossiq info` and the HTML report
show. Part of the [reference](../reference.md).

| You have | Go to |
|---|---|
| A column in the `status` table | [Dependency table](#dependency-table) |
| A label under *What's Next* | [What's Next labels](#whats-next-labels) |
| A marker such as `[YANKED]` or `[pre]` | [Lifecycle markers](#lifecycle-markers) |
| A `↳`, `+` or `✗` row under a package | [Sub-rows](#sub-rows) |
| `✓ satisfied`, `✓ via override` or `✗ violation` | [Peer Constraint Status](#peer-constraint-status) |
| A `missing peer` or `out of reach` row | [Unresolved peers](#unresolved-peers) |
| A section of `ossiq info` | [`info` report](#info-report) |
| A badge or node color in the HTML report | [HTML report](#html-report) |

For the same data as JSON, see
[JSON export and agent format](export-and-agent-format.md).

## `status` report

```bash
ossiq status [PROJECT_PATH]        # default: only what needs action
ossiq status --full [PROJECT_PATH] # every package, every column
```

By default the report shows only the packages that need
attention (a version behind, a CVE, an unmaintained upstream, or an unsolvable
constraint) and a four-column table. `--full` shows every package and the detail
columns.

The report has up to six parts, printed in this order. Parts with nothing to show are omitted.

1. **Header**: project name, registry (`npm` or `pypi`), path, and counts: production packages, development packages, and transitive packages with an update recommendation.
2. **Dependency table**: one row per direct dependency, grouped into *Production* and *Development* sections.
3. **Transitive Recommendations**: transitive packages the solver recommends updating.
4. **New transitive dependencies**: packages that would enter the tree if the recommended updates were applied.
5. **Peer Constraint Status**: peer dependency requirements and whether the installed versions satisfy them (npm projects only; violations only unless `--full`). Peers that are installed but out of reach are not here: they appear as [unresolved-peer rows](#unresolved-peers) under the package that declares them.
6. **Constraint Widening Opportunities**: for library projects, dependency ranges that could safely be widened.

### Dependency table

Default columns: **Package**, **CVEs**, **Installed**, **Latest**, **Recommended**, **What's
Next**. `--full` adds **EPSS**, **Update Mode**, **Lag**, and **State**.

| Column | Meaning |
|---|---|
| Package | Package name. |
| CVEs | Number of known vulnerabilities affecting the installed version. Empty when there are none. |
| EPSS | *(`--full`)* Probability that the package's worst known CVE sees exploitation in the next 30 days. `—` means no CVE carries a score, which is unknown rather than safe. |
| Update Mode | *(`--full`)* Semantic drift between installed and latest version: `Latest`, `Patch`, `Minor`, `Major`, `Prerelease`, `Build`, or `N/A` when the latest version is unknown. |
| Installed | Version resolved in the lockfile, with a [lifecycle marker](#lifecycle-markers) when one applies. |
| Latest | Newest version the registry publishes, ignoring your declared range. This is what **Update Mode** and **Lag** are measured against. `—` when it could not be determined. |
| Recommended | Solver-recommended update target — clamped into your declared range, so it is often *not* the Latest version. Yellow when the recommendation is older than the latest version — usually held back by the [cooldown](#update-solver) or by a constraint. `[NO RESOLUTION]` when no published version satisfies all constraints. Blank when no acceptable target was found at all — including when every newer version is still inside the [cooldown](#update-solver), in which case *What's Next* reads **Wait for cooldown**. |
| Lag | *(`--full`)* Time between the installed and the latest version. Red when it exceeds `--lag-threshold-delta` (default `1y`). |
| State | *(`--full`)* Maintenance-state verdict for the upstream repository: `maintained`, `winding_down`, `abandoned`, or `deprecated`. `—` when the package could not be assessed. See [Repository Stability](../explanation/repository-stability.md). |
| What's Next | The single next action for this package. See [What's Next labels](#whats-next-labels). Blank when nothing is due. |

### What's Next labels

Each package gets at most one label. The rules run in this order, and the first match wins:

| Label | Shown when |
|---|---|
| **Check for the Fix** | The package has a CVE with an EPSS of 10% or more. |
| **Find alternative** | The registry deprecated, archived or quarantined the package, or the package is at its latest version and upstream is abandoned or deprecated. |
| **Consider alternative** | Upstream is winding down. |
| **Wait for cooldown** | A newer version exists, but every version reachable from the installed one is younger than the cooldown period. No version is recommended. |
| **Check Release Notes** | The package is a major version behind. |
| **Update Immediately** | The package is a minor or patch behind, and `plan` will write a newer version. That version is inside the declared range, or past it when the run's tier reaches that far or a CVE or end-of-life motive carried the pick past it. |
| **Withheld by strategy** | A bump is available and the range admits it, but the run's `--update-strategy` tier admitted no motive to take it. The sub-row names the lowest tier that would. |
| **Constrained. Check newer version** | The package is a minor or patch behind, but the declared range admits no bump `plan` will write. Widening the range is the next step. |

On a terminal narrower than 110 columns, or 157 with `--full`, **Constrained. Check newer
version** is shortened to **Constrained**. The `--full` sub-row under the package still names the
range and what it caps. Only the console shortens it: `--format agent`, the JSON export, the MCP
tools and the HTML report always carry the full label.

### Lifecycle markers

The *Installed* column carries a marker when one applies:

| Marker | Meaning |
|---|---|
| `[UNPUBLISHED]` | The installed version has been removed from the registry. |
| `[YANKED]` | The installed version was yanked by its maintainer. |
| `[DEPRECATED]` | The installed version, or the whole package, is deprecated. |
| `[ARCHIVED]` | PyPI marks the whole package archived: no further releases are expected. |
| `[QUARANTINED]` | PyPI flags the whole package as unsafe to use. |
| `[pre]` | The installed version is a pre-release. |

### Sub-rows

A row can carry indented sub-rows. They say what applying the recommendation would do to the rest
of the dependency tree, or what holds the package back:

| Sub-row | Meaning |
|---|---|
| `↳ <package> <current> → <projected>` | Updating the parent also moves this transitive package. When more than three packages would move, a count is shown instead of the list. |
| `+ <package> <version> (new dep)` | Updating the parent introduces this package into the tree. Listed with full detail in **New transitive dependencies**. |
| `↳ ⚠ <package>: <detail>` | The update collides with a constraint on this transitive package. See [When an update is blocked](#update-blocked). |
| `✗ no actionable update found` | Every candidate update collides with a transitive constraint; the solver has no version to recommend. See [When an update is blocked](#update-blocked). |
| `↳ no version satisfies: <specifiers>` | The constraints on this package contradict each other — no published version satisfies all of them at once. Shown together with `[NO RESOLUTION]`. |
| `↳ <specifier> caps this below <latest>[; <version> is the newest in the current major line]` | *(`--full`)* The declared range is what holds the package behind the registry's latest. Drawn only when the range genuinely admits nothing newer than what is installed — when it does admit a bump, the blocker is something else and draws its own row. The trailing clause appears only when the newest version within the installed major line differs from the latest overall. Shown with **Constrained. Check newer version**. |
| `↳ <version> is <n> days old; nothing older to move to before the <n>-day cooldown` | *(`--full`)* Every release newer than the installed one is younger than `--cooldown-period`, so no version was recommended. Names the release being waited on. Not drawn when a CVE or end-of-life motive is in play — those escalate past the cooldown rather than waiting it out. Shown with **Wait for cooldown**. |
| `↳ no motive admitted at <tier>; available under --update-strategy <tier>` | *(`--full`)* The run's update strategy, not the declared range, is what left this package without a target. Shown with **Withheld by strategy**. |

### Transitive Recommendations

Transitive packages — packages your direct dependencies pull in — for which the solver recommends a different version, most often because the installed version carries a CVE or is far behind. With `--update-strategy security`, the list narrows to packages with CVEs only. To turn these recommendations into an executable update plan, run `ossiq plan` (see [Update Solver](#update-solver)).

Columns: **Package**, **CVEs**, **Installed**, **Recommended**, **What's Next**; `--full` adds **EPSS**. The **Recommended** version is the one the solver picks within all parent constraints; **What's Next** follows the same rules as the dependency table.

### New transitive dependencies

Packages that are not in the tree today, and that the recommended updates pull in. The native package manager resolves their versions at apply time, outside the solver's cooldown, so OSS IQ flags a fresh entry and does not withhold it. A `⚠` before the package name means the projected version is younger than the cooldown period: look at it before you apply. [Cooldown](../explanation/cooldown.md#new-transitive-dependencies-sit-outside-the-cooldown) explains why.

| Column | Meaning |
|---|---|
| Package | New package name, prefixed with `⚠` when younger than the cooldown period. |
| Version | Version the package manager is projected to resolve. |
| Constraint | Version range declared by the package that requires it. |
| Age | Age of the projected version, in days. |
| Required By | The direct dependency whose update introduces this package. |

(peer-constraint-status)=
### Peer Constraint Status

npm packages can declare `peerDependencies`: versions of *other* packages they expect to find installed next to them but do not install themselves. A plugin that declares which framework versions it works with is the classic example. npm enforces these at install time, but overrides, `--legacy-peer-deps`, and `--force` installs can leave the tree in a state npm never checked. OSS IQ re-validates every peer requirement against the lockfile on every scan. PyPI has no peer dependency mechanism, so this table only appears for npm projects.

| Column | Meaning |
|---|---|
| Package | The package the requirement applies to. |
| Installed | Its installed version. |
| Peer Constraint | The version range the requirer expects. |
| Required By | The package that declares the peer requirement. |
| Status | One of the three values in the next table. |

| Status | Meaning |
|---|---|
| `✓ satisfied` | The installed version is inside the required range. |
| `✓ via override` | The installed version satisfies the range, but it is forced by an `overrides` entry rather than resolved normally. The override — not the resolver — is what keeps this pair compatible; re-check this row whenever the override changes. An override OSS IQ wrote reads `✓ satisfied`. |
| `✗ violation` | The installed version is outside the range the requirer declared. |

A `✗ violation` means two packages you ship disagree about a third. The requirer was built
against the declared peer range and can fail at runtime outside it, even though the install
succeeded. To fix one, see
[Fix a peer violation](../how-to/resolve-blocked-updates.md#fix-a-peer-violation).

(unresolved-peers)=
### Unresolved peers

A peer requirement can be *satisfied* (see [Peer Constraint Status](#peer-constraint-status)) and still be *unreachable*. npm resolves a peer from the requiring package's own location: its own `node_modules`, then up the tree. A copy nested under some other package does not count. When the only copy of a peer sits where its requirer cannot see it, the requirer fails when it loads, for example with `Cannot find module '@vue/server-renderer'`. No version range anywhere is violated. A lockfile does not show this as a conflict, which is why OSS IQ reports it separately.

An unresolved peer is shown as a `↳` row under the package that declares it, in every mode (not only `--full`), and a package that has one stays on the default table even when it is otherwise up to date:

| Row | Meaning |
|---|---|
| `↳ missing peer host ^1: nothing installed where this package looks for it` | A required peer that npm should have installed is not installed where the package looks. |
| `↳ optional peer @vue/server-renderer 3.x is installed only out of reach (3.5.43); this package cannot load it` | A copy exists, but only nested under another package. |

The same entries are listed under **Unresolved Peers** in [`ossiq info`](#info-package-report) and exported as `unresolved_peers` (schema 1.6).

An *optional* peer that is installed nowhere is normal and is **not** reported. It is reported only when a copy exists out of reach, because that is the layout in which a package that imports it unguarded breaks.

When an out-of-reach copy satisfies the range the package declares, `plan` proposes a repair
under *Repairs unresolved peers*, and `apply` writes it:

- The peer is added to `devDependencies`, or to `dependencies` when a production package needs
  it. Its range follows the style of the family it belongs to, tilde by default, so that npm
  places it where its requirers resolve it.
- The stale hoisted copies of its exact-pinned family move with it, each as a keyed `overrides`
  entry (see [npm: `overrides`](#npm-overrides)). A copy that another package still pins to the
  old version is left alone.
- A peer already declared anywhere in your manifest is never rewritten.

After `ossiq apply`, a second `ossiq plan` reports nothing. When no out-of-reach copy satisfies
the declared range, OSS IQ has nothing to repair and the row stays. To repair a peer by hand, or
to handle that last case, see
[Repair an unresolved peer](../how-to/resolve-blocked-updates.md#repair-an-unresolved-peer).

### Constraint Widening Opportunities

Shown for library projects only: dependency ranges in your manifest whose upper bound excludes versions that already exist and resolve cleanly.

| Column | Meaning |
|---|---|
| Package | Direct dependency with a narrowed range. |
| Current Range | The range declared in the manifest today. |
| Latest In-Range | Newest version the current range allows. |
| Latest Available | Newest version published on the registry. |
| Suggested Range | Widened range that admits the latest available version. |

(info-package-report)=
## `info` report

```bash
ossiq info PACKAGE_NAME [PROJECT_PATH]
```

A deep-dive into one package. When the package is installed in the project, the report has the following sections, in order; empty sections are omitted. When it is not installed, the report switches to [prospective mode](#info-prospective).

### Header

Package name and installed version; role tags `DIRECT` and/or `TRANSITIVE` (both, when the package appears in both roles); a lifecycle marker (`[UNPUBLISHED]`, `[YANKED]`, `[QUARANTINED]`, `[ARCHIVED]`, `[DEPRECATED]`, `[pre]` — same meanings as in the status table); license; registry URL.

### Warnings

A panel of package health findings: `✗` marks critical findings (these block `ossiq add` unless `--force` is passed), `!` marks notices. Examples: a package its registry deprecated, archived or quarantined (critical; the finding quotes the registry's note), a deprecated release you asked for with `--version` (critical), a package with a single published version (critical; typosquatting risk), a single maintainer (bus-factor risk).

### Health Metrics

Registry-level signals: downloads over the last month, number of published versions, maintainer count, age of the latest version, age of the recommended version (when it differs from the latest), and cooldown remaining — days until the latest release is old enough to clear the [cooldown period](../explanation/cooldown.md).

For an installed package, this block also shows the two risk pipelines:

| Row | Meaning |
|---|---|
| EPSS | Probability that the package's worst known CVE sees exploitation in the next 30 days. |
| Gap CV | Coefficient of variation of inter-commit gaps from the [repository's last 100 commits](../explanation/repository-stability.md), and how many commits it spans. `too few gaps` below 20 sampled gaps. |
| ↳ silence | Days since the most recent sampled commit, and the empirical probability (`p`) of a silence this long, from the repository's own history. |
| Last pushed | Time since the last push to the upstream repository. |
| Repository archived | Shown only when the upstream repository is archived. |
| Triage | The recommended action and why. |
| Fix available | How long a fix for a known CVE has been published without being applied. |
| Runs code at install | Whether installing the package executes code, and what indicated it. |

Any of these can render `—`: it means the signal could not be measured, never that the package carries no risk.

### Occurrences

A package can appear in the tree more than once — for example as a direct dependency and, at a different version, as a transitive one. Each occurrence gets its own block of the next five sections, labelled `Occurrence n of m`.

### Drift Status

Status (same values as the status table), installed version, latest version, time lag (red past 180 days), how many releases behind the installed version is, and the next recommended action (same rule as the status table's **What's Next** column; blank when nothing is due).

### Dependency Tree

The ancestor path from the project root down to this package (`← you are here`). For a direct dependency the path is `root → package`. For a transitive one it names every intermediate package, so you can see *which* direct dependency pulls this package in.

### Policy Compliance

How the installed version relates to the rules that produced it:

| Row | Meaning |
|---|---|
| Constraint | Version specifier from the manifest, or `—` for transitive packages without one. |
| Resolved | The installed version. |
| In Range | Newest version the declared constraint already admits — reachable with no manifest edit. Dimmed when it equals the installed version, which means the range admits nothing newer; omitted only when it could not be determined. |
| In Major | Newest version sharing the installed major line, under the same rules. |
| Compatible Major | Newest version across majors at or above the installed one that carries no known module-system or API break. Shown only when it differs from **In Major**, that is, when a known break sits in between. |
| Latest | Most recent published version. |
| Recommended | Solver-recommended target, when one exists. Yellow when held below the latest. When reaching it requires widening the declared constraint (an out-of-range ladder pick), a dim `(requires widening <constraint> — same major/new major)` caveat is appended — `ossiq apply` holds these back; it does not write them automatically. The rung the recommendation came from is marked `← recommended` in the *In Range*, *In Major* and *Latest* rows. |
| Resolution | `NO VALID VERSION — conflicting constraints: <specifiers>` when the solver found no version satisfying all constraints. See [When an update is blocked](#update-blocked). |
| Constraint Type | Shown only when the version is controlled by something beyond a plain manifest entry (`PINNED`, `NARROWED`, `ADDITIVE`, `OVERRIDE`), with the file that introduced it. See [Constraint Provenance](#constraint-provenance). |

### Recommendation Rationale

Why the solver picked the recommended version, and why it rejected the others:

- *Eliminated (hard constraints)*: versions that can never be chosen: outside a parent's range, affected by a CVE, yanked, or pre-release without `--allow-prerelease`. When `ossiq add` picks a version for a package that is otherwise live, deprecated releases are eliminated too.
- *Penalised (soft constraints)*: versions that remain eligible but are scored down, for example younger than the cooldown period, or deprecated (in a project scan).
- The closing `✓` line states the selection: the latest eligible version, or the best stable candidate when the latest was eliminated or penalized.

If the version you expected is not the recommendation, this section names the exact rule that removed it.

### Peer Requirements

Every peer constraint other packages place on this one, with the same markers as the status report's [Peer Constraint Status](#peer-constraint-status) table: `✓` satisfied, `✓ … via override`, `✗` violated (the installed version is shown in red next to the violated range). To fix a violation, see [Fix a peer violation](../how-to/resolve-blocked-updates.md#fix-a-peer-violation).

### Unresolved Peers

Peers this package declares that nothing within its reach satisfies, each with its range, whether it is optional, and the versions installed out of reach (or `not installed`). Drawn only when there are any; see [Unresolved peers](#unresolved-peers).

### Security Advisories

Known vulnerabilities in the installed version of *this* package: severity, advisory ID, source database, and summary — or `✓ No known vulnerabilities`.

### Transitive CVEs

Vulnerabilities in packages *downstream* of this one — exposure you carry because this package pulls the affected ones in. Grouped per affected `package@version`, worst severity first. Updating this package may or may not resolve them; run `ossiq info <affected package>` to see what constrains each one.

### Licenses

Listed only when the package's occurrences carry more than one SPDX identifier; a single unambiguous license is already shown in the header.

(info-prospective)=
### Prospective mode

When the package is not installed in the project, `info` evaluates it as a candidate instead: the header carries a `PROSPECTIVE` tag, a lifecycle marker when the registry deprecated, archived or quarantined the package, and the registry description, followed by health metrics, the recommendation rationale, and security advisories. This is the same pre-installation check that `ossiq add` runs before installing.

## HTML report

The `ossiq html` command produces a self-contained HTML file embedding an interactive Vue.js single-page application. The report includes the full dependency tables and the **Transitive Dependency Explorer**: an interactive D3 tree that visualises the `transitive_packages` dependency graph.

The dependency table shows the same version ladder the console does. Under **Latest**, a dim `in range <version>` line names the newest version the declared constraint already admits, and `in major <version>` the newest in the installed major line; each appears only when it sits below the registry's latest, which is exactly when something is holding the package back. A `widen` badge on **Rec. Version** means the recommendation lies outside the declared range, so `ossiq apply` will not write it without the range being widened first. Selecting a package opens a **Version Ladder** block with every rung and the one the recommendation came from. **What's Next** carries the label the scan decided, so it never disagrees with `ossiq status`.

The Explorer supports:

- Color-coded nodes by risk type — six priority tiers: CVE (red), OVERRIDE (orange dash-dot), ADDITIVE (green dotted), PINNED (orange solid-thick), NARROWED (yellow dashed), DECLARED (blue)
- Fuzzy search and toggle filters (CVE, Narrowed, Override/Pinned)
- Click to focus a node and highlight all ancestor and descendant paths
- Alt+Click to collapse or expand a subtree
- Dashed curved links between nodes sharing an identical `package_name@installed_version`
- Zoom and pan

For full Explorer interaction details, see [EXPLORER.md](https://github.com/ossiq/ossiq/blob/main/frontend/EXPLORER.md).
