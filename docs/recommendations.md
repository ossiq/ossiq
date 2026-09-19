# Recommendations and Risk

**Every line OSS IQ prints under *Recommended*, *What's Next* or *Plan* is a decision taken on your
behalf. This page says what each decision means, which evidence it rests on, and what it costs you
when that evidence is missing or wrong.**

[Reference → Update Strategy](reference.md#update-strategy) and
[Reference → Version ladder](reference.md#version-ladder) define the flags and the fields. This
page is the *why*, and it is the one to read before you wire `ossiq` into CI, hand it to a coding
agent, or run `apply --yes`.

---

## How a recommendation is decided

Three questions, answered in order by three different parts of the tool:

| # | Question | Answer | Decided in |
|---|---|---|---|
| 1 | May this package move at all? | a set of **motives** | [`strategy/motive.py`](https://github.com/ossiq/ossiq/blob/main/src/ossiq/strategy/motive.py) |
| 2 | How far up the version ladder may it go? | a **reach** | [`strategy/pyramid.py`](https://github.com/ossiq/ossiq/blob/main/src/ossiq/strategy/pyramid.py) |
| 3 | May `apply` write the result? | the picked **rung** vs. the tier's authorization | [`service/update.py`](https://github.com/ossiq/ossiq/blob/main/src/ossiq/service/update.py) |

Questions 1 and 2 are pure functions over facts already gathered — no network, no clock. Question 3
is where something you can *read* becomes something OSS IQ will *write*.

Two invariants hold across all of it:

- **No downgrades.** Every candidate is strictly newer than the installed version, at every tier,
  under every motive. A recommendation can be blank; it can never point backwards.
- **A visible recommendation is not an authorized write.** `status` can show a target that
  `plan` files under *Requires constraint widening* and `apply` will not touch. See
  [The writable/readable split](#the-writable-readable-split).

(the-pyramid)=
## 1. The update pyramid

`--update-strategy` picks one of five tiers. Each tier is a strict superset of the one below: it
admits every reason to move that the lower tier admits, and it can reach at least as far.

```
                    ┌──────────────┐
                    │ cutting-edge │  + prereleases
                  ┌─┴──────────────┴─┐
                  │      latest      │  + widen the constraint to reach newest
                ┌─┴──────────────────┴─┐
                │       standard       │  + any drift, inside the declared range
              ┌─┴──────────────────────┴─┐
              │       deprecation        │  + end-of-life packages
            ┌─┴──────────────────────────┴─┐
            │          security            │  exploitable CVEs only, minimal diff
            └──────────────────────────────┘
```

| Tier | Moves a package for | Base reach | Picks | Answers |
|---|---|---|---|---|
| `security` | an exploitable CVE | in-range | the **nearest** CVE-clear version | "What must I patch today?" |
| `deprecation` | + end-of-life | in-range | the **nearest** version that resolves it | "What is dying under me?" |
| `standard` *(default)* | + plain drift | in-range | the **newest** version in range | "What would I install today?" |
| `latest` | + plain drift | latest | the **newest** version, range rewritten | "What is current?" |
| `cutting-edge` | + plain drift | latest, prereleases included | the **newest** release of any kind | "What is about to be current?" |

The bottom two tiers **minimise the diff**; the top three **maximise freshness**. That split is the
point of the pyramid: a security patch that also carries six months of unrelated drift is an
unreviewable diff, and an unreviewable diff is how a rushed CVE fix breaks production.

### Two axes, not one dial

A tier sets two independent things, kept in two separate tables on purpose:

- **Motive** — *why* a package may move ([`ADMITTED_MOTIVES`](#motives)).
- **Reach** — *how far up the ladder* it may go on that motive (`MAX_REACH`).

Collapsing them would make "why did this move" and "how far could it move" the same question, and
they are not. An end-of-life package may have to leave its declared range even under the otherwise
minimal-diff `deprecation` tier.

### Escalation: the pyramid refuses to say "stay put"

Two motives — `exploitable_cve` and `end_of_life` — push reach to `latest` regardless of tier.
"Remain inside a range that contains no safe version" is not an answer OSS IQ will give. When that
happens, the selection carries an `escalation` string naming the reason. The same applies when
*every* reachable version still carries a qualifying CVE: OSS IQ picks the newest anyway and says so
rather than silently recommending nothing.

Freshness tiers get one more escape: if drift alone leaves nothing in reach — an exact pin whose
only newer releases sit outside the declared range — reach widens one rung at a time until
something is found. This is why a `pydantic==1.10.13` pin yields `1.10.26` instead of `None`.

### A real run, two tiers

Same project ([`testdata/pypi/version-constraint`](https://github.com/ossiq/ossiq/tree/main/testdata/pypi/version-constraint)),
two tiers, verified output:

| Package | Declared | Installed | `security` | `standard` |
|---|---|---|---|---|
| `requests` | `~=2.31.0` | 2.31.0 | **2.32.4** — nearest CVE-clear | **2.34.2** — newest |
| `jsonschema` | `<4.5.0,>=4.0.0a6` | 4.4.0 | no target | **4.26.0** — widening |
| `numpy` | `!=1.24.2,<2.0.0` | 1.26.4 | no target | **2.5.3** — widening, new major |
| `pydantic` | `>=2.0.0` | 2.12.5 | no target | **2.13.5** |
| `scikit-learn` | `<2.0.0` | 1.8.0 | no target | **1.9.1** |

`ossiq plan` at `security` closes with `4 more updates available under --update-strategy
standard.` — the tier reports what it withheld and names the cheapest tier that would move it. In
`status --full` the same fact arrives per package, as the `↳` row under `Withheld by strategy`.

### What tier choice risks

| Tier | The risk you accept | How it surfaces |
|---|---|---|
| `security` | Drift and maintenance debt accumulate invisibly; a package with only low-EPSS CVEs is never moved at all. At `security` and `deprecation` alike, the transitive solver also narrows itself to CVE-affected packages. | "N more updates available under…" footer; packages sit at `Withheld by strategy`, whose `↳` row names the lowest tier that would move them |
| `deprecation` | The same minimal-diff risk, now resting on maintenance evidence that may never have been gathered — see [§6](#partial-data). | Silent: an unassessed package simply carries no `end_of_life` motive | Silent: an unassessed package simply carries no `end_of_life` motive |
| `standard` | Packages whose only newer releases sit outside the declared range are recommended but **not written** — the default tier proposes changes it will not apply. | *Requires constraint widening* block in `plan` |
| `latest` | Authorizes rewriting declared ranges. That range was a decision someone made, possibly encoding an incompatibility OSS IQ cannot see. | Second confirmation prompt in `apply` |
| `cutting-edge` | Prereleases enter the candidate set. Cooldown still applies, but a prerelease is by definition unproven. | The picked version itself |

```{note}
`--strategy-override pkg=tier` runs one package at a different tier; `--override pkg==version`
forces an exact version and wins over both. A forced version bypasses the solver, the cooldown, the
widening hold **and** the acknowledgement prompt — its compatibility is deliberately unverified.
```

(motives)=
## 2. Motives — why a package is allowed to move

A motive is evidence that a package *should* change. Four exist; `classify_motives` derives them
from facts already on the scan record.

| Motive | Set when | Evidence source |
|---|---|---|
| `exploitable_cve` | any CVE with EPSS ≥ 0.005 **or with no EPSS score at all** | OSV + EPSS |
| `suppressed_cve` | a CVE scored below 0.005 | OSV + EPSS |
| `end_of_life` | maintenance state is `abandoned`/`deprecated`, **or** a registry deprecation marker, **or** strong deprecation evidence | registry + GitHub + the [maintenance model](explanation/repository-stability.md) |
| `drift` | always | — |

Which tier admits which:

| Tier | `exploitable_cve` | `end_of_life` | `drift` | `suppressed_cve` |
|---|:---:|:---:|:---:|:---:|
| `security` | ✓ | | | |
| `deprecation` | ✓ | ✓ | | |
| `standard` | ✓ | ✓ | ✓ | |
| `latest` | ✓ | ✓ | ✓ | |
| `cutting-edge` | ✓ | ✓ | ✓ | |

`suppressed_cve` is admitted by nothing. It is reported for visibility and never unlocks a tier.

### Three deliberate asymmetries

**An unscored CVE counts as exploitable.** [`risk/triage.py`](https://github.com/ossiq/ossiq/blob/main/src/ossiq/risk/triage.py)
drops unscored CVEs; this module promotes them. The difference is what the two are for: triage is
*advisory* — a human reads it and decides. The motive set gates *writes*. Recommending a version
that still carries an unscored CVE would be a decision made on someone's behalf, and absent
evidence must not read as absent risk.

**`winding_down` is not end-of-life.** A maintainer who is slowing down has not stopped. It surfaces
as `Consider alternative` in *What's Next*, which is the right severity. Promoting it would make the
minimal-diff tiers move packages whose maintainers are still shipping fixes.

**`drift` is unconditional.** Every package carries it. Whether there is actually anywhere newer to
go is decided by the candidate ladder, not here — which is why `standard` on an up-to-date project
correctly reports nothing to do rather than "no motive".

### What motives risk

| Risk | Why | Mitigation |
|---|---|---|
| **A missing source silently removes a motive.** OSV unreachable → no CVEs → no `exploitable_cve` → `--update-strategy security` reports *"nothing to do"*, character-for-character identical to a clean project. | Motives are derived from fetched evidence, and an absent fetch looks like absent evidence. | Check `data_completeness` before trusting an empty security run — [§6](#partial-data) |
| **Triage and the motive set can disagree, by design.** With EPSS degraded, a package's CVEs are unscored: the strategy treats it as exploitable and moves it; triage drops the unscored score, finds no exploit signal and reports `retain`. | Fail-safe for writes, evidence-based for advice. | Read `triage` as advice, `motives` as the reason something moved |
| **`end_of_life` leans on GitHub.** With the repositories step degraded, the maintenance model may not run at all, leaving `end_of_life` resting on registry markers alone. | The model needs commit/activity/README observations. | `--update-strategy deprecation` is only as good as that scan's repository coverage |

(recommendations)=
## 3. Every recommendation OSS IQ can make

Five distinct kinds of output tell you to do something. They are computed by different modules
against different evidence, and they are *not* rankings of each other.

### 3.1 The target — `recommended_version` + `recommended_from_rung`

The version to move to, and which rung of the [version ladder](reference.md#version-ladder) it
came from.

| Rung | Meaning | Writable by `apply`? |
|---|---|---|
| `solver` | the SAT solver's own pick, inside the declared constraint | yes |
| `in_range` | newest version satisfying the declared constraint | yes |
| `in_major` | newest within the installed major line — **outside** the declared range | only if the tier authorizes widening |
| `latest` | newest overall — **outside** the declared range | only if the tier authorizes widening |

(the-writable-readable-split)=
The rung, not the version, decides whether `apply` may write. `in_major` and `latest` require
rewriting the manifest's declared range first, so `build_update_plan` withholds them into
*Requires constraint widening* unless the run's tier reaches that far. `status` and the agent
payload still show them — with `requires_constraint_widening: true` — because knowing a newer
version exists is useful even when taking it needs a human decision.

### 3.2 `next_action` — the one-line headline

One label per package, first match wins, most urgent first:

| Label | Fires when | What it does **not** mean |
|---|---|---|
| `Check for the Fix` | a CVE with EPSS ≥ 0.10 | not "a fix exists" — only that exploitation is probable |
| `Find alternative` | already at latest **and** upstream is not maintained | — |
| `Consider alternative` | upstream is `winding_down` | not abandoned; not urgent |
| `Check Release Notes` | major-version drift | not "this will break" |
| `Update Immediately` | minor/patch drift with a writable in-range target | — |
| `Constrained. Check newer version` | minor/patch drift and the declared range admits nothing newer | not "the package is broken" — the range is the thing to change |
| `Withheld by strategy` | minor/patch drift, a bump is reachable, but the tier admitted no motive | **not** the constraint's fault — a higher `--update-strategy` moves it |
| *(none)* | nothing is due | — |

The two are decided in different places and must not be confused. `Constrained. Check newer
version` is a fact about the manifest: the declared range admits nothing newer than what is
installed, so widening it is the next step. `Withheld by strategy` is a fact about *this run*:
`security` and `deprecation` move a package only on a qualifying motive, and without one the
package is left alone however much newer the registry has gone. The `↳` sub-row under each names
its own cause, and the withheld one names the lowest tier that would move it — so a second run at
a higher tier is a confirmation, never a cross-check you are obliged to perform.

### 3.3 `triage.action` — the operational verdict

From the EPSS × maintenance matrix (see [Repository stability](explanation/repository-stability.md#the-triage-matrix)):
`retain`, `patch`, `refactor`, `evict`. **Advisory only** — it appears on every surface but changes
no recommendation and gates no build.

### 3.4 The add decision — `install` / `install with caution` / `do not install`

Produced by `ossiq add` and the `ossiq_evaluate_dependency` MCP tool, for a package not yet in the
tree. `do not install` on critical health warnings; `--force` overrides.

### 3.5 The non-recommendations

These carry as much decision-making weight as the targets, and are easier to skim past:

| Output | Means | Where |
|---|---|---|
| `withheld_reason` | no motive admitted at this tier; names the lowest tier that would move it | `plan` footer, the `status --full` `↳` row under `Withheld by strategy`, agent `strategy_withheld_reason`, export `strategy` |
| *Held for cooldown* | target is younger than `--cooldown-period` (default 7 days). CVE-carrying packages are exempt | `plan` section |
| *Requires constraint widening* | target sits outside the declared range and the tier does not authorize rewriting it | `plan` section, export `requires_constraint_widening` |
| `rejected_candidates` | a newer release was found and held back — by a transitive conflict, a known module-system break, or an engine mismatch — one per rung, with the reason | `status --full` `↳` rows, export, agent `reasons` |
| `constraint_conflict` | no version satisfies all constraints (`[NO RESOLUTION]`) | `status`, `info` |
| `escalation` | reach was pushed past the tier's base, or every reachable version still carries a CVE | export `strategy`, agent |
| *New transitive dependency* `⚠` | a package entering the tree for the first time, younger than the cooldown. Resolved by the native package manager, so the cooldown hold cannot apply to it | `plan` section |

A blank *Recommended* cell with no accompanying `↳` row means OSS IQ found nothing newer. A blank
cell **with** a `↳` row means it found something and refused it, and the row says why.

### What the recommendation catalogue risks

- **Mistaking advice for a gate.** `triage_action` and `next_action` change no exit code. `ossiq
  status` exits 0 on a project full of `evict` verdicts. Any CI gate is yours to write, over the
  JSON export. The single exception is not a gate but a refusal: a `security`/`deprecation` run
  whose vulnerability data never arrived exits non-zero rather than report an empty result it
  cannot back up — see [§6](#partial-data).
- **Reading one surface only.** The target lives in *Recommended*; the reason it is what it is lives
  in the `↳` rows (`--full`), in `info`'s *Policy Compliance* block, or in the agent payload's
  `reasons` array. The default console view is deliberately narrow.
- **Assuming the headline covers the package.** `next_action` is one label chosen by priority. A
  package can be simultaneously CVE-affected, deprecated and three majors behind, and print only
  `Check for the Fix`.

(engines)=
## 4. Engine constraints

An "engine" is the runtime a release declares it needs: `engines.node` on npm, `requires-python` on
PyPI. A release that cannot run on your runtime is not a candidate, however new it is.

### Which runtime gets checked

| Source | Used when | Value |
|---|---|---|
| `detected` | a runtime probe succeeded | the actual interpreter — the project's virtualenv Python, or `node --version` **and `npm --version`** from `PATH` |
| `declared` | no probe (or `--no-probe-runtime`) | the **lowest** version the project's own manifest claims to support, per engine key |
| `none` | neither available | no engine checking happens at all |

Probes are gated by registry: a pure-PyPI scan never spawns `node --version`.

Both sides carry `npm` as well as `node`, so a release declaring `engines.npm` is checked against
the npm you actually have — the two share one semver grammar and one matcher. `pnpm` and `yarn`
are deliberately **not** evaluated: OSS IQ has no adapter for either, so nothing probes them, and
a floor checked on the declared path but not the detected one would be worse than no check at all.
They pass through as satisfied like any other engine key OSS IQ cannot evaluate. The npm probe
never selects `detected` on its own: an npm-only context would discard the project's declared node
floor, which on a failed Node probe is the only thing left to check against.

### One definition, three consumers

`engine_mismatch_reason` is the single engine check. The solver's ranking clauses, the record's
`engine_compatible` flag, and the candidate gate in the strategy pipeline all derive from it, so a
candidate the gate rejects can never disagree with the verdict written onto the record. The reason
string it returns is the one you read:

```
↳ requires node >=22.0.0, detected 18.0.0 (detected)
```

### `engine_compatible` is tri-state

`False` = a conflict was found. `True` = checked and clear. `None` = **the question was never
answerable** — the release declares no requirement, or there was no runtime to check against.
`None` never means compatible.

### The escape hatch

If the engine gate would reject *every* installable release, OSS IQ drops the gate for that pass
rather than blanking the recommendation — the same rule it applies when every reachable version
carries a CVE. You get the newest version, with `engine_compatible: false` on the record and a red
`↳` row naming the mismatch. **A recommendation can be incompatible with your runtime and still be
the best available answer**; OSS IQ's obligation is to say so, not to hide it.

### What engine handling risks

| Risk | Detail |
|---|---|
| **The probed runtime may not be the deployed one** | On npm, the detected Node is whatever is on the `PATH` of the shell running `ossiq` — a developer laptop, not CI or production. Recommendations are gated against that. |
| **The declared floor is a floor, not your runtime** | Without a probe, checks run against the *lowest* version the manifest supports. A package requiring `node >=22` is reported incompatible for a project declaring `>=18`, even if every real deployment runs 24. |
| **The check fails open** | An engine key nothing can evaluate (`bun`, say) and an unparseable range both return "satisfied". A malformed `engines` field reads as compatible, not as unknown. |
| **An engine absent from the context is never checked** | The check iterates the runtime versions it has, not the requirements a release declares. A `pnpm` requirement on a project that declares no `pnpm` floor is passed over in silence, exactly as an `npm` requirement was everywhere before it was probed. |
| **`None` is easy to misread** | An absent requirement and a verified pass are different states and look similar in JSON. |

(the-cycle)=
## 5. The cycle: `status` → `plan` → `apply`

| Command | Reads | Writes | Prompts |
|---|---|---|---|
| `status` | full scan | nothing | — |
| `plan` | full scan + update plan | nothing | — |
| `apply` | full scan + update plan | manifest + lockfile, via the native package manager | two |

`plan` and `apply` run the *same* code path: `apply` is `plan` plus confirmation plus execution. The
plan you are shown by `apply` is the plan `apply` executes — it is computed in the same process,
milliseconds earlier.

### Why `apply` re-scans instead of consuming a saved plan

There is no plan file. `apply` performs its own scan and builds its own plan. This costs a second
scan when you run `plan` first, and buys three things:

1. **No stale plan.** A plan saved an hour ago describes a registry that has moved and a tree that
   may have been changed by a teammate. There is no window between deciding and writing.
2. **No new format to trust.** A serialized plan would be a file the tool has to re-validate, and a
   file an attacker could hand you.
3. **CLI and MCP stay equals.** Both front doors call the same service function; neither holds a
   decision the other would get wrong.

### How the write actually happens

Per ecosystem, in this order:

1. **Read and parse the manifest first.** An unparseable `package.json`/`pyproject.toml` fails the
   whole update loudly, before anything is rewritten, rather than degrading package by package.
2. **Rewrite direct specifiers** in the manifest text. `--pin-all` writes exact `==`/exact pins.
3. **Persist transitive picks as overrides** — npm `overrides`, uv `[tool.uv] override-dependencies`
   — and record what was written under an `ossiq:metadata` key. On the next run, an override whose
   value no longer matches what OSS IQ last wrote is left alone: you have taken ownership of it, and
   it is never silently overwritten.
4. **Hand resolution to the native package manager** — `npm install --ignore-scripts`, or
   `uv lock --upgrade-package … && uv sync`. OSS IQ does not resolve trees itself, and
   `--ignore-scripts` keeps install-time code out of the update path.
5. **On failure, restore the original manifest text** and raise.

### The two prompts

```
Proceed with 7 updates? [y/N]
```

then, only if something needs it:

```
The following updates need explicit acknowledgement - they widen the declared version
constraint (authorized by --update-strategy latest), or carry a known API/module-system break:
  requests  ~=2.31.0 -> 2.34.2  [direct]  (widens ~=2.31.0)
```

The second prompt exists because two different things deserve a separate "yes": **rewriting a
constraint someone chose deliberately**, and **taking a version whose major line is a known API or
module-system break**. The second case used to pass silently whenever the break happened to sit
*inside* the declared range — `uuid@>11.0.0` admits ESM-only `14.0.2` — so nothing asked. Both are
now named per entry. `--yes` skips both prompts.

### Convergence

Updates are resolved in a single pass against the *current* lockfile. Applying them re-resolves the
tree, which can surface further recommendations, so `apply` closes by telling you to re-run `plan`.
Most projects converge in one or two passes.

### What the cycle risks

| Risk | Detail | What to do |
|---|---|---|
| **Rollback restores the manifest, not the world** | If the package manager fails mid-run, the manifest is restored — the lockfile, `node_modules` and the virtualenv are whatever the failed command left behind. | Run `apply` on a clean working tree, under version control |
| **`--yes` authorizes constraint rewriting** | In CI at `latest`/`cutting-edge`, `--yes` skips the acknowledgement prompt, so declared ranges are rewritten with no second check. | Pin CI runs to `standard`, or review the `plan` output as a gate |
| **`--override` is unverified by construction** | It bypasses the solver, the cooldown, the widening hold and the prompt. Parent-constraint compatibility is not checked. | Treat forced versions as manual changes; test them |
| **One pass is not convergence** | The plan describes the tree as it is now, not as it will be after the write. | Re-run `plan` after every `apply` |
| **Transitive picks persist** | They are written as overrides and stay until removed, and show up as `ConstraintType.OVERRIDE` on later scans. | Expect them in review; remove them when upstream catches up |

(partial-data)=
## 6. Partial data

**A scan step reaching completion is not the same as it succeeding.** OSS IQ depends on four
external sources — the package registry, GitHub, OSV and EPSS — and any of them can be firewalled,
rate-limited or simply down. A report built on missing data must never be indistinguishable from a
clean one.

### What is tracked

Every fetch returns its outcome as a value alongside its data:

| Status | Meaning |
|---|---|
| `ok` | the source delivered |
| `partial` | some chunks failed; the rest of the data is real |
| `unreachable` | nothing came back — connection, timeout or HTTP failure |
| `rate_limited` | the source's quota was exhausted mid-scan |

Three of the seven scan steps report one:

| Step | Reports status? | Why |
|---|---|---|
| `repositories` (GitHub) | ✅ | four fetches — repo info, commits, activity, READMEs — combined into one status |
| `vulnerabilities` (OSV) | ✅ | one batch |
| `epss` (api.first.org) | ✅ | one batch |
| `packages`, `versions` | ❌ | per-package cached registry reads, not one batch run — deferred deliberately |
| `project`, `solver` | ❌ | no external data source; a status would be a category error |

```{note}
Two different combination rules, on purpose. Merging the fetches that make up **one source** treats
a mix of success and failure as `partial` — one failed GitHub stream out of four does not mean
GitHub was unreachable. Merging across **all sources** into the report-level verdict is a plain
worst-of — one failed source taints the whole report.
```

### What breaks when each source degrades

This is the part that matters, because degradation does not produce errors. It produces *quieter*
output:

| Degraded | Direct effect | The recommendation you get |
|---|---|---|
| **OSV** (`vulnerabilities`) | no CVEs on any record | `--update-strategy security` would find no `exploitable_cve` motive anywhere and print *"No packages need updates under --update-strategy security — nothing to do."*, identical to a clean project — so it **refuses to answer instead**, unless `--allow-partial`. `Check for the Fix` never fires. Triage cannot reach `patch` or `evict`. |
| **EPSS** | CVEs present, all unscored | The strategy treats unscored as exploitable and moves **more** packages than usual; triage sees no scores, finds no exploit signal, and falls back to `retain`/`refactor`. The two disagree — correctly. |
| **GitHub** (`repositories`) | no maintenance state, no stability, weaker deprecation evidence | No `end_of_life` motive unless a registry marker exists, so `--update-strategy deprecation` under-reports. `Find alternative` / `Consider alternative` never fire. Triage cannot reach `refactor` or `evict`. |
| **Registry** (`packages`, `versions`) | **not tracked** | A thin or failed registry read degrades the ladder itself, with no status to show for it. |

### Where degradation is visible

| Surface | Shown as | Present? |
|---|---|---|
| Console stepper | per-step icon and suffix — `⚠ … (partial — some data missing)`, `✗ … (unreachable — no data)`, `✗ … (rate limited — no data)`. A degraded step never draws the green `✓` | ✅ |
| Console, after the scan | a stderr warning block: *"Some data sources did not fully respond, so this report may be based on incomplete data"*, listing each degraded step. Emitted on every path — including `--verbose` and a missing Rich, which skip the stepper but not the warning, and a scan that raises partway | ✅ |
| `--format agent`, MCP | `data_completeness: {overall, sources[]}` inside the payload | ✅ |
| `export` | `metadata.data_completeness` | ✅ |
| HTML report | an **Incomplete data** banner above the table, naming each degraded source and carrying `metadata.warnings` | ✅ |
| Exit code | non-zero (MCP: a titled error) when `--update-strategy security`/`deprecation` ran without vulnerability data. Every other tier still exits 0 | ✅ opt out with `--allow-partial` |

```{note}
Every surface now says so, but they do not say it equally well. Machine-readable output
(`--format agent`, MCP, `export`) carries the degradation *inside* the document, where a consumer
cannot process the result without also being handed the caveat. The console warning and the HTML
banner sit beside the result and can be scrolled past. If you are automating on top of OSS IQ,
read `data_completeness` rather than trusting that someone saw the banner.
```

### The governing rule

> **Unknown is not zero.**

Both pipelines follow it, in opposite directions, and both are correct:

- **Triage is conservative about accusing.** A package whose repository could not be measured is
  never marked for refactoring. Unknown is not unstable.
- **The strategy is conservative about writing.** A CVE with no EPSS score counts as exploitable.
  Absent evidence must not silently read as absent risk when the output is a change to your
  manifest.

The difference is the consequence of being wrong. Triage produces advice a human reads; the strategy
produces a version a tool writes.

---

## Reading any recommendation in four questions

1. **Why did it move?** → `motives`, or the `↳` reason rows.
2. **How far did it reach, and from which rung?** → `recommended_from_rung`;
   `in_major`/`latest` means the declared range has to be rewritten first.
3. **Will `apply` actually write it?** → not if it is under *Requires constraint widening* or
   *Held for cooldown*.
4. **Was the evidence actually there?** → `data_completeness`. An empty result and an
   unreachable source look identical in the headline, and only here.
