(recommendations)=
# Every recommendation OSS IQ can make

Part of [Recommendations and Risk](../recommendations.md).

Five distinct kinds of output tell you to do something. They are computed by different modules
against different evidence, and they are *not* rankings of each other.

## The target — `recommended_version` + `recommended_from_rung`

The version to move to, and which rung of the [version ladder](../reference.md#version-ladder) it
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
*Requires constraint widening* unless the run's tier reaches that far or a CVE or end-of-life motive carried the pick past it (`widening_authorized`). `status` and the agent
payload still show them — with `requires_constraint_widening: true` — because knowing a newer
version exists is useful even when taking it needs a human decision.

## `next_action` — the one-line headline

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

## `dependency_health` (triage) — the operational verdict

From the EPSS × maintenance matrix (see [Repository stability](../explanation/repository-stability.md#the-triage-matrix)):
`retain`, `patch`, `refactor`, `evict`. **Advisory only** — it appears on every surface but changes
no recommendation and gates no build. The agent payload and MCP tools name it `dependency_health`,
and the JSON export `dependency_health_action`. It answers "is this dependency healthy long-term?";
`next_action` answers "what do I do now?".

## The add decision — `install` / `install with caution` / `do not install`

Produced by `ossiq add` and the `ossiq_evaluate_dependency` MCP tool, for a package not yet in the
tree. `do not install` on critical health warnings; `--force` overrides.

## The non-recommendations

These carry as much decision-making weight as the targets, and are easier to skim past:

| Output | Means | Where |
|---|---|---|
| `withheld_reason` | no motive admitted at this tier; names the lowest tier that would move it | `plan` footer, the `status --full` `↳` row under `Withheld by strategy`, agent `strategy_withheld_reason`, export `strategy` |
| *Held for cooldown* | target is younger than `--cooldown-period` (default 7 days). CVE-carrying packages are exempt | `plan` section |
| *Requires constraint widening* | target sits outside the declared range and neither the tier nor an escalating motive authorizes rewriting it | `plan` section, export `requires_constraint_widening` |
| `rejected_candidates` | a newer release was found and held back — by a transitive conflict, a peer dependency range, a known module-system break, or an engine mismatch — one per rung, with the reason. On npm a transitive conflict means an `overrides` rule: a dependent whose range cannot share the installed copy simply gets its own | `status --full` `↳` rows, export, agent `reasons` |
| *Held by overrides you wrote* | an `overrides` rule of yours kept a release or a transitive update out of the plan. OSS IQ never rewrites a rule it did not write | `plan` and `apply` section |
| *Held by peer dependencies* | a newer release exists, but an installed package's `peerDependencies` range rules it out (`typescript` 7.0.2, held by `@typescript-eslint/*` peer-requiring `<6.1.0`), or the release's own peers cannot be met. One line per package: the newest refused release, the first requirer and how many more. Held to the *declared* range even where an `overrides` entry would let npm install past it | `plan` section, `status --full` `↳` rows, `info` |
| *Repairs unresolved peers* | a peer is installed only where its requirer cannot load it, and `apply` fixes that: it adds the peer to the manifest at the range shown and moves the stale copies of its family with it. See *Unresolved peers* in [Reference → Console Reports](../reference.md#console-reports) | `plan` section, `apply`, export and agent `peer_repairs` |
| `unresolved_peers` | the peers a package declares that nothing within its reach satisfies | `status` (every mode), `info`, export, agent |
| `constraint_conflict` | no version satisfies all constraints (`[NO RESOLUTION]`) | `status`, `info` |
| `escalation` | reach was pushed past the tier's base, or every reachable version still carries a CVE | export `strategy`, agent |
| `widening_authorized` | a CVE or end-of-life motive carried the pick past the tier's base reach, so `plan` lists it as an update and `apply` confirms the widening instead of holding it | export `strategy`, agent |
| *New transitive dependency* `⚠` | a package entering the tree for the first time, younger than the cooldown. Resolved by the native package manager, so the cooldown hold cannot apply to it | `plan` section |

A blank *Recommended* cell with no accompanying `↳` row means OSS IQ found nothing newer. A blank
cell **with** a `↳` row means it found something and refused it, and the row says why. The
commonest case: a CommonJS project already at the top of its CommonJS line, whose only newer
releases are ESM-only (`↳ 6.0.0 rejected: ESM-only from 6.0.0`). See
[The module-system line](update-pyramid.md#the-module-system-line).

## What the recommendation catalogue risks

- **Mistaking advice for a gate.** `dependency_health_action` and `next_action` change no exit code. `ossiq
  status` exits 0 on a project full of `evict` verdicts. Any CI gate is yours to write, over the
  JSON export. The single exception is not a gate but a refusal: a `security`/`deprecation` run
  whose vulnerability data never arrived exits non-zero rather than report an empty result it
  cannot back up — see [Partial data](partial-data.md).
- **Reading one surface only.** The target lives in *Recommended*; the reason it is what it is lives
  in the `↳` rows (`--full`), in `info`'s *Policy Compliance* block, or in the agent payload's
  `reasons` array. The default console view is deliberately narrow.
- **Assuming the headline covers the package.** `next_action` is one label chosen by priority. A
  package can be simultaneously CVE-affected, deprecated and three majors behind, and print only
  `Check for the Fix`.
