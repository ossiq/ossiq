# Update Strategy — the dependency update pyramid

Pure decision module that answers one question per package: *given the evidence OSS IQ has
gathered, which version should be recommended, and why?* It sits where `risk/` sits — it computes
a verdict from facts, and never touches the registry, the solver, or a `ScanRecord` directly.

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

Each tier is a strict superset of the one below it: every motive the lower tier admits, the higher
tier admits too, and it can reach at least as far up the version ladder. `security` proposes the
smallest possible diff that clears exploitable CVEs; `cutting-edge` proposes whatever is newest,
prereleases included.

---

## Module map

```
strategy/
├── pyramid.py       UpdateStrategy + the two tables (ADMITTED_MOTIVES, MAX_REACH) that define the pyramid,
│                    plus the tier sets (MINIMAL_DIFF_TIERS, PRERELEASE_TIERS, MODULE_BREAK_TIERS)
├── motive.py        UpdateMotive + PackageFacts + classify_motives() — why a package may move
├── targeting.py      Candidate, StrategySelection, select_target() — the selector itself
├── compare.py        compare_target() — judges a caller's chosen target against the recommendation
└── overrides.py      StrategyPlan + parse_strategy / parse_overrides — per-run, per-package tiers
```

---

## The two axes

A strategy is not one dial, it is two, kept separate on purpose:

- **Motive** — *why* a package is allowed to move: an exploitable CVE, an end-of-life marker, or
  plain drift.
- **Reach** — *how far up the ladder* it may go on that motive: inside the declared range, inside
  the installed major line, or anywhere.

### `ADMITTED_MOTIVES`

| Tier | exploitable_cve | end_of_life | drift |
|---|:---:|:---:|:---:|
| `security` | ✓ | | |
| `deprecation` | ✓ | ✓ | |
| `standard` | ✓ | ✓ | ✓ |
| `latest` | ✓ | ✓ | ✓ |
| `cutting-edge` | ✓ | ✓ | ✓ |

### `MAX_REACH`

| Tier | Base reach | Escalates to `LATEST` when... |
|---|---|---|
| `security` | in-range | an admitted motive is `exploitable_cve` (no in-range version clears the CVE) |
| `deprecation` | in-range | an admitted motive is `exploitable_cve` or `end_of_life` |
| `standard` | in-range | same as above |
| `latest` | latest | already maximal |
| `cutting-edge` | latest | already maximal, plus prereleases admitted |

### Worked example

`pydantic==1.10.13` pinned exactly, no CVE, no maintenance signal; `requests==2.28.1`, CVEs affect
`2.28.1…2.31.0`, releases run through `2.34.2`:

| Tier | `pydantic` | `requests` |
|---|---|---|
| `security` | no target (no CVE) | `2.32.0` — nearest CVE-clear version |
| `deprecation` | no target | `2.32.0` |
| `standard` | `1.10.13` — pin admits no in-range move | `2.34.2` — newest, already CVE-clear |
| `latest` | `2.13.5` — widens the pin, `requires_widening=True` | `2.34.2` |
| `cutting-edge` | `2.13.5` (or newer, if a prerelease exists) | `2.34.2` |

---

## Interacting with OSS IQ

| Flag / field | Meaning |
|---|---|
| `--update-strategy <tier>` | The default tier for the run. Default: `standard` — preserves pre-fix behaviour. |
| `--strategy-override pkg=tier` | Run one package at a different tier than the run default. Repeatable. |
| `--override pkg==version` | Force an exact version, bypassing the strategy and the solver entirely. Wins over a `--strategy-override` on the same package. |
| `--allow-prerelease` / `cutting-edge` | Prereleases are not a sixth rung — `cutting-edge` is `latest` plus `allow_prerelease=True`, applied at prefetch so prereleases flow into the ladder through the existing path. |
| `--security` (retired) | Removed, not aliased — this is pre-release software; use `--update-strategy security`. |
| MCP `update_strategy` / `strategy_overrides` arguments | Same semantics, over the wire, on both MCP tools. |
| Export `metadata.update_strategy`, `PackageMetrics.strategy_*` | The tier used for the run and the per-package verdict, in `ossiq export` / `ossiq html`. |
| Agent JSON `update_strategy`, per-entry `motives` / `withheld_reason` | Same verdict, in `--format agent` and both MCP tools. |

---

## Reading the output

- **`withheld_reason`** — set only when *no* motive was admitted at the chosen tier (e.g. a package
  with no CVE, under `security`). Names the lowest tier that would have moved it, so a project can
  report "N more updates available under `--update-strategy standard`".
- **`requires_widening`** — the target sits outside the declared constraint (`IN_MAJOR` / `LATEST`
  rung). `apply` confirms these in a separate prompt before writing them; `--yes` skips both
  prompts.
- **`escalation`** — set when reach was pushed past the tier's base `MAX_REACH` (a CVE or
  end-of-life motive escalated it), or when every reachable candidate still carries a qualifying
  CVE and the newest was picked anyway. Never silently "stay put".

---

## Key Implementation Decisions

**Why two tables rather than one dial?** Collapsing motive and reach into a single ordered list of
five tiers would make "why did this move" and "how far could it move" the same question, and they
aren't: an end-of-life package can need to leave its declared range even under the otherwise
minimal-diff `deprecation` tier. Keeping them as two tables makes each tier's behaviour a lookup,
not a special case.

**Why do unscored CVEs count as exploitable, when `risk.triage` drops them?** `triage` is advisory
— an operator reads its verdict and decides. This module gates *writes*: recommending a version
that still carries an unscored CVE is a decision made on behalf of the user, and absent evidence
must not silently read as absent risk.

**Why is `WINDING_DOWN` not end-of-life?** It already surfaces as "Consider alternative" in
`next_action`, which is the right severity — a maintainer who is slowing down has not stopped.
Escalating it to `end_of_life` would make `deprecation`/`security` tiers move packages whose
maintainers are still shipping fixes, defeating the "minimal diff" promise of the bottom two tiers.

**Why minimal-diff for the bottom two tiers, freshness for the top three?** `security` and
`deprecation` exist to answer "what must I patch today" — the smallest change that resolves the
motive. `standard` and above answer "what would I install today" — freshness is the point.
Conflating them would make a security patch also carry unrelated drift, which is exactly the kind
of unreviewable diff this module exists to prevent.

**Why no fourth `PRERELEASE` rung?** `RecommendationRung` and the version ladder are about *where*
on the ladder a version sits (in-range / in-major / latest), which is orthogonal to whether
prereleases are visible on that ladder at all. Modelling prerelease admission as `allow_prerelease`
at prefetch time — exactly like `--allow-prerelease` already works — means `cutting-edge` needs no
changes to `VersionLadder`, `RecommendationRung`, or the export schema.

**Why is `Candidate` pre-tagged rather than parsed here?** Keeping version parsing, constraint
matching and registry lookups entirely in `service.project.strategy.build_candidates` means this
module has zero registry coupling and is trivially property-testable: a `Candidate` list is just
data, and `select_target` is a pure function over it. A release's age rides along the same way, as
`Candidate.age_days`: the tag is a registry fact, the threshold (`cooldown_period`) is a parameter,
and the decision stays here.

**Why does the cooldown live in the selector rather than in `plan`/`apply`?** It used to live only
there, as `service.update.is_held_for_cooldown`. But `apply_update_strategy` runs last and rewrites
`recommended_version`, so `status` would recommend a two-day-old release with "Update Immediately"
while `apply` refused it — with a settled release sitting between the two, recommended by nobody.
Filtering fresh candidates out of the ladder here makes one decision serve every surface, which is
the whole point of rule 5 in the root `CLAUDE.md`. The downstream hold survives as a backstop for
transitive recommendations, which come from the solver's *soft* freshness penalty.

**Why may only `latest`/`cutting-edge` cross to ESM-only, and only on a `require(esm)` Node?**
For a CommonJS project an ESM-only release is a break whatever its version number:
`require()` of it fails outright below Node 20.19/22.12, and above that it returns the module
namespace, so a default-export-only package (chalk) still breaks. `MODULE_BREAK_TIERS` makes
crossing a freshness decision the top of the pyramid may take, flagged with `breaking_change` so
`apply` asks for it separately. Everything below stays on the installed module system. The
permission only grows with the tier, so rule 6 ("a higher tier's target is never lower") still
holds by construction. The gate itself (`service.project.strategy.module_system_gate`) is a
*strict* gate: `build_candidates` never waives it just because it empties the ladder, because a
drift-only package should stay put rather than cross. `apply_update_strategy` waives it in one
case, when an `exploitable_cve` or `end_of_life` motive has no clean candidate left without it.
It re-runs `select_target` over the full ladder and keeps that answer only if it resolves the
motive. The selector stays pure; the re-run is wiring.

**Why does `compare_target` never pick a version?** `recommended_version` has one writer. A
second target-picker for `update_context` would be a second answer to the same question, and the
two would drift. `compare_target` only turns facts about a proposed target into a verdict relative
to that one answer.

**Why `--strategy-override` and not `--override-strategy`?** `--override pkg==version` already
exists and means "force this exact version". `--override-strategy` reads as a variant of the same
flag and invites the wrong mental model; `--strategy-override` parses unambiguously as "an override
of the strategy" for one package.
