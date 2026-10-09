(partial-data)=
# Partial data

Part of [Recommendations and Risk](../recommendations.md).

**A scan step reaching completion is not the same as it succeeding.** OSS IQ depends on four
external sources — the package registry, GitHub, OSV and EPSS — and any of them can be firewalled,
rate-limited or simply down. A report built on missing data must never be indistinguishable from a
clean one.

## What is tracked

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

## What breaks when each source degrades

This is the part that matters, because degradation does not produce errors. It produces *quieter*
output:

| Degraded | Direct effect | The recommendation you get |
|---|---|---|
| **OSV** (`vulnerabilities`) | no CVEs on any record | `--update-strategy security` would find no `exploitable_cve` motive anywhere and print *"No packages need updates under --update-strategy security — nothing to do."*, identical to a clean project — so it **refuses to answer instead**, unless `--allow-partial`. `Check for the Fix` never fires. Triage cannot reach `patch` or `evict`. |
| **EPSS** | CVEs present, all unscored | The strategy treats unscored as exploitable and moves **more** packages than usual; triage sees no scores, finds no exploit signal, and falls back to `retain`/`refactor`. The two disagree — correctly. |
| **GitHub** (`repositories`) | no maintenance state, no stability, weaker deprecation evidence | No `end_of_life` motive unless a registry marker exists, so `--update-strategy deprecation` under-reports. `Find alternative` / `Consider alternative` never fire. Triage cannot reach `refactor` or `evict`. |
| **Registry** (`packages`, `versions`) | **not tracked** | A thin or failed registry read degrades the ladder itself, with no status to show for it. |

## Where degradation is visible

| Surface | Shown as | Present? |
|---|---|---|
| Console stepper | per-step icon and suffix — `⚠ … (partial — some data missing)`, `✗ … (unreachable — no data)`, `✗ … (rate limited — no data)`. A degraded step never draws the green `✓` | ✅ |
| Console, after the scan | a stderr warning block: *"Some data sources did not fully respond, so this report may be based on incomplete data"*, listing each degraded step **and what caused it** — `partial — 3 not found (renamed, deleted or private)` — plus the API quota the scan ended on. Emitted on every path — including `--verbose` and a missing Rich, which skip the stepper but not the warning, and a scan that raises partway | ✅ |
| Console, before the scan | a stderr warning when GitHub's remaining quota does not cover what the scan is about to need: `core: 12/5000 left, this scan needs ~90, resets in 43m`. On an unauthenticated scan it adds how to raise the limit: set `OSSIQ_GITHUB_TOKEN` (the only option in CI and containers), or run `ossiq auth login` where a system keyring is available. The check itself is free and never cached | ✅ |
| `--format agent`, MCP | `data_completeness: {overall, sources[], api_budgets[]}` inside the payload; each degraded source carries `failures: [{reason, count}]` | ✅ |
| `export` | `metadata.data_completeness`, including per-source `failures[]` and `api_budgets[]` | ✅ |
| HTML report | an **Incomplete data** banner above the table, naming each degraded source and carrying `metadata.warnings` | ✅ |
| Exit code | non-zero (MCP: a titled error) when `--update-strategy security`/`deprecation` ran without vulnerability data. Every other tier still exits 0 | ✅ opt out with `--allow-partial` |

```{note}
Every surface now says so, but they do not say it equally well. Machine-readable output
(`--format agent`, MCP, `export`) carries the degradation *inside* the document, where a consumer
cannot process the result without also being handed the caveat. The console warning and the HTML
banner sit beside the result and can be scrolled past. If you are automating on top of OSS IQ,
read `data_completeness` rather than trusting that someone saw the banner.
```

## The governing rule

> **Unknown is not zero.**

Both pipelines follow it, in opposite directions, and both are correct:

- **Triage is conservative about accusing.** A package whose repository could not be measured is
  never marked for refactoring. Unknown is not unstable.
- **The strategy is conservative about writing.** A CVE with no EPSS score counts as exploitable.
  Absent evidence must not silently read as absent risk when the output is a change to your
  manifest.

The difference is the consequence of being wrong. Triage produces advice a human reads; the strategy
produces a version a tool writes.
