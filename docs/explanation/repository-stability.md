# Repository Stability

OSS IQ runs two risk pipelines and never combines them into one number.

| Pipeline | Metric | Question it answers | Action it drives |
|---|---|---|---|
| Tactical | EPSS | Is a known CVE being exploited right now? | Patch or bump |
| Strategic | Maintenance state | Will this project still be maintained? | Refactor or replace |

## Why they stay separate

EPSS is scoped to published CVE identifiers. A package with no filed CVEs has an *undefined*
EPSS, not a zero — treating an unvetted or abandoned package as safe because nobody filed an
advisory is the single most common way a dependency scanner misleads you. The two also mix
units: EPSS is an exploit probability over a 30-day window, maintenance state is a statement
about upstream capacity. OSS IQ reports both and joins them only at the point of deciding what
to do — the [triage matrix](#the-triage-matrix).

## The maintenance-state model

`risk/maintenance.py` computes one naive-Bayes posterior over four states, ordered healthiest
to least:

`maintained` → `winding_down` → `abandoned` → `deprecated`

```
P(S | obs) ∝ P(S) · ∏ₖ P(obsₖ | S)
```

`PRIORS` and the `LIKELIHOOD` tables are hand-tunable constants, fit from the 62-repo, 4-state
corpus in `qa/calibrate_stability.py`. Four observations feed the model, each dropped when it
can't be measured:

| Observation | Values | Source |
|---|---|---|
| `deprecation_strength` | none / weak / strong | [deprecation evidence](#deprecation-evidence) |
| `has_stopped` | true / false | [commit-gap estimator](#the-commit-gap-estimator) — validated |
| `push_age` | fresh (<30d) / recent (<90d) / aging (<365d) / stale (<730d) / ancient | `days_since_push` |
| `flow_trend` | improving / stable / declining | [engagement-flow channel](#the-engagement-flow-channel) |

Two independence gates stop the correlated commit signals from double-counting:

- **`deprecation_strength == strong`** (archived, registry-deprecated, or PyPI
  `Development Status :: 7 - Inactive`) drops every other observation — an archived repo with
  fresh CI commits is still deprecated.
- **`push_age == fresh`** drops `flow_trend` — a repo pushed in the last 30 days is active
  whatever its issue backlog does; mature-library flow decline is release-driven, not decay.

The model reports **`P(abandoned) + P(deprecated)`** as the "not maintained" risk. At or above
`MAINTENANCE_THRESHOLD` (0.5) triage marks the package unstable. `stability_csi` is
`1 − P(not maintained)`, the probability the repository is maintained; `stability_coverage` is
the fraction of the four observations that were available. Both are `null` when nothing could be
observed.

## The commit-gap estimator

Drives `has_stopped`, the model's dominant abandonment signal, and is independently validated.

The channel samples the **last 100 commits** — fixed event count, random elapsed time — and
measures the **inter-commit gap**. Inter-arrival times of a memoryless process are Exponential
with `CV = 1` at any rate, so `gap_cv` is volume-free by construction: a busy repository and a
quiet one with the same commit rhythm score alike. Read it as `> 1` bursty, `≈ 1` memoryless,
`< 1` more regular than chance.

`gap_cv` is a **displayed diagnostic, not a model input** — it is confounded by release cadence:
a low-churn library committing in bursts around releases looks identical to a decaying one.

### The dormancy test

```
silence_days = now − most-recent sampled commit
silence_p    = fraction of this repo's own historical gaps longer than silence_days
has_stopped  = silence_p < 0.05  and  silence_days ≥ 90
```

Both halves are load-bearing. The p-value clears calm-but-alive repos — a package whose typical
gap is 60 days sitting silent for 90 is unremarkable *for it*. The 90-day floor clears both a
hyperactive repo's long weekend and a low-churn library's ordinary one-to-two-month lull.

`benjaminp/six` shows why the comparison is self-referential: it has been silent ~184 days, but
`six`'s own history has gone quiet that long often enough (`silence_p ≈ 0.06`) that the silence
isn't unusual *for six*. A fixed calendar window would flag it; measuring each repository against
its own gap history keeps a finished-but-fine library apart from a genuinely dead one.

### Sampling

`GET /repos/{owner}/{repo}/commits?per_page=100` — one page, one request, newest-first. Bot
commits (`dependabot[bot]`, `renovate`, `pre-commit-ci`, `github-actions`, any `*[bot]`) are
filtered before gaps are computed — a weekly dependabot commit otherwise gives a dead repo a
perfectly regular distribution. Timestamps use `commit.committer.date`; author dates survive
rebase and are occasionally in the future.

Runs for **direct dependencies only** — there is no independent lever to act on a transitive
package you didn't choose to depend on. Cached 7 days (`--stability-cache-ttl`, default 168h).

## The engagement-flow channel

Supplies `flow_trend`. Issues and PRs aren't in git, so this is a batched GraphQL job — one
`POST /graphql` per repo per stream (issues and PRs are separate requests), run at low
concurrency to stay under GitHub's CPU-time secondary rate limit.

It tracks issue and PR **flow over time**:

- A **180-day window**, six ~30-day buckets.
- Per bucket, `opened` and `closed`, where `closed` counts items closed *in* that bucket
  regardless of when they opened — so slow items that outlive the window still count.
- `flow_ratio = closed / max(opened, 1)` — `> 1` draining backlog, `≈ 1` keeping pace, `→ 0`
  falling behind.
- `flow_trend` is the OLS slope direction of `flow_ratio` across the buckets (`improving` /
  `stable` / `declining`), forced to `declining` when the last two buckets average under 60% of
  the earlier median. `null` below three measured buckets.

Like `has_stopped`, it measures a repository against its own recent history: a project that
always closed 30% of its issues and still does is stable; one that closed 90% and now closes 10%
is not.

GraphQL needs a token, so this channel **defaults on when `OSSIQ_GITHUB_TOKEN` is set, off
otherwise**; force it with `--stability-responsiveness` / `--no-stability-responsiveness`. Direct
dependencies only, cached 7 days. Raw buckets are persisted in the JSON export for offline
recalibration.

## Deprecation evidence

`deprecation_evidence` reduces eight markers — collected alongside the existing metadata fetch,
no extra request — to a strength tier:

| Signal | Source |
|---|---|
| `archived` | GitHub `archived: true` |
| `registry_deprecated` | npm `deprecated` field set, or every PyPI release yanked |
| `inactive_classifier` | PyPI trove `Development Status :: 7 - Inactive` |
| `topic_tagged` | GitHub topic `deprecated` / `unmaintained` / `abandoned` / `obsolete` / `eol` |
| `description_marked` | deprecation phrase in the repo description or registry summary |
| `readme_marked` | deprecation banner in the first screenful of the README |
| `pinned_notice` | a pinned issue titled like a migration / end-of-life notice |
| `successor_named` | a replacement package named in metadata, a deprecation message, or the README |

`strong` = any one of the first three, or two-plus signals of any kind. `weak` = exactly one
soft signal. A `strong` marker is near-deterministic and, per the gate above, is then the only
observation the model sees.

## Unknown is not zero

| Situation | `maintenance_state` | Meaning |
|---|---|---|
| No repository, non-GitHub host, no commit sampled, and no deprecation marker | `null` | Nothing to assess |
| At least one observation available | a state | Assessed on what was measured |

A package that could not be assessed is never marked for refactoring — it keeps its
exploit-driven action, so it can reach `patch` but never `evict` or `refactor`. `prefetch` only
resolves `github.com` URLs, so GitLab, Codeberg and packages with no declared repository stay
unknown.

## The triage matrix

| Exploit signal | Repository | Action | Why |
|---|---|---|---|
| EPSS ≥ 0.10 | not maintained | `evict` | Exploited, and no upstream fix is coming. Replace it. |
| EPSS ≥ 0.10 | maintained | `patch` | Exploited, but a fix can ship. Bump it. |
| below 0.10 | not maintained | `refactor` | No exploit pressure, but real maintenance debt. Schedule it. |
| otherwise | | `retain` | Baseline healthy state. |

"Not maintained" is `P(abandoned) + P(deprecated) ≥ 0.5` from the model, not a raw calendar
rule. CVEs scoring below **0.005** — a 0.5% chance of exploitation — don't count toward the
exploit signal; they're reported as `suppressed_cves` rather than dropped, so the noise
reduction is visible.

The action is **advisory**. It appears in `status`, `info`, the JSON and CSV exports, the HTML
report and the agent/MCP verdict, but it does not change the `ok`/`warn`/`block` verdict that
gates a build.

## Reading the output

`status` reports counts, never one score — maintenance doesn't compose across a dependency tree:

```
Unmaintained deps: 3 (1 deprecated) of 18 assessed  |  Unassessed: 4
```

`info <package>` shows the full decomposition: `Gap CV` and its commit span, `silence` and its
p-value, the `engagement` flow trend, `Last pushed`, any `Deprecation` signals, the
`Maintenance` state with its risk and the observations behind it, and the resulting triage
action.

The `--schema-version=1.5` export and the CSV carry `maintenance_state`, `stability_csi`
(`= 1 − stability_risk`), `stability_risk`, `stability_coverage`, `gap_cv`, `median_gap_days`,
`silence_days`, `silence_p`, `commits_sampled`, `span_days`, `flow_trend`, `deprecation_signals`,
`deprecation_successor`, `days_since_push`, `archived` and `triage_action`, plus the raw
engagement buckets. Any field is `null` when it couldn't be measured — that means "unknown,"
never "no risk."

Switch the whole channel off with `--no-stability` (`OSSIQ_STABILITY=false`); switch just the
GraphQL flow channel off with `--no-stability-responsiveness` — already off by default on
unauthenticated scans, where GitHub allows 60 requests an hour.

## Calibration

`qa/calibrate_stability.py` (`just calibrate-stability`, needs `OSSIQ_GITHUB_TOKEN`) runs the
real scan path against the 62-repo hand-labelled 4-state corpus. Three gap checks gate the exit
code and are passing:

1. `gap_cv` decoupled from commit volume — `|Pearson r| < 0.5` across the `maintained` set.
2. Every `abandoned` repo flagged `has_stopped`; `benjaminp/six` not flagged.
3. No repo with a commit inside 30 days flagged.

The model itself is reported as a confusion matrix, multiclass Brier score and reliability curve
over the four states — **informational until the `LIKELIHOOD` tables are tuned** against the
corpus, then promoted to a hard check (diagonal accuracy ≥ 70%, Brier ≤ 0.20). The tuning
procedure is in `qa/manual/stability-calibrate.md`.
