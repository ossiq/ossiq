# Repository Stability

**A dependency can fail two ways, so OSS IQ runs two pipelines and never averages them into one
score.**

| Pipeline | Metric | Question | Action |
|---|---|---|---|
| Tactical | EPSS | Is a known CVE being exploited right now? | Patch or bump |
| Strategic | Maintenance state | Will this project still be maintained? | Refactor or replace |

They meet in one place only: the [triage matrix](#the-triage-matrix), which turns the pair into a
single recommended action — `retain`, `patch`, `refactor` or `evict`.

## Why they stay separate

EPSS is scoped to published CVE identifiers. A package with no filed CVEs has an *undefined*
EPSS, not a zero. Treating an unvetted or abandoned package as safe because nobody filed an
advisory is the most common way a dependency scanner misleads you.

The units don't mix either: EPSS is an exploit probability over 30 days; maintenance state is a
statement about upstream capacity. Multiplying them would hide both.

## The maintenance-state model

[`risk/maintenance.py`](https://github.com/ossiq/ossiq/blob/main/src/ossiq/risk/maintenance.py)
computes one naive-Bayes posterior over four states, healthiest first:

`maintained` → `winding_down` → `abandoned` → `deprecated`

$$
P(S \mid o_1 \dots o_k) \;\propto\; P(S) \prod_{i=1}^{k} P(o_i \mid S)
$$

`PRIORS` and the `LIKELIHOOD` tables are hand-tunable constants, fit from the 63-repo, 4-state
corpus in `qa/calibrate_stability.py`. Four observations feed the model, each dropped when it
can't be measured:

| Observation | Values | Source |
|---|---|---|
| `deprecation_strength` | weak / strong | [deprecation evidence](#deprecation-evidence) |
| `has_stopped` | true / false | [commit-gap estimator](#the-commit-gap-estimator) — validated |
| `push_age` | fresh $<30$d / recent $<90$d / aging $<365$d / stale $<730$d / ancient | `days_since_push` |
| `flow_trend` | improving / stable / declining | [engagement-flow channel](#the-engagement-flow-channel) |

Finding *no* deprecation marker is not an observation: the strength only reaches the model once at
least one signal fires, so a repository nobody has flagged stays scored on its commit history
instead of being pushed toward `maintained` by the absence of a notice.

### Two independence gates

Naive Bayes assumes the observations are conditionally independent. The commit-derived ones
aren't, so two gates drop the correlated signal instead of double-counting it:

- **`deprecation_strength = strong`** (archived, registry-deprecated, or PyPI
  `Development Status :: 7 - Inactive`) drops every other observation. An archived repo with
  fresh CI commits is still deprecated.
- **`push_age = fresh`** drops `flow_trend`. A repo pushed in the last 30 days is active whatever
  its issue backlog does; in mature libraries flow decline is release-driven, not decay.

### What it reports

The "not maintained" risk is the mass on the bottom two states:

$$
P(\text{not maintained}) = P(\text{abandoned}) + P(\text{deprecated})
$$

At or above `MAINTENANCE_THRESHOLD` $= 0.5$, triage marks the package unstable.

$$
\texttt{maintenance_risk} = P(\text{not maintained})
\qquad
\texttt{maintenance_coverage} = \frac{\text{observations used}}{4}
$$

Coverage counts the observations that actually reached the model, so a `strong` deprecation
marker scores $0.25$ — the gate dropped the rest by design, not for lack of data. Both fields are
`null` when nothing could be observed.

## The commit-gap estimator

Drives `has_stopped`, the model's dominant abandonment signal, and the only channel that is
independently validated.

The channel samples the **last 100 commits** — a fixed event count over a random elapsed time —
and measures the gaps between them. For a memoryless process the inter-arrival times are
Exponential, whose coefficient of variation is $1$ at *any* rate, so

$$
\texttt{gap_cv} = \frac{\sigma(g)}{\bar{g}}, \qquad g_i = t_{i+1} - t_i
$$

is volume-free by construction: a busy repository and a quiet one with the same rhythm score
alike. Read $\texttt{gap_cv} > 1$ as bursty, $\approx 1$ as memoryless, $< 1$ as more regular
than chance. It is reported only from 20 gaps up, the same floor the dormancy test uses.

```{warning}
`gap_cv` is a **displayed diagnostic, not a model input.** Release cadence confounds it — a
low-churn library committing in bursts around releases looks identical to a decaying one.
```

### The dormancy test

Let $d$ be the days since the most recent sampled commit, over $n$ historical gaps $g_1 \dots g_n$:

$$
\texttt{silence_p} = \hat{S}(d) =
\begin{cases}
\dfrac{\left|\{\, i : g_i > d \,\}\right|}{n} & n \ge 20 \\[1.4em]
e^{-d / \bar{g}} & n < 20
\end{cases}
$$

$$
\texttt{has_stopped} \iff \texttt{silence_p} < 0.05 \;\wedge\; d \ge 90\ \text{days}
$$

The empirical tail is preferred because real gap distributions are overdispersed; the fitted
exponential is a fallback when there are too few gaps to resolve a percentile.

Both halves of the conjunction are load-bearing. The p-value clears calm-but-alive repos — a
package whose typical gap is 60 days sitting silent for 90 is unremarkable *for it*. The 90-day
floor clears both a hyperactive repo's long weekend and a low-churn library's ordinary
one-to-two-month lull.

`benjaminp/six` shows why the comparison must be self-referential. It has been silent ~184 days,
but `six`'s own history has gone quiet that long often enough ($\texttt{silence_p} \approx 0.06$)
that the silence isn't unusual *for six*. A fixed calendar window would flag it; measuring each
repository against its own gap history keeps a finished-but-fine library apart from a dead one.

### Sampling

`GET /repos/{owner}/{repo}/commits?per_page=100` — one page, one request, newest-first. Bot
commits (`dependabot[bot]`, `renovate`, `pre-commit-ci`, `github-actions`, any `*[bot]`) are
filtered before gaps are computed; a weekly dependabot commit otherwise gives a dead repo a
perfectly regular distribution. Timestamps use `commit.committer.date`, because author dates
survive rebase and are occasionally in the future.

Runs for **direct dependencies only** — there is no independent lever to act on a transitive
package you didn't choose. Cached 7 days (`--stability-cache-ttl`, default 168h).

The model itself is not direct-only. `push_age` and the registry-side deprecation markers come
from metadata every package in the tree already has, so a transitive still gets a state — just at
lower coverage, without the commit, engagement or README evidence.

## The engagement-flow channel

Supplies `flow_trend`. Issues and PRs aren't in git, so this is a batched GraphQL job: one
`POST /graphql` per repo per stream (issues and PRs are separate requests), at low concurrency to
stay under GitHub's CPU-time secondary rate limit.

It tracks issue and PR **flow** across a 180-day window in six ~30-day buckets. Both streams share
one ratio per bucket $b$:

$$
r_b = \frac{\text{issues closed}_b + \text{PRs merged}_b}{\max(\text{issues opened}_b + \text{PRs opened}_b,\, 1)}
$$

The numerator counts items finished *in* that bucket regardless of when they opened, so slow items
that outlive the window still count. Pull requests count as outflow only when **merged** — a PR
closed unmerged is a backlog item dropped, not work shipped. Read $r_b > 1$ as a draining backlog,
$\approx 1$ as keeping pace, $\to 0$ as falling behind.

`flow_trend` is the direction of the OLS slope $\hat{\beta}$ of $r_b$ against bucket index, with
one override for a sharp recent drop:

$$
\texttt{flow_trend} =
\begin{cases}
\texttt{declining} & \operatorname{mean}(r_{n-1}, r_n) < 0.6 \cdot \operatorname{median}(r_1 \dots r_{n-2}) \\
\texttt{declining} & \hat{\beta} \le -0.03 \\
\texttt{improving} & \hat{\beta} \ge +0.03 \\
\texttt{stable} & \text{otherwise}
\end{cases}
$$

The override exists because "outflow just stopped" is exactly the case a shallow slope hides.
Empty buckets are dropped from the fit but keep their index, so a run of quiet months spreads the
regression rather than collapsing it. `flow_trend` is `null` below three measured buckets.

Like `has_stopped`, this measures a repository against its own recent history: a project that
always closed 30% of its issues and still does is stable; one that closed 90% and now closes 10%
is not.

GraphQL needs a token, so the channel **defaults on when `OSSIQ_GITHUB_TOKEN` is set, off
otherwise**; force it with `--stability-responsiveness` / `--no-stability-responsiveness`. Direct
dependencies only, cached 7 days. The raw buckets are persisted in the JSON export as
`engagement_buckets` — one `[issues_opened, issues_closed, prs_opened, prs_merged]` row per
bucket, oldest first — so the trend can be re-fitted offline.

## Deprecation evidence

`deprecation_evidence` reduces eight markers to a strength tier. Most ride the metadata the scan
already fetches; two do not, and both are direct-dependency only: the README banner costs one
extra `GET .../readme` per repository (cached at the stability TTL), and the pinned-issue notice
arrives inside the GraphQL activity payload, so it is unavailable without a token.

| Signal | Source | Strong on its own |
|---|---|---|
| `archived` | GitHub `archived: true` | ✅ |
| `registry_deprecated` | npm `deprecated` field set, or every PyPI release yanked | ✅ |
| `inactive_classifier` | PyPI trove `Development Status :: 7 - Inactive` | ✅ |
| `topic_tagged` | GitHub topic `deprecated` / `unmaintained` / `abandoned` / `obsolete` / `eol` | |
| `description_marked` | deprecation phrase in the repo description or registry summary | |
| `readme_marked` | deprecation banner in the first screenful of the README (extra request) | |
| `pinned_notice` | a pinned issue titled like a migration / end-of-life notice (needs a token) | |
| `successor_named` | a replacement package named in metadata, a deprecation message, or the README | |

`strong` = any one hard marker, **or** any two signals. `weak` = exactly one soft signal.
A `strong` marker is near-deterministic and, per the gate above, becomes the only observation the
model sees.

## Unknown is not zero

| Situation | `maintenance_state` | Meaning |
|---|---|---|
| No GitHub repository record (non-GitHub host, none declared) and no deprecation marker | `null` | Nothing to assess |
| At least one observation available | a state | Assessed on what was measured |

A package that could not be assessed is **never** marked for refactoring. It keeps its
exploit-driven action, so it can reach `patch` but never `evict` or `refactor`. Prefetch only
resolves `github.com` URLs, so GitLab, Codeberg and packages with no declared repository stay
unknown.

## The triage matrix

| Exploit signal | Repository | Action | Why |
|---|---|---|---|
| EPSS $\ge 0.10$ | not maintained | `evict` | Exploited, and no upstream fix is coming. Replace it. |
| EPSS $\ge 0.10$ | maintained | `patch` | Exploited, but a fix can ship. Bump it. |
| EPSS $< 0.10$ | not maintained | `refactor` | No exploit pressure, but real maintenance debt. Schedule it. |
| otherwise | | `retain` | Baseline healthy state. |

"Not maintained" means $P(\text{abandoned}) + P(\text{deprecated}) \ge 0.5$ from the model, not a
raw calendar rule. CVEs scoring below $0.005$ — a 0.5% chance of exploitation — don't count
toward the exploit signal; they are reported as `suppressed_cves` rather than dropped, so the
noise reduction stays visible.

```{note}
The action is **advisory.** It appears in `status`, `info`, the JSON and CSV exports, the HTML
report and the agent/MCP verdict, but it does not change the `ok` / `warn` / `block` verdict that
gates a build.
```

## Reading the output

`status` reports counts, never one score — maintenance doesn't compose across a dependency tree:

```
Unmaintained deps: 3 (1 deprecated) of 18 assessed  |  Unassessed: 4
```

That count is the *most probable* state — packages whose posterior peaks on `abandoned` or
`deprecated`. Triage asks the softer question, $P(\text{not maintained}) \ge 0.5$, so a package
split evenly between `winding_down` and `abandoned` can be triaged `refactor` without appearing in
the unmaintained count.

`info <package>` shows the full decomposition: `Gap CV` and the number of commits behind it,
`silence` and its p-value, the `engagement` flow trend, `Last pushed`, any `Deprecation` signals,
the `Maintenance` state with its risk and the observations behind it, and the resulting triage
action.

The `--schema-version=1.5` JSON export carries `maintenance_state`, `maintenance_risk`,
`maintenance_coverage`, `gap_cv`, `median_gap_days`, `silence_days`, `silence_p`,
`commits_sampled`, `span_days`, `flow_trend`, `engagement_buckets`, `deprecation_signals`,
`deprecation_successor`, `days_since_push`, `archived` and `triage_action`. The CSV carries the
same set minus the four that don't fit a flat column — `maintenance_coverage`, `median_gap_days`,
`span_days`, `archived` — and minus `engagement_buckets`.

**Any field is `null` when it couldn't be measured. That means "unknown", never "no risk."**

Switch the whole channel off with `--no-stability` (`OSSIQ_STABILITY=false`); switch just the
GraphQL flow channel off with `--no-stability-responsiveness` — already off by default on
unauthenticated scans, where GitHub allows 60 requests an hour.

## Calibration

`qa/calibrate_stability.py` (`just calibrate-stability`, needs `OSSIQ_GITHUB_TOKEN`) runs the real
scan path against the 63-repo hand-labelled 4-state corpus. Three gap checks gate the exit code
and are passing:

1. `gap_cv` decoupled from commit volume — Pearson $|r| < 0.5$ across the `maintained` set.
2. Every `abandoned` repo flagged `has_stopped`; `benjaminp/six` not flagged.
3. No repo with a commit inside 30 days flagged.

The model itself is reported as a confusion matrix, multiclass Brier score and reliability curve
over the four states — **informational until the `LIKELIHOOD` tables are tuned** against the
corpus, then promoted to a hard check (diagonal accuracy $\ge 70\%$, Brier $\le 0.20$). The
tuning procedure is in `qa/manual/stability-calibrate.md`.
