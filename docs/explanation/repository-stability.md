# Repository Stability

OSS IQ runs two risk pipelines that are deliberately never combined into one number.

| Pipeline | Metric | Question it answers | Action it drives |
|---|---|---|---|
| Tactical | EPSS | Is a known CVE being exploited right now? | Patch or bump |
| Strategic | Repository stability | Will this project still be maintained? | Refactor or replace |

## Why they stay separate

EPSS is scoped to published CVE identifiers. A package with no filed CVEs has an *undefined* EPSS,
not a zero. Treating an unvetted or abandoned package as safe because nobody has filed an advisory
against it is a false negative, and it is the single most common way a dependency scanner misleads
you.

Multiplying the two into one scalar would also mix units. Exploit probability is a likelihood over
a 30-day window; repository stability is a statement about maintenance capacity. Their product
means nothing. So OSS IQ reports both, and joins them only at the point of deciding what to do.

## The Composite Stability Index

The index comes from
[Introducing Repository Stability](https://arxiv.org/abs/2504.00542) and its
[empirical validation](https://arxiv.org/abs/2508.01358). It treats a repository as a control
system and asks whether its activity returns to equilibrium after a disturbance — a contributor
leaving, a flood of bug reports, a release crunch.

```
CSI(t) = wc·φc(c) + wi·φi(i) + wp·φp(p) + wa·φa(a)
W      = [0.30, 0.25, 0.25, 0.20]
φk(x)  = 1 − |x − μk| / σk   if |x − μk| ≤ σk   else 0
```

| Component | Measures | Weight | Status in OSS IQ |
|---|---|---|---|
| `φc` commit frequency | Coefficient of variation of weekly commit counts | 0.30 | not computed — replaced by gap sampling, no corridor mapping |
| `φi` issue resolution | Closure ratio, penalised by median resolution time | 0.25 | computed, **not in CSI** — corridor collapses to 0 |
| `φp` pull requests | Merge ratio, penalised by median review time | 0.25 | computed, **not in CSI** — corridor collapses to 0 |
| `φa` engagement | Comment intensity and active-participant share | 0.20 | **in CSI** — the one channel whose corridor separates the corpus |

All three `φ` channels are computed from a batched GraphQL sample of the last 120 days of issue,
pull-request and discussion activity (see [Responsiveness sampling](#responsiveness-sampling)) and
exported as `phi_i` / `phi_p` / `phi_a`. Which ones feed `stability_csi` is decided by
[calibration](#calibration): a channel joins `CALIBRATED_CHANNELS` only once its corridor is shown
to separate a hand-labelled `active` / `abandoned` corpus. The 33-repo run found `φi` and `φp`
collapse to ≈0 for nearly every repository on the paper's `(0.40, 0.10)` / `(0.50, 0.10)` corridors
— matching arXiv:2508.01358's `φi = 0` result — so both are computed and exported but left out;
only `φa` (active mean 0.18, abandoned 0.02) is wired in. `stability_csi` is therefore an
**engagement-only partial index** with `stability_coverage` `0.20`; it is displayed and advisory,
never a verdict input. When a repository has no issue or PR activity in the window at all, `φa` and
`stability_csi` are `null` (unknown, not zero).

The commit channel `φc` is out permanently: its gap-sampling replacement (below) is volume-free by
construction but has no calibrated mapping onto this paper's corridor normalizer.

## Why the estimator changed

The original commit channel sampled **fixed time, random event count**: 17 weekly buckets, count
commits per bucket, take the coefficient of variation. For a Poisson process, `CV = 1/√λ` — the
statistic is a function of *volume*, not stability. Measured against this project's own PyPI
fixtures, that put every single measured package below the paper's 0.70 threshold, `ruff`, `uv`,
`pydantic` and `requests` included: "stable" was reading as "busy."

The current channel samples the **last 100 commits** instead — event count fixed, elapsed time
random. The natural statistic is the **inter-commit gap**, and inter-arrival times of a memoryless
process are Exponential, which has `CV = 1` regardless of rate. `gap_cv` is therefore volume-free by
construction: read `gap_cv > 1` as clumped/bursty activity, `≈ 1` as memoryless, `< 1` as more
regular than chance.

### The dormancy test

The gap distribution answers the question that actually matters for a calm-but-healthy package: is
the *current* silence unusual for *this* repository?

```
silence_days = now − (most recent sampled commit)
silence_p    = fraction of this repo's own historical gaps longer than silence_days
stopped      = silence_p < 0.05  and  silence_days ≥ 90
```

Both halves of that conjunction are load-bearing. The p-value clears calm-but-alive repositories —
a package whose typical gap is 60 days sitting silent for 90 is unremarkable *for that package*.
The 90-day floor clears both a hyperactive repository's long weekend and a low-churn library's
ordinary one-to-two-month lull — three months of silence is where an unusually long gap starts to
look like abandonment rather than a pause.

This replaces the older rule ("zero commits in a fixed 120-day window"), which conflated *abandoned*
with *finished*. A concrete case from calibration: `benjaminp/six` had zero commits in the old
120-day weekly-bucket window — flagged dormant, wrongly. Its current silence is 183.8 days, but
`six`'s own commit history has gone quiet for stretches this long often enough that `silence_p =
0.061`, just above the threshold — the silence isn't unusual *for six*. The new test compares each
repository against its own history instead of a cross-repository constant, so it can tell `six` and
a genuinely abandoned package like `nose` apart using the same rule.

### Sampling

Commits are fetched via `GET /repos/{owner}/{repo}/commits?per_page=100` — one page, one request,
newest-first. Bot commits (`dependabot[bot]`, `renovate`, `pre-commit-ci`, `github-actions`, and any
`*[bot]` login) are filtered out before gaps are computed: a weekly dependabot commit would
otherwise give an abandoned repository a perfectly regular gap distribution and read as healthy.
Timestamps use `commit.committer.date`, not `commit.author.date` — author dates survive rebase and
cherry-pick and are occasionally in the future.

This channel only runs for **direct dependencies** (packages declared directly in the project
manifest) — transitive dependency stability is out of scope by design: there is no independent
lever to act on an upstream package you didn't choose to depend on. Results are cached for 7 days
(`--stability-cache-ttl`, default 168 hours) since a repository's commit rhythm doesn't meaningfully
change day to day, well past the general HTTP cache's default TTL.

### Responsiveness sampling

The `φi` / `φp` / `φa` channels need issue and pull-request data, which is not in git and not
reachable from the commit endpoint at any sampling design. They come from one batched GraphQL query
(`POST /graphql`) that aliases ~5 repositories per request and pages issues and PRs back to a
**120-day window**: issues opened / closed and their median resolution time, PRs opened / merged and
their median review time, comment counts, and the set of participating accounts against the
repository's mentionable-user count. Bots are filtered from every author set — a stream of
dependabot PRs otherwise inflates `φp`.

GraphQL requires a token (it 401s unauthenticated), so this channel **defaults on when a
`OSSIQ_GITHUB_TOKEN` is set and off otherwise**; force it either way with
`--stability-responsiveness` / `--no-stability-responsiveness`. Like the commit channel it runs for
**direct dependencies only** and its responses are cached for 7 days (`--stability-cache-ttl`). The
raw inputs behind each `φ` are persisted in the JSON export so the corridors can be recalibrated
offline without re-hitting the API.

### Unknown is not zero

| Situation | `commits_sampled` | `gap_cv` / `silence_p` | Meaning |
|---|---|---|---|
| No repository URL, a non-GitHub host, or no commit was sampled | n/a (unmeasured) | n/a | Nothing was measured |
| Measured, but fewer than 20 sampled gaps | > 0 | `null` | Measured, gap statistics not yet trustworthy |
| Measured, with at least 20 gaps | > 0 | a number | Fully measured |

A package that could not be measured is never marked for refactoring. `prefetch` only resolves
`github.com` URLs, so GitLab, Codeberg and packages with no declared repository stay unknown
forever.

## Calibration

The gap estimator was validated against a hand-labelled corpus (active, finished, and abandoned
repositories) before the triage path was cut over to it — see
[Repository Stability — Gap Estimator Calibration](repository-stability-calibration.md) for the
full write-up and results table. The checklist it answered: does `gap_cv` decouple from commit
volume, does `has_stopped` agree with hand-labelled abandonment (specifically clearing "finished"
libraries like `six`), and does the silence floor hold on the busiest repositories without false
positives. All three passed on that corpus, and `has_stopped` is what now drives triage.

The same harness ([`qa/calibrate_stability.py`](../../qa/calibrate_stability.py)) also reports, per
`φ` channel, whether its corridor separates the labelled `active` and `abandoned` sets or collapses
every repository to 0 / 1 the way the old weekly-bucket `commit_cv` did. A channel joins
`CALIBRATED_CHANNELS` — and therefore `stability_csi` — only when it passes that check; a channel
that doesn't is still computed and exported, just left out of the composite. `has_stopped` and the
triage matrix are unaffected either way.

## The triage matrix

| Exploit signal | Repository | Action | Why |
|---|---|---|---|
| EPSS ≥ 0.10 | stopped | `evict` | Exploited, and no fix is coming. Replace it. |
| EPSS ≥ 0.10 | active | `patch` | Exploited, but maintainers can ship a fix. Bump it. |
| below 0.10 | stopped | `refactor` | No exploit pressure, but real maintenance debt. Schedule it. |
| otherwise | | `retain` | Baseline healthy state. |

"Stopped" here is `has_stopped` — an unusual silence relative to the repository's own commit
history, not a fixed calendar window. CVEs scoring below **0.005** — a 0.5% chance of exploitation —
do not count toward the exploit signal. They are reported as `suppressed_cves` rather than dropped,
so the noise reduction is visible instead of silent.

An unmeasured repository is never treated as stopped. A package whose stability is unknown (too few
commits sampled to resolve a silence p-value, or no repository at all) keeps its exploit-driven
action, so it can reach `patch` but never `evict` or `refactor`.

The action is **advisory**. It appears in `status`, `info`, the JSON and CSV exports, the HTML
report and the agent/MCP verdict, but it does not change the `ok`/`warn`/`block` verdict that gates
a build.

## Reading the output

```
  Dormant repos: 11 of 56 measured  |  Unmeasured: 54
```

Three numbers, deliberately not one. There is no project-level CSI: unlike EPSS, where "at least
one dependency is exploited" is a real probability with a real composition rule, averaging
stability across a dependency tree produces a number with no meaning.

`ossiq-cli info <package>` shows the full decomposition for one package — the gap coefficient of
variation and how many commits it spans, the current silence and its p-value, the responsiveness
channels `φi` / `φp` / `φa` (and the CSI once one is calibrated), days since the last push, whether
the repository is archived, and the resulting action with its reason.

Repository measurement can be switched off with `--no-stability` (or `OSSIQ_STABILITY=false`),
which skips one GitHub request per direct-dependency repository. The GraphQL responsiveness channels
are switched off separately with `--no-stability-responsiveness` and are already off by default on
unauthenticated scans, where the GitHub quota is 60 requests an hour.
