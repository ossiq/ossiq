# Stability & Maintenance-State Calibration (N4)

> Runbook for calibrating the naive-Bayes maintenance-state model in
> [`src/ossiq/risk/maintenance.py`](../../src/ossiq/risk/maintenance.py) against the
> hand-labelled corpus in [`qa/calibrate_stability.py`](../calibrate_stability.py).
>
> The `PRIORS` / `LIKELIHOOD` tables currently ship as **hand-seeded estimates**. This
> procedure turns them into calibrated numbers and flips the harness's model check from
> informational to enforced.
>
> Budget ~1–2 hours: most of it is the label-verification pass (Step 3), which is manual
> and one-time. The tuning loop (Step 4) is fast once the cache is warm.

---

## Preconditions

```bash
# A GitHub token with public-repo read (classic PAT or fine-grained, no scopes needed for public data)
export OSSIQ_GITHUB_TOKEN=ghp_...

# Working tree on feature/GH-60--health-score-calibration (or later), qa green
uv run just qa
```

- [ ] `OSSIQ_GITHUB_TOKEN` is set and valid (`curl -sH "Authorization: bearer $OSSIQ_GITHUB_TOKEN" https://api.github.com/rate_limit | grep -m1 remaining` shows a large number)
- [ ] `uv run just qa` passes
- [ ] You have ~5000 GitHub REST + a healthy GraphQL budget available (the full corpus is ~150 REST + ~80 GraphQL requests on a cold cache; near-zero on a warm one)

---

## Step 1 — Baseline run

```bash
uv run just calibrate-stability          # == uv run python qa/calibrate_stability.py
```

Runs the real scan path against every corpus repo:
`commits_batch` + `repository_activity_batch` + `readmes_batch` + PyPI/npm metadata
→ `repository_stability` → `deprecation_evidence` → `assess_maintenance`.

The harness prints its cache path on the first line. It uses a **dedicated cache file**
(`~/.ossiq/calibrate-cache.sqlite3`, not the one `ossiq status` shares) with **every response
on the 7-day stability TTL** — so a re-run inside the week is fully offline and deterministic
(~0 network requests), and it can never serve stale registry data to a real scan. To force a
fresh sample:

```bash
rm ~/.ossiq/calibrate-cache.sqlite3       # exact path is printed at the top of each run
```

First run on a cold cache is ~150 REST + ~80 GraphQL requests (well under the 5000/hr
authenticated budget). Every re-run inside 7 days is ~0. The GraphQL fetch runs at
`max_workers=3` over a 180-day window (`RESPONSIVENESS_PAGE_CAP=6`) to stay under GitHub's
CPU-time **secondary** rate limit — if you still see `HTTP 403 rate limit! Pausing...`,
lower `max_workers` in `GithubGraphQLBatchStrategy.config` further.

- [ ] Exit code 0 and the final line reads `All three gap checks passed.`
- [ ] `GraphQL activity: 0 resource-limit hit(s)` and `no activity payload for` lists **nothing** (or only repos with issues disabled — note which)

If a gap check fails, stop and fix that first — the model is downstream of `has_stopped` and
the gap checks guard it (see Step 6 / Troubleshooting).

---

## Step 2 — Read the output

The script prints, top to bottom:

| Section | What it tells you |
|---|---|
| **per-repo table** | `gap_cv`, `commits`, `silence_d`, `stopped`, `push_d`, `depr` (deprecation strength), `flow` (issue/PR flow trend), `predicted` state, `risk` = P(not maintained). One row per corpus repo. |
| **check 1** | Pearson r between `gap_cv` and commits/day across `maintained`. Must be `\|r\| < 0.5` — the whole reason the estimator switched off weekly-bucket CV. |
| **check 2** | Every `abandoned` repo flagged `has_stopped`; `benjaminp/six` NOT flagged. `deprecated` is **not** checked here — a deprecated package can carry a live repo; its signal comes from `deprecation_evidence` and the confusion matrix validates it. A `deprecated`-but-still-committing repo is listed informationally under "deprecated but still committing". |
| **check 3** | No repo with a commit inside `RECENT_ACTIVITY_DAYS` (30) flagged `has_stopped` — a regression guard on the `MIN_SILENCE_DAYS` (90) floor. |
| **GraphQL activity** | resource-limit hits + repos that returned no issue/PR payload. A repo in `missing` contributed no `flow_trend`, so its prediction leans on `deprecation_strength` + `has_stopped` + `push_age` only. |
| **confusion matrix** | predicted (argmax posterior) vs hand label, 4×4, with per-row recall and per-column precision, plus overall diagonal accuracy. **This is the headline metric.** |
| **multiclass Brier** | mean over scored repos of `Σ_s (p_s − 1[label=s])²`. 0 = perfect. Reported overall and per class. |
| **reliability curve** | predicted `P(not maintained)` in deciles vs the observed not-maintained rate in each bucket. `<-- off diagonal` marks a bucket where mean-predicted and observed differ by > 0.2 (the model is over/under-confident there). |

Record the baseline numbers before touching anything:

```
diagonal accuracy: ____%      Brier: ____
per-class recall:  maintained ___  winding_down ___  abandoned ___  deprecated ___
```

---

## Step 3 — Verify the corpus labels (one-time)

The corpus is only ground truth if the labels are right. Go through
[`qa/calibrate_stability.py`](../calibrate_stability.py) `CORPUS` and confirm each entry.
**Priority: every `note="VERIFY..."` entry, plus every repo the confusion matrix mispredicts.**

For each repo check, in order:

1. **Last commit HEAD date** — `https://github.com/<owner>/<repo>/commits` (or the per-repo
   table's `silence_d` / `push_d`).
   - commit inside ~3 months → `maintained` unless flow is clearly declining
   - 3–12 months → `winding_down` (mature) or check for a deprecation marker
   - 12+ months, no marker → `abandoned`
2. **Archived flag** — the grey "This repository has been archived" banner → `deprecated`.
3. **PyPI trove `Development Status`** — `https://pypi.org/pypi/<name>/json` →
   `.info.classifiers` contains `Development Status :: 7 - Inactive` → `deprecated`.
4. **All releases yanked** — every version on the PyPI release history struck through → `deprecated`.
5. **npm `deprecated`** — `https://registry.npmjs.org/<name>` → `.versions["<latest>"].deprecated`
   is a string → `deprecated`.
6. **README top** — a deprecation banner / "use X instead" in the first screenful → `deprecated`.
7. **Release cadence** — a package still cutting releases every few months, even with few
   commits, is `winding_down`, not `abandoned`.

Fix the `state=` and tighten the `note=` for anything that was wrong. Known suspects to
resolve first:

- [ ] `noamraph/tqdm` — this is the *original author's* fork; the live project is `tqdm/tqdm` and maintained. Replace with `tqdm/tqdm` (`maintained`) or drop the entry.
- [ ] `lodash/lodash` — verify release cadence; it went quiet for a long stretch, may be `winding_down`.
- [ ] `chardet/chardet`, `PyCQA/mccabe` — confirm still-alive-but-quiet vs abandoned.
- [ ] `substack/node-browserify`, `jashkenas/coffeescript` — confirm `winding_down` not `deprecated`.
- [ ] `boto/boto`, `celery/django-celery`, `getsentry/raven-python` — confirm the repo is archived (the label assumes it).
- [ ] `mitsuhiko/flask-oldsessions` — has no `pypi`/`npm` name; confirm the GitHub repo still resolves.

Then grow toward **50–80 entries, ≥ 10 per state** (the seed set is thin on `deprecated`
and `winding_down`). Keep the wide `maintained` commit-volume range and the
popular-but-abandoned cases (`itsdangerous`, `moment`) — those are the ones the model gets
wrong.

- [ ] Every `CORPUS` entry hand-verified; `VERIFY` notes replaced with the evidence found
- [ ] ≥ 10 repos per state
- [ ] Re-run Step 1 — check 2 still passes (a relabel can move a repo into `abandoned`/`deprecated` and expose a `has_stopped` miss)

---

## Step 4 — Tune the likelihood tables

Edit the constants in [`src/ossiq/risk/maintenance.py`](../../src/ossiq/risk/maintenance.py):

- `PRIORS` — set to the corpus proportions (count each state, divide by total). Or leave a
  mild lean toward `maintained` if the corpus over-samples dead repos (it does by design).
- `LIKELIHOOD[obs][value][state]` = `P(observation = value | state)`. Read these off the
  per-repo table: for each `(observation, state)` cell, what fraction of that state's repos
  show that value?
  - e.g. `LIKELIHOOD["has_stopped"][True]["abandoned"]` ≈ (abandoned repos flagged stopped) / (abandoned repos measured)
  - `LIKELIHOOD["flow_trend"]["declining"]["winding_down"]` ≈ (winding_down repos whose `flow` column reads `declining`) / (winding_down repos with a flow trend)
- **Keep every cell in `[0.01, 0.99]`** (Laplace smoothing) so one surprising observation
  can never zero out a state.
- `MAINTENANCE_THRESHOLD` (default `0.5`) — the `P(abandoned) + P(deprecated)` cut that makes
  triage mark a package unstable. Raise it if the reliability curve shows the model is
  over-confident in the `0.4–0.6` band and you're getting false `refactor`s; lower it if
  real abandonment is slipping through as `retain`.
- `push_age_bucket` boundaries (`30` / `90` / `365` / `730` days → fresh / recent / aging /
  stale / ancient). `fresh` (<30d) is split out on purpose so a recent push is near-decisive
  for "active" — a low-churn library with bursty `gap_cv` (werkzeug, sqlalchemy) can't drift to
  `winding_down` on dispersion alone. Tune `LIKELIHOOD["push_age"]["fresh"]` hard toward
  `maintained` if mature libs still misclassify.

**Two observation gates** in `service/project/stability.py::maintenance_observations` handle
the naive-Bayes independence violation between the correlated commit signals — tune the
*tables*, not these, unless the gate itself is wrong:

- **`deprecation_strength == "strong"` → every other observation is dropped.** An archived /
  registry-deprecated repo is deprecated even with recent CI commits; nothing else should move
  the verdict.
- **`push_age == "fresh"` → `flow_trend` is dropped.** A repo that pushed in the last 30 days
  is active whatever its issue/PR flow does — mature-library flow decline is release-driven,
  not decay. (`gap_cv` is deliberately *not* a model input for the same reason — it's confounded
  by release cadence; it stays a displayed / exported diagnostic.)

The loop:

```bash
# edit src/ossiq/risk/maintenance.py
uv run pytest tests/risk/test_maintenance.py -q        # tables still internally consistent
uv run just calibrate-stability                        # cached -> fast, re-scores instantly
```

Iterate until, on the verified corpus:

- [ ] confusion-matrix **diagonal accuracy ≥ 70%**
- [ ] **multiclass Brier ≤ 0.20**
- [ ] no reliability-curve bucket flagged `<-- off diagonal`
- [ ] `deprecated` recall ≥ 0.8 (missing a deprecated dep is the costly error)
- [ ] `maintained` precision ≥ 0.9 (don't cry wolf on healthy deps)

Some `test_maintenance.py` assertions bake in the *direction* of a few cells (e.g.
`test_strong_deprecation_dominates`, `test_fresh_and_alive_reads_maintained`). If a
deliberate re-tuning breaks one, update the test to match the new intent — don't fight it.

---

## Step 5 — Cross-check individual packages

Spot-check the model end-to-end through the real CLI, not just the harness:

```bash
# a healthy dep -> maintained, low risk, triage retain
uv run hatch run ossiq-cli info typer testdata/pypi/uv

# a deprecated npm dep -> deprecated, risk ~1.0, triage refactor, deprecation pills
uv run hatch run ossiq-cli --no-stability-responsiveness info request testdata/npm/deprecated

# project roll-up
uv run hatch run ossiq-cli status testdata/npm/deprecated
#   expect: "Unmaintained deps: N (K deprecated) of M assessed  |  Unassessed: U"

# export carries the fields
uv run hatch run ossiq-cli export --output-format=json --schema-version=1.5 \
    --output=reports/e.json testdata/pypi/uv
python -c "import json;d=json.load(open('reports/e.json'));\
p=[x for x in d['production_packages'] if x.get('maintenance_state')][0];\
print({k:p.get(k) for k in ('package_name','maintenance_state','stability_csi','stability_risk','flow_trend','deprecation_signals','triage_action')})"
```

- [ ] `info` "Maintenance" row shows a sane state + the observations behind it
- [ ] `info` "Deprecation" row lists the right signals for a known-deprecated package
- [ ] a package the model calls `deprecated`/`abandoned` gets `triage refactor` (or `evict` with a live CVE), a healthy one gets `retain`
- [ ] export `maintenance_state` / `stability_risk` match what `info` shows; `phi_*` keys are gone

---

## Step 6 — Lock it in

Once the metrics in Step 4 hold across **3 runs (2 warm cache + 1 fresh)**:

1. In [`qa/calibrate_stability.py`](../calibrate_stability.py), promote the model metrics
   from informational to a hard check:
   - add a `check_model_calibrated(rows)` that returns a failure string when
     `diagonal accuracy < 0.70` or `Brier > 0.20`
   - append its result to `failures` in `main()`
   - update the module docstring (it currently says "informational until the tables are tuned")
   - update the closing `print(...)` line
2. Bump the corpus-size / run-date note in the docstring and in
   [`TODO_NEXT.md`](../../TODO_NEXT.md) "Calibration outcome" section.
3. Unblock **N6** (docs): regenerate
   `docs/explanation/repository-stability-calibration.md` from the harness output (confusion
   matrix + Brier + the φ-drop finding), add it to the `docs/explanation/index.md` toctree,
   and rewrite the `## The Composite Stability Index` section of
   `docs/explanation/repository-stability.md` — the weighted-sum framing is retired.
4. `uv run just qa` + `uv run frontend-build`, commit.

- [ ] harness fails loudly on a regression in the model metrics
- [ ] docstrings / TODO_NEXT reflect the calibrated numbers and corpus size
- [ ] N6 docs regenerated

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `OSSIQ_GITHUB_TOKEN is required` | token not exported into the shell running `uv` |
| `check 1` fails (`gap_cv` tracks volume) | not a tuning problem — the gap estimator regressed. Check `commit_timestamps` / `gap_dispersion` in `risk/stability.py`. |
| `check 2` fails (a not-maintained repo not flagged) | either the label is wrong (Step 3) or the repo genuinely had a recent commit — inspect its `silence_d` / `push_d` in the table. `MIN_SILENCE_DAYS` / `SILENCE_ALPHA` in `risk/stability.py` are the levers, but changing them re-opens the whole gap calibration. |
| `check 3` fails (a repo committed <30d ago flagged) | `MIN_SILENCE_DAYS` (90) was lowered below 30, `silence_days` is being computed wrong, or a bot-commit slipped the filter (`BOT_LOGIN_RE`). A low-churn library flagged on a 1–3 month lull is *not* check 3 — that's the 90-day floor working; if the label is right (`winding_down`), the model's `push_age` observation pulls it back. |
| `HTTP 403 rate limit! Pausing all threads...` while `curl .../rate_limit` shows a full REST/GraphQL budget | GitHub's **secondary** rate limit (CPU-time / request-rate based, not the point budget). The batch client pauses `Retry-After` seconds and retries (rate-limit pauses no longer consume the error-retry budget). To avoid it: lower `max_workers` (default 3) in `GithubGraphQLBatchStrategy.config`, or `RESPONSIVENESS_PAGE_CAP` (default 6), or shrink `RESPONSIVENESS_WINDOW_DAYS`. |
| `GraphQL activity: N resource-limit hit(s)` with `N > 0` | a query blew GitHub's per-query node ceiling. Lower issues/PRs `first: 100 → 50` in `build_activity_query`, or `RESPONSIVENESS_PAGE_CAP`. |
| repos in `no activity payload for ...` | issues disabled on the repo (fine — `flow_trend` just stays null) OR the repo was renamed/deleted (fix the corpus key) OR under-sampling (see above). |
| model is confidently wrong on popular-but-abandoned repos (`itsdangerous`, `moment`) | that's the hard case — these keep community comment volume after the maintainers leave. Lean on `has_stopped` + `push_age` + `deprecation_strength`, keep `flow_trend`'s weight modest. |
| re-run gives different numbers | the 7-day cache rolled to a new grid cell (`since` moved a week) or was partially deleted mid-session. `rm ~/.ossiq/calibrate-cache.sqlite3` and run once clean. |
| a re-run still costs ~100+ requests | you're on a working tree from before the `trim_vary_header` / `engagement_window_since` fixes (GitHub's `Vary: Authorization` made requests-cache treat every authenticated hit as a miss). Check the cache path printed on line 1 exists and is non-trivial in size after run 1. |
