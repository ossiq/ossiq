# Repository Stability — Gap Estimator Calibration

Phase 4 of the [sampled-commit redesign](../../TODO.md) validates the gap-based commit estimator
(`gap_cv`, `silence_p`, `has_stopped` — see [`risk/stability.py`](../../src/ossiq/risk/stability.py))
against the shipped weekly-bucket one (`commit_cv`, `is_dormant`) before anything is cut over. This
is that validation, run against live GitHub data via
[`qa/calibrate_stability.py`](../../qa/calibrate_stability.py).

**Corpus:** 12 hand-picked repositories — 7 labelled `active`, 3 `finished` (maintained but
intentionally quiet), 2 `abandoned` — chosen for direct dependencies of real Python projects plus a
couple of well-known finished/abandoned libraries. This is a best-effort starting corpus, not an
authoritative one; TODO.md's own target is 30-50 hand-labelled packages.

## Results

```
repo                             label       commit_cv   gap_cv  commits   span_d  silence_d  silence_p  is_dormant  has_stopped
--------------------------------------------------------------------------------------------------------------------------------
astral-sh/ruff                   active          0.349    2.207       98      6.6        0.0      0.608       False        False
numpy/numpy                      active          0.383    2.272       93     12.8        0.2      0.141       False        False
astral-sh/uv                     active          0.540    2.396       61     11.3        0.0      0.533       False        False
pydantic/pydantic                active          0.668    1.982       90     39.8        0.2      0.371       False        False
pypa/packaging                   active          0.661    1.642       96     65.7        5.1      0.011       False        False
pallets/click                    active          1.453    1.885      100     86.2        0.8      0.273       False        False
psf/requests                     active          1.229    2.343       73    199.4        0.9      0.431       False        False
nose-devs/nose                   abandoned           -    1.891      100    667.6     3826.8      0.000        True         True
benjaminp/six                    finished            -    2.349      100   3050.9      183.8      0.061        True        False
certifi/python-certifi           finished        1.350        -       11    681.7       40.2      0.554       False        False
```

`yaml/pyyaml` and `PyCQA/pep8` came back **unmeasured** — see [Coverage gap](#coverage-gap-found-during-this-run) below.

0 of the 8 measured repos have a label/`has_stopped` mismatch.

## Checklist

**1. Does `gap_cv` decouple from commit volume, unlike `commit_cv`?** Sorted by commits/day, the
`active` repos span a 10x volume range (packaging: ~1.5 commits/day, over ruff's ~15/day) while
`gap_cv` clusters at 1.64-2.40 for all seven — no visible trend with volume. `commit_cv` shows no
clean trend either in this sample, but it's mathematically volume-dependent by construction
(`CV = 1/sqrt(lambda)` for a Poisson process — see TODO.md's derivation), so a small corpus not
showing the effect isn't evidence it's absent; it just means the effect needs a wider volume range
than 7 busy repos to surface empirically. The decoupling claim for `gap_cv` rests on the analytic
property (Exponential inter-arrival times have CV = 1 regardless of rate), not on this sample size —
this run is a sanity check, not the proof.

**2. Does `has_stopped` agree with hand-labelled abandonment, and specifically clear "finished"
libraries?** Yes, on both counts that matter most:
- `benjaminp/six`: `commit_cv` is `None` (old rule: **dormant**, wrongly) — 0 commits in the last
  120-day weekly-bucket window. `has_stopped` is **False**: its current 183.8-day silence has
  `silence_p = 0.061`, just above `SILENCE_ALPHA = 0.05` — six has gone quiet for stretches this
  long non-trivially often across its own 3050-day (8.4-year) sampled history, so this silence isn't
  unusual *for six*. This is the exact case TODO.md's design targets, live-confirmed.
- `nose-devs/nose`: both rules agree it's dead. `silence_days = 3826.8` (~10.5 years) with
  `silence_p = 0.000` — unprecedented even in nose's own history. Correctly flagged by both.

**3. Does the silence floor hold on the busiest repos (no false positives)?** Yes — `ruff`, `uv`,
and `numpy` (the three busiest by commits/day) all show `has_stopped = False`, with `silence_days`
near zero in each case. No false positives in this sample.

## Coverage gap found during this run

`pyyaml` and `pep8` returned "unmeasured" — not a gap-estimator failure, but the deliberate
simplification flagged in Phase 3's implementation: `repository_stability` only computes the new
gap fields when the **old** estimator's `MIN_WEEKS` gate passes, so a repo too quiet for 8 complete
weekly buckets in the last year loses gap-field visibility too, even if its last-100-commits page
has plenty of gap data. This is precisely the "calm package" case the new estimator exists to serve
better, so it's a real cost of the phase-3 simplification worth revisiting before scaling this
corpus past a dozen repos — decoupling the gap computation from the old gate (compute it whenever
`commits` has data, regardless of `weeks_sampled`) would very likely recover both.

## φ channel corridors (issue / pull-request / engagement)

The same harness also scores `phi_i` / `phi_p` / `phi_a` from a 120-day batched-GraphQL activity
sample and reports whether each corridor separates the labelled `active` and `abandoned` sets. The
33-repo run:

```
phi_i: active mean 0.03   abandoned mean 0.00   ->  drop
phi_p: active mean 0.08   abandoned mean 0.00   ->  drop
phi_a: active mean 0.18   abandoned mean 0.02   ->  keep
```

`phi_i` and `phi_p` collapse to ≈0 for nearly every repository on the paper's `(0.40, 0.10)` and
`(0.50, 0.10)` corridors — the "denominator drag" / slow-resolution effect
[arXiv:2508.01358](https://arxiv.org/abs/2508.01358) documents, reproduced here even with a 120-day
window instead of cumulative totals. Both are computed and exported (`phi_i` / `phi_p`) but left out
of `CALIBRATED_CHANNELS`, so they do not enter `stability_csi`. `phi_a` (engagement — comment
intensity × participant share) is the one corridor that discriminates and is wired in;
`stability_csi` is therefore an engagement-only partial index with `stability_coverage` `0.20`,
displayed and advisory, never a triage or verdict input. `has_stopped` and the triage matrix are
unchanged by any of this.

## Recommendation

Proceed to Phase 5 for the `has_stopped` triage cutover. The evidence is directionally strong and
the headline case (`six`) validates exactly what the design set out to fix, but before broadening
the corpus to TODO.md's full 30-50 packages: (1) decouple the gap fields from the `MIN_WEEKS` gate
so quiet-but-measurable repos like `pyyaml` aren't lost, and (2) widen the `active` sample's volume
range (this run's busiest-to-calmest ratio was only ~10x) to give the volume-decoupling check in
item 1 room to actually discriminate.
