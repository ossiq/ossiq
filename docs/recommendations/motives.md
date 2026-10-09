(motives)=
# Motives — why a package is allowed to move

Part of [Recommendations and Risk](../recommendations.md).

A motive is evidence that a package *should* change. Four exist; `classify_motives` derives them
from facts already on the scan record.

| Motive | Set when | Evidence source |
|---|---|---|
| `exploitable_cve` | any CVE with EPSS ≥ 0.005 **or with no EPSS score at all** | OSV + EPSS |
| `suppressed_cve` | a CVE scored below 0.005 | OSV + EPSS |
| `end_of_life` | maintenance state is `abandoned`/`deprecated`, **or** a registry deprecation marker, **or** strong deprecation evidence | registry + GitHub + the [maintenance model](../explanation/repository-stability.md) |
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

## Three deliberate asymmetries

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

## What motives risk

| Risk | Why | Mitigation |
|---|---|---|
| **A missing source silently removes a motive.** OSV unreachable → no CVEs → no `exploitable_cve` → `--update-strategy security` reports *"nothing to do"*, character-for-character identical to a clean project. | Motives are derived from fetched evidence, and an absent fetch looks like absent evidence. | Check `data_completeness` before trusting an empty security run — [Partial data](partial-data.md) |
| **Triage and the motive set can disagree, by design.** With EPSS degraded, a package's CVEs are unscored: the strategy treats it as exploitable and moves it; triage drops the unscored score, finds no exploit signal and reports `retain`. | Fail-safe for writes, evidence-based for advice. | Read `triage` as advice, `motives` as the reason something moved |
| **`end_of_life` leans on GitHub.** With the repositories step degraded, the maintenance model may not run at all, leaving `end_of_life` resting on registry markers alone. | The model needs commit/activity/README observations. | `--update-strategy deprecation` is only as good as that scan's repository coverage |
