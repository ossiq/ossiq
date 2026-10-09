(the-pyramid)=
# The update pyramid

Part of [Recommendations and Risk](../recommendations.md).

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

## Two axes, not one dial

A tier sets two independent things, kept in two separate tables on purpose:

- **Motive** — *why* a package may move ([`ADMITTED_MOTIVES`](motives.md)).
- **Reach** — *how far up the ladder* it may go on that motive (`MAX_REACH`).

Collapsing them would make "why did this move" and "how far could it move" the same question, and
they are not. An end-of-life package may have to leave its declared range even under the otherwise
minimal-diff `deprecation` tier.

## Escalation: the pyramid refuses to say "stay put"

Two motives — `exploitable_cve` and `end_of_life` — push reach to `latest` regardless of tier.
"Remain inside a range that contains no safe version" is not an answer OSS IQ will give. When that
happens, the selection carries an `escalation` string naming the reason. The same applies when
*every* reachable version still carries a qualifying CVE: OSS IQ picks the newest anyway and says so
rather than silently recommending nothing.

Freshness tiers get one more escape: if drift alone leaves nothing in reach — an exact pin whose
only newer releases sit outside the declared range — reach widens one rung at a time until
something is found. This is why a `pydantic==1.10.13` pin yields `1.10.26` instead of `None`.

## The module-system line

For a CommonJS npm project, a release that is ESM-only is a break however semver numbers it:
`require()` of it fails outright on older Node, and on a Node that supports `require(esm)` it
returns the module namespace, so a package with only a default export (chalk) still breaks. The
manifest can't say which shape a package has. So the tier also decides whether a recommendation
may cross from the installed module system to ESM-only:

| Tier | May recommend an ESM-only release to a CommonJS project |
|---|---|
| `security`, `deprecation`, `standard` | no |
| `latest`, `cutting-edge` | only when the runtime can `require()` ESM (Node ≥ 20.19, ≥ 22.12, ≥ 23), flagged with `breaking_change` |
| any tier, CVE or end-of-life motive | yes, when no clean release is left on the CommonJS line — flagged the same way |

The permission only grows up the pyramid, so a higher tier's target is still never lower. Drift
alone never crosses on a lower tier. When every newer release is ESM-only, the target stays blank
and the refused release is named in `rejected_candidates`, rather than being taken anyway. The
record carries both answers: `latest_preserving_module_system` (where your code keeps working as
it does today) and `latest_compatible_major` (what the runtime might load), with
`module_system_note` saying which one the runtime qualifies for.

## A real run, two tiers

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

## What tier choice risks

| Tier | The risk you accept | How it surfaces |
|---|---|---|
| `security` | Drift and maintenance debt accumulate invisibly; a package with only low-EPSS CVEs is never moved at all. At `security` and `deprecation` alike, the transitive solver also narrows itself to CVE-affected packages. | "N more updates available under…" footer; packages sit at `Withheld by strategy`, whose `↳` row names the lowest tier that would move them |
| `deprecation` | The same minimal-diff risk, now resting on maintenance evidence that may never have been gathered — see [Partial data](partial-data.md). | Silent: an unassessed package simply carries no `end_of_life` motive | Silent: an unassessed package simply carries no `end_of_life` motive |
| `standard` | Packages whose only newer releases sit outside the declared range are recommended but **not written** — the default tier proposes changes it will not apply. | *Requires constraint widening* block in `plan` |
| `latest` | Authorizes rewriting declared ranges. That range was a decision someone made, possibly encoding an incompatibility OSS IQ cannot see. | Second confirmation prompt in `apply` |
| `cutting-edge` | Prereleases enter the candidate set. Cooldown still applies, but a prerelease is by definition unproven. | The picked version itself |

```{note}
`--strategy-override pkg=tier` runs one package at a different tier; `--override pkg==version`
forces an exact version and wins over both. A forced version bypasses the solver, the cooldown, the
widening hold **and** the acknowledgement prompt — its compatibility is deliberately unverified.
```
