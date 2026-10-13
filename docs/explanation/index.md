---
title: Explanation
description: "Why OSS IQ reports what it reports, in the order of a run: what status measures, how plan picks an update, and what apply writes."
---

# Explanation

These pages explain why OSS IQ reports what it reports. Read them before you trust a
recommendation in CI or hand it to a coding agent. They follow the order of a run: what `status`
measures, how `plan` picks an update, and what `apply` writes.

Start with [The update pyramid](../recommendations/update-pyramid.md), which shows the five update
strategy tiers in one diagram. For flags and fields, see the [reference](../reference.md). For
tasks, see the [how-to guides](../how-to/index.md).

## What OSS IQ measures

A scan gathers the evidence that `status` reports and that every recommendation rests on.

| Page | What it answers |
|---|---|
| [Repository stability](repository-stability.md) | How OSS IQ judges whether a package is still maintained and whether a CVE is being exploited, and how the two meet in one triage verdict |
| [Partial data](../recommendations/partial-data.md) | What each external source feeds, what breaks when it degrades, and where that shows |

```{toctree}
:hidden:
:maxdepth: 1

Repository stability <repository-stability>
../recommendations/partial-data
```

## How OSS IQ picks an update

OSS IQ picks at most one target version for each direct dependency, and `plan` lists the result.

| Page | What it answers |
|---|---|
| [The update pyramid](../recommendations/update-pyramid.md) | How far up the version ladder a package may go, tier by tier, and what choosing a tier risks |
| [How a recommendation is decided](../recommendations.md) | Which three questions OSS IQ answers before it recommends a version, and how to read the result |
| [Motives](../recommendations/motives.md) | Why a package is allowed to move at all, and what a missing source does to that |
| [How OSS IQ picks a target version](../recommendations/target-selection.md) | When each tier withholds a package, bumps it in range, widens the range or crosses a major, as a table and a flowchart per tier |
| [Cooldown](cooldown.md) | Why a release must age before OSS IQ recommends it, and what skips the wait |
| [Engine constraints](../recommendations/engine-constraints.md) | Which runtime a release is checked against, and where that check fails open |
| [Every recommendation OSS IQ can make](../recommendations/catalogue.md) | The target version, `next_action`, the triage verdict, the add decision and the non-recommendations |

```{toctree}
:hidden:
:maxdepth: 1

../recommendations/update-pyramid
../recommendations
Motives <../recommendations/motives>
../recommendations/target-selection
cooldown
../recommendations/engine-constraints
../recommendations/catalogue
```

## What OSS IQ writes

`apply` is the only command that changes your manifest and lockfile.

| Page | What it answers |
|---|---|
| [The cycle: `status` → `plan` → `apply`](../recommendations/the-cycle.md) | What each command reads and writes, how `apply` writes, the two prompts, and convergence |

```{toctree}
:hidden:
:maxdepth: 1

../recommendations/the-cycle
```
