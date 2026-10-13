---
title: How a recommendation is decided
description: The three questions OSS IQ answers before it recommends a version, the two rules that hold at every tier, and five questions for reading any recommendation.
---

# How a recommendation is decided

Part of [Explanation](explanation/index.md).

**Every line OSS IQ prints under *Recommended*, *What's Next* or *Plan* is a decision taken on your
behalf. This page says how OSS IQ reaches that decision and how to read the result.**

[Reference → Update Strategy](reference.md#update-strategy) and
[Reference → Version ladder](reference.md#version-ladder) define the flags and the fields. This
page is the *why*, and it is the one to read before you wire `ossiq` into CI, hand it to a coding
agent, or run `apply --yes`.

## Three questions, answered in order

Three different parts of the tool answer them:

| # | Question | Answer | Decided in |
|---|---|---|---|
| 1 | May this package move at all? | a set of **motives** | [`strategy/motive.py`](https://github.com/ossiq/ossiq/blob/main/src/ossiq/strategy/motive.py) |
| 2 | How far up the version ladder may it go? | a **reach** | [`strategy/pyramid.py`](https://github.com/ossiq/ossiq/blob/main/src/ossiq/strategy/pyramid.py) |
| 3 | May `apply` write the result? | the picked **rung** vs. the tier's authorization | [`service/update.py`](https://github.com/ossiq/ossiq/blob/main/src/ossiq/service/update.py) |

Questions 1 and 2 are pure functions over facts already gathered — no network, no clock. Question 3
is where something you can *read* becomes something OSS IQ will *write*.

Two invariants hold across all of it:

- **No downgrades.** Every candidate is strictly newer than the installed version, at every tier,
  under every motive. A recommendation can be blank; it can never point backwards.
- **A visible recommendation is not an authorized write.** `status` can show a target that
  `plan` files under *Requires constraint widening* and `apply` will not touch. See
  {ref}`The writable/readable split <the-writable-readable-split>`.

## Reading any recommendation in five questions

1. **Why did it move?** → `motives`, or the `↳` reason rows.
2. **How far did it reach, and from which rung?** → `recommended_from_rung`;
   `in_major`/`latest` means the declared range has to be rewritten first.
3. **Will `apply` actually write it?** → not if it is under *Requires constraint widening* or
   *Held for cooldown*.
4. **Was the evidence actually there?** → `data_completeness`. An empty result and an
   unreachable source look identical in the headline, and only here.
5. **Can every package load its peers?** (npm) → `unresolved_peers` on the package and
   `peer_repairs` on the decision. A package can read `no action needed` and still be unable to
   load a peer; `plan` shows the repair `apply` would make.
