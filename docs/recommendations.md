# Recommendations and Risk

**Every line OSS IQ prints under *Recommended*, *What's Next* or *Plan* is a decision taken on your
behalf. This page says what each decision means, which evidence it rests on, and what it costs you
when that evidence is missing or wrong.**

[Reference → Update Strategy](reference.md#update-strategy) and
[Reference → Version ladder](reference.md#version-ladder) define the flags and the fields. This
page is the *why*, and it is the one to read before you wire `ossiq` into CI, hand it to a coding
agent, or run `apply --yes`.

---

## How a recommendation is decided

Three questions, answered in order by three different parts of the tool:

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

## Where each part lives

| Page | What it answers |
|---|---|
| [The update pyramid](recommendations/update-pyramid.md) | How far up the version ladder a package may go, tier by tier, and what choosing a tier risks |
| [Motives](recommendations/motives.md) | Why a package is allowed to move at all, and what a missing source does to that |
| [Every recommendation OSS IQ can make](recommendations/catalogue.md) | The target version, `next_action`, the triage verdict, the add decision and the non-recommendations |
| [Engine constraints](recommendations/engine-constraints.md) | Which runtime a release is checked against, and where that check fails open |
| [The cycle: `status` → `plan` → `apply`](recommendations/the-cycle.md) | What each command reads and writes, how `apply` writes, the two prompts, and convergence |
| [Partial data](recommendations/partial-data.md) | What each external source feeds, what breaks when it degrades, and where that shows |

```{toctree}
:hidden:
:maxdepth: 1

recommendations/update-pyramid
recommendations/motives
recommendations/catalogue
recommendations/engine-constraints
recommendations/the-cycle
recommendations/partial-data
```

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
