---
title: Constraint provenance
description: "Why OSS IQ reports where each version constraint comes from: a constraint says who has the power to change a version, and that decides how a CVE gets fixed."
---

# Constraint provenance

Part of [Explanation](index.md).

**A constraint says more than which version is installed. It says who has the power to change
it.** OSS IQ reports where each constraint comes from, so you see that before a CVE forces you
to find out.

| What holds the version | Who can change it |
|---|---|
| A range in your manifest | You |
| A constraints file, or uv's `constraint-dependencies` | Whoever owns that file or setting |
| An override | Whoever wrote the override |
| A range another package declares on a transitive dependency | That package's maintainers |

The five constraint types, and how OSS IQ reads each package manager's settings, are in
[Reference → Constraints, overrides and aliases](../reference/constraints.md).

## Why a constraint is harder to fix than a dependency

When a normal dependency becomes vulnerable, the fix is direct: update it, and the resolver picks
a patched version.

Constraints and overrides break that flow, because they impose version rules *from outside* the
normal dependency graph. A constraint can hold a transitive package in a range that still
contains a vulnerable version, and nothing in the lockfile shows it. You can read `h11==0.13.0`
in the lockfile and have no idea that a rule somewhere else stops `0.14.0` from resolving.

[Against Upper-Bound Version Constraints in Libraries](https://iscinumpy.dev/post/bound-version-constraints/)
describes this failure mode. Once a constraint caps a package below a patched version, *you*
cannot fix it alone: the person who wrote the constraint has to release a patch first. With many
transitive constraints spread across `pyproject.toml` entries and nested overrides, the debt
stays invisible until a CVE forces a full audit.

## Why overrides and constraints are tracked separately

An `OVERRIDE` means someone decided that a package's own version declarations don't matter. An
`ADDITIVE` constraint means a separate authority narrows what the resolver can pick. Neither is
an ordinary declared dependency, so OSS IQ reports both apart from those.

`constraint_info` names which packages are under a constraint, what kind it is, and which file
introduced it.

## Why a newer version can stay out of reach

Sometimes a direct dependency cannot move forward even though a newer version exists. A direct
dependency is one node in a graph. Each of its versions declares its own requirements on
transitive packages, and other parents in your tree constrain those same packages. The solver
recommends a version only when the whole subtree still resolves.

Take a project that depends on `A` and `B`. `A 2.0` requires `C >= 3`, but the latest `B` still
requires `C < 3`. No version of `C` satisfies both, so `A` cannot reach 2.0:

| The report shows | It means |
|---|---|
| A newer *Latest*, a *Recommended* that stays behind, and a `↳ ⚠ C: …` sub-row | The update to `A` collides with a constraint on `C` |
| `✗ no actionable update found` | Every candidate version of `A` hits such a collision |
| `[NO RESOLUTION]` with `↳ no version satisfies: …` | The constraints already contradict each other in the current tree, before any update |

The owner of the blocking constraint, here `B`, has to publish a release that widens its range.
For what you can do in the meantime, see
[Move past a transitive constraint](../how-to/resolve-blocked-updates.md#move-past-a-transitive-constraint).
