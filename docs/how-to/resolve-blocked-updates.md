---
title: Resolve a blocked update or a peer problem
description: "What to do when ossiq status holds a recommendation back or flags a peer: move past a transitive constraint, fix a peer violation, or repair an unresolved peer."
---

# Resolve a blocked update or a peer problem

When `ossiq status` holds a recommendation back or flags a peer, the report names what is in the
way. Find the row you see, then follow its section.

| You see | Go to |
|---|---|
| `↳ ⚠ <package>: …`, `✗ no actionable update found` or `[NO RESOLUTION]` | [Move past a transitive constraint](#move-past-a-transitive-constraint) |
| `✗ violation` under *Peer Constraint Status* | [Fix a peer violation](#fix-a-peer-violation) |
| `↳ missing peer …` or `↳ optional peer … is installed only out of reach` | [Repair an unresolved peer](#repair-an-unresolved-peer) |

Every row and marker is defined in
[Reference → Console and HTML reports](../reference/reports.md#sub-rows).

(update-blocked)=
## Move past a transitive constraint

A newer version of a direct dependency exists, but it needs a version of a transitive package
that another package in your tree rules out. The `↳ ⚠` sub-row names that transitive package.
[Constraint provenance](../explanation/constraint-provenance.md#why-a-newer-version-can-stay-out-of-reach)
explains why.

1. Find who declares the blocking constraint:

   ```bash
   ossiq info <blocking-package>
   ```

   Replace `<blocking-package>` with the package the sub-row names. *Dependency Tree* shows which
   direct dependency pulls it in, and *Policy Compliance* shows the constraint.

2. Pick one of these, in order of preference:

   - **Update or replace the other parent.** A newer version of the package that declares the
     constraint might already accept the version you need. If that package is abandoned,
     replacing it removes the constraint.
   - **Wait for upstream.** The owner of the blocking constraint has to publish a release that
     widens its range. You can't change their constraint yourself.
   - **Force the version.** `--override` bypasses the solver for one package:

     ```bash
     ossiq apply --override <package>==<version>
     ```

     You take on the compatibility risk the constraint protected against. The override persists
     in your manifest, and every later scan reports it as `OVERRIDE` until you remove it. See
     [Forced versions](../reference/update-rules.md#forced-versions).
   - **Stay on the installed version.** It keeps resolving, and the report keeps showing the
     lag.

3. Run `ossiq plan` again. The update is unblocked when the package appears in the plan without
   a `↳ ⚠` row.

## Fix a peer violation

This section applies to npm projects. `✗ violation` means the installed version of a package is
outside the range another package declares for it as a peer. The usual causes are an `overrides`
entry that forces a version out of range, an install with `--legacy-peer-deps` or `--force`, or
one package updated past what its peers allow.

Try these in order:

1. **Update the requirer.** A newer release of the package in the *Required By* column might
   accept the installed version. To check whether one exists and what constrains it, run:

   ```bash
   ossiq info <requirer>
   ```

2. **Move the violated package into the range.** Upgrade or downgrade it to a version inside the
   *Peer Constraint* column. First check that nothing else in the tree needs the version you
   move away from.
3. **Remove or adjust the override**, when an override is the cause. `ossiq info <package>`
   names the override under *Constraint Type*. See
   [npm: `overrides`](../reference/constraints.md#npm-overrides).
4. **Accept it.** If you have verified that the pair works together, leave it. The row keeps
   appearing on every scan as a reminder.

The violation is fixed when `ossiq status` shows `✓ satisfied` for the pair, or no longer lists
it.

## Repair an unresolved peer

This section applies to npm projects. A package declares a peer, and the only installed copy
sits nested under another package, where the declaring package cannot load it. It usually
follows a bump of a package that pins its dependencies exactly: npm nests the new versions and
prunes the hoisted copy.

1. Preview the repair:

   ```bash
   ossiq plan
   ```

   Look for the *Repairs unresolved peers* section. It lists the peer that OSS IQ adds to your
   manifest and the range it writes.

2. Apply it:

   ```bash
   ossiq apply
   ```

3. Run `ossiq plan` again. The repair worked when the plan reports nothing for that peer.

To make the same repair by hand, install the peer as a direct dependency, for example:

```bash
npm install --save-dev @vue/server-renderer@~3.5.43
```

Then add an `overrides` entry for each stale copy that blocks the hoist.

When the plan has no *Repairs unresolved peers* section, no installed copy satisfies the range
the package declares, and OSS IQ has nothing to repair. Update the package that declares the
peer, or the peer itself.

[Unresolved peers](../reference/reports.md#unresolved-peers) describes exactly what `apply`
writes.
