(the-cycle)=
# The cycle: `status` → `plan` → `apply`

Part of [Recommendations and Risk](../recommendations.md).

| Command | Reads | Writes | Prompts |
|---|---|---|---|
| `status` | full scan | nothing | — |
| `plan` | full scan + update plan | nothing | — |
| `apply` | full scan + update plan | manifest + lockfile, via the native package manager | two |

`plan` and `apply` run the *same* code path: `apply` is `plan` plus confirmation plus execution. The
plan you are shown by `apply` is the plan `apply` executes — it is computed in the same process,
milliseconds earlier.

## Why `apply` re-scans instead of consuming a saved plan

There is no plan file. `apply` performs its own scan and builds its own plan. This costs a second
scan when you run `plan` first, and buys three things:

1. **No stale plan.** A plan saved an hour ago describes a registry that has moved and a tree that
   may have been changed by a teammate. There is no window between deciding and writing.
2. **No new format to trust.** A serialized plan would be a file the tool has to re-validate, and a
   file an attacker could hand you.
3. **CLI and MCP stay equals.** Both front doors call the same service function; neither holds a
   decision the other would get wrong.

## How the write actually happens

Per ecosystem, in this order:

1. **Read and parse the manifest first.** An unparseable `package.json`/`pyproject.toml` fails the
   whole update loudly, before anything is rewritten, rather than degrading package by package.
2. **Rewrite direct specifiers** in the manifest text. `--pin-all` writes exact `==`/exact pins.
3. **Add repaired peers (npm).** A peer the plan repairs (see *Repairs unresolved peers* in the [catalogue](catalogue.md#the-non-recommendations)) is
   declared in `devDependencies`, or `dependencies` when a production package needs it, at the range
   the plan shows. A package your manifest already declares anywhere is left as you wrote it.
4. **Persist transitive picks as overrides** — npm `overrides`, uv `[tool.uv] override-dependencies`
   — and record what was written under an `ossiq:metadata` key. On npm each pick is keyed to the copy
   it replaces (`"minimatch@10.2.5": "10.2.6"`), so a nested copy of the same name that npm installed
   for a different range is not dragged along. A copy that has to move together with its family is
   keyed to the range from its old version to its new one (`"@vue/shared@3.5.42 - 3.5.43": "3.5.43"`). On the next run, an override whose value no longer
   matches what OSS IQ last wrote is left alone: you have taken ownership of it, and it is never
   silently overwritten.
5. **Hand resolution to the native package manager** — `npm install --ignore-scripts`, or
   `uv lock --upgrade-package … && uv sync`. OSS IQ does not resolve trees itself, and
   `--ignore-scripts` keeps install-time code out of the update path.
6. **On failure, restore the original manifest text** and raise.

## The two prompts

```
Proceed with 7 updates? [y/N]
```

then, only if something needs it:

```
The following updates need explicit acknowledgement - they widen the declared version
constraint (authorized by --update-strategy latest), or carry a known API/module-system break:
  requests  ~=2.31.0 -> 2.34.2  [direct]  (widens ~=2.31.0)
```

The second prompt exists because two different things deserve a separate "yes": **rewriting a
constraint someone chose deliberately**, and **taking a version that crosses a known API or
module-system break**. `breaking_change` ignores the runtime, so an ESM-only target in a CommonJS
project always asks, including the ones `latest` picks on a `require(esm)`-capable Node. The second case used to pass silently whenever the break happened to sit
*inside* the declared range — `uuid@>11.0.0` admits ESM-only `14.0.2` — so nothing asked. Both are
now named per entry. `--yes` skips both prompts.

## Convergence

Updates are resolved in a single pass against the *current* lockfile. Applying them re-resolves the
tree, which can surface further recommendations, so `apply` closes by telling you to re-run `plan`.
Most projects converge in one or two passes.

## What the cycle risks

| Risk | Detail | What to do |
|---|---|---|
| **Rollback restores the manifest, not the world** | If the package manager fails mid-run, the manifest is restored — the lockfile, `node_modules` and the virtualenv are whatever the failed command left behind. | Run `apply` on a clean working tree, under version control |
| **`--yes` authorizes constraint rewriting** | In CI at `latest`/`cutting-edge`, `--yes` skips the acknowledgement prompt, so declared ranges are rewritten with no second check. | Pin CI runs to `standard`, or review the `plan` output as a gate |
| **`--override` is unverified by construction** | It bypasses the solver, the cooldown, the widening hold and the prompt. Parent-constraint compatibility is not checked. | Treat forced versions as manual changes; test them |
| **One pass is not convergence** | The plan describes the tree as it is now, not as it will be after the write. | Re-run `plan` after every `apply` |
| **Transitive picks persist** | They are written as overrides and stay until removed, and show up as `ConstraintType.OVERRIDE` on later scans. | Expect them in review; remove them when upstream catches up |
