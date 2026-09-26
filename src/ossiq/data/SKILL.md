---
name: ossiq-dependency-check
description: >-
  Check open-source dependency health with OSS IQ before adding a new dependency
  or updating existing ones. Use whenever you are about to add a package to a
  project (pip/uv/npm install, editing pyproject.toml / package.json) or bump
  dependency versions. Returns a per-package `next_action` (what to do next), a
  recommended version, known CVEs, and supply-chain warnings.
---

# OSS IQ dependency check

OSS IQ is a **local CLI tool** — it runs entirely on your machine and does not
send any project data to external services. All analysis is performed locally.

Run via `uvx ossiq` (no install needed, works from any directory) or bare `ossiq` if already installed.

**GitHub rate limits:** Without a token, GitHub's API allows 60 req/hr. If you hit rate limits, the user should run `ossiq install skills <tool> --github-token <token>` once to store the token in `~/.ossiq/config` (classic PAT, no scopes needed for public repos raises the limit to 5 000 req/hr). Do not ask the user to pass it manually on every command.

OSS IQ scores dependency health: drift, CVEs, maintainer/bus-factor risk,
typosquat signals, and a solver-recommended version. Run it **before** you
change a project's dependencies and do what the `next_action` says.

Either call the CLI (below) or, if an MCP server named `ossiq` is connected, call
the equivalent tools `ossiq_evaluate_dependency` / `ossiq_evaluate_updates`. Prefer these (or
`--format agent`) over the `ossiq export` JSON: the export is a full report and several times larger.

## Tell OSS IQ which runtime the project runs on

Recommendations depend on the runtime (which Node can `require()` an ESM-only package, which
Python a release supports). Don't let OSS IQ guess it:

- **MCP:** every tool **requires** `runtime`, keyed by the project's registry:
  `{"node": "22.12.0"}` for npm, `{"python": "3.11"}` for PyPI. Take the version from the same
  shell that runs the project's own tests: `node -v` next to `npm test`, `python --version` inside
  the project's environment. If you can't tell, pass `"unknown"`; OSS IQ then assumes no runtime
  beyond the project's declared floor. **Never guess a version.**
- **CLI:** OSS IQ probes the runtime on `PATH` by default. When that isn't the project's runtime
  (nvm, fnm, volta, a different venv), pass `--engine node=<version>` / `--engine python=<version>`.

The runtime you state is still held to the project's declared floor (`engines.node`,
`requires-python`). If it disagrees with a version pin the project keeps (`.nvmrc`,
`.node-version`, `.tool-versions`, `mise.toml`, `volta.node`, `.python-version`, `.venv`),
`runtime_context.runtime_mismatch` says so. Re-check which shell you read the version from.

## When adding a new dependency

Before introducing a package, run:

```bash
uvx ossiq info <package> <project_path> --format agent
```

Example output:

```json
{
  "operation": "add",
  "registry": "pypi",
  "package": "requests",
  "next_action": "install with caution",
  "recommended_version": "2.31.0",
  "latest_in_range": null,
  "latest_in_major": null,
  "reasons": ["recommend 2.31.0 rather than latest 2.32.0", "single maintainer — bus factor risk"],
  "cves": [],
  "warnings": ["SINGLE_MAINTAINER"]
}
```

`latest_in_range`/`latest_in_major` are only populated for a package already
installed in the project (not a prospective add) — see the version ladder below.

`next_action` for an add is `install`, `install with caution`, or `do not install`.

## When updating existing dependencies

Before bumping versions, run:

```bash
uvx ossiq status <project_path> --format agent
```

By default this targets the `standard` tier of the update pyramid (plain drift, inside each
package's declared range). Pass `--update-strategy security` for the smallest diff that clears
known CVEs, or `latest`/`cutting-edge` to also widen constraints / admit prereleases — see
`ossiq status --help`. The MCP tool `ossiq_evaluate_updates` takes the same `update_strategy`
argument.

Example output:

```json
{
  "operation": "update",
  "registry": "npm",
  "update_strategy": "standard",
  "next_action": "Check for the Fix",
  "updates": [
    {
      "package": "lodash",
      "next_action": "Check for the Fix",
      "from": "4.17.15",
      "to": "4.17.21",
      "latest_in_range": "4.17.15",
      "latest_in_major": "4.17.21",
      "reasons": ["CVE-2021-23337 (HIGH)", "recommend updating 4.17.15 -> 4.17.21"],
      "cves": [{"id": "CVE-2021-23337", "severity": "HIGH", "summary": "..."}],
      "transitive_impact": []
    },
    {
      "package": "pydantic",
      "next_action": "Constrained. Check newer version",
      "from": "1.10.13",
      "to": "1.10.26",
      "latest_in_range": "1.10.13",
      "latest_in_major": "1.10.26",
      "requires_constraint_widening": true,
      "reasons": [
        "declared range ==1.10.13 caps this below 2.13.5",
        "declared range ==1.10.13 must be widened to reach 1.10.26"
      ],
      "cves": [],
      "transitive_impact": []
    }
  ]
}
```

The top-level `next_action` is the most urgent one across the `updates` list, or
`no action needed` when the list is empty. Each entry's `next_action` is one of:

- **Check for the Fix** — a known CVE that `to` does not clear (or there is no `to`); check for a
  patched release.
- **Find alternative** — the package is gone or its upstream is abandoned/deprecated; migrate off it.
- **Consider alternative** — the upstream is winding down; plan a migration.
- **Check Release Notes** — a major version behind; review breaking changes before the bump.
- **Update Immediately** — a minor/patch behind, or a recommended version exists; bump it.
- **Constrained. Check newer version** — a minor/patch behind, but the declared range
  (e.g. `~7.3.0`) admits no newer version, or the CVE fix in `to` needs it widened; widening the
  range is the real next step.
- **Withheld by strategy** — a minor/patch behind, and the range admits a bump, but the run's
  `--update-strategy` tier admitted no motive to take it. Nothing is wrong with the package;
  `strategy_withheld_reason` names the lowest tier that would move it.

`latest_in_range` (newest version satisfying the declared constraint) and
`latest_in_major` (newest version sharing the installed major line) are always
present — equal to `from` when that step has nothing newer, never omitted.

`dependency_health` (when present) is **advice, not the action**. It answers "is this dependency
healthy long-term?" (`retain` / `patch` / `refactor` / `evict`, from exploit probability ×
upstream maintenance). `next_action` is what to do now. A `retain` next to a CVE doesn't mean
"don't update": `suppressed_cves` counts CVEs scored below the EPSS noise floor, and each CVE's
own `epss` is listed under `cves`.

`dependency_name` appears only when the manifest declares the package under a different key
than its registry name — npm aliases (`"uuid-v7": "npm:uuid@^7.0.0"`) are the only case today.
Two aliases of one package produce two entries sharing `"package"`, so `dependency_name` is what
tells you which declaration an entry answers for and which line to edit.

### Module-system and API breaks

A recommended version is not always drop-in. Semver alone can't see an npm package going
ESM-only. For a CommonJS project (no `"type": "module"`), OSS IQ keeps `to` on the installed
module system:

- `security`, `deprecation` and `standard` never recommend an ESM-only release. When every newer
  release is ESM-only and the only reason to move is drift, `to` equals `from`, and
  `rejected_candidates`/`reasons` say `"<version> rejected: ESM-only from 5.0.0"`.
- `latest` and `cutting-edge` may recommend an ESM-only release, but only when the stated runtime
  can `require()` ESM (Node ≥ 20.19 / ≥ 22.12 / ≥ 23). The pick then carries `breaking_change`
  and `carries_known_break: true`.
- **Exception:** when a CVE (or end-of-life) has no fix left on the CommonJS line, the ESM-only
  fix is recommended at every tier, flagged the same way. Security beats build convenience.

```json
{
  "package": "chalk",
  "next_action": "Check Release Notes",
  "from": "4.0.0",
  "to": "4.1.2",
  "latest_in_major": "4.1.2",
  "latest_compatible_major": "6.0.0",
  "latest_preserving_module_system": "4.1.2",
  "module_system": "cjs",
  "recommended_module_system": "cjs",
  "breaking_change": null,
  "module_system_note": "ESM-only: require() on Node 22.12.0 returns the module namespace, so it works only if the package has named exports; a default-export-only package still breaks",
  "reasons": ["major version drift behind 6.0.0", "5.6.2 rejected: ESM-only from 5.0.0"]
}
```

- `latest_preserving_module_system` is the newest release your code can keep loading as it
  does today, whatever the runtime.
- `latest_compatible_major` is the newest release the stated runtime *might* load.
- `module_system_note` explains the gap between the two. `require()` of an ESM-only package
  returns its namespace, so `const { v4 } = require("uuid")` works on a capable Node, but
  `require("chalk").bold` does not, because chalk only has a default export.

Whenever `breaking_change` is non-null, don't treat `to` as safe to `require()` until the
project's own tests pass on it.

Pin to `recommended_version` (`to`) when it is set — it is the solver's safe
choice (avoids known-CVE and too-fresh versions) — **unless the entry also carries
`"requires_constraint_widening": true`**. That flag means `to` is only reachable by
widening the manifest's declared range first (`==1.10.13` admits nothing past
1.10.13, so `1.10.26` needs a wider specifier, not just a straight rewrite of the
pin). `ossiq update`/`ossiq apply` will not write such an entry on their own —
widen the constraint by hand, then re-run the command.

### Engine/runtime compatibility

`to` also routes around a package version whose declared runtime requirement (npm `engines.node`,
PyPI `requires-python`) conflicts with the runtime actually checked, the same way it routes around
a module-system break — `engine_requirement`/`engine_compatible`/`engine_context_source` report the
result for whichever version `to` ended up being:

```json
{
  "package": "some-pkg",
  "to": "1.1.0",
  "engine_requirement": {"node": ">=16.0.0"},
  "engine_compatible": true,
  "engine_context_source": "detected",
  "reasons": []
}
```

`engine_compatible` is checked against the **lower** of two versions per engine: the runtime (the
one you stated, or, on the CLI, the one probed on this machine) and the project's own manifest floor (`engines.node`/`requires-python`). The
floor counts even when a newer runtime is installed, because a release that outruns it breaks the
project's own users and will fail resolution — `uv` resolves every Python version in the declared
range, not just the one you are on. `engine_context_source` says which side is binding:
`"provided"` (the runtime you stated, for every engine), `"detected"` (the CLI probe, for every
engine), `"declared"` (the manifest floor, for at least one), or `"none"` — neither was available, and `engine_compatible` is `null` in that case, absence of
evidence rather than evidence of compatibility. When every reachable version conflicts, `to` still
lands on the newest one and `engine_compatible: false` names the concrete requirement and the
version it was checked against instead of leaving it a silent runtime failure.

## Before applying an update to a specific version

`to` above is OSS IQ's own recommendation. If you (or the user) want to go to a *different*
version — one `ossiq status`/`ossiq_evaluate_updates` didn't propose — check it first instead of
discovering a break via test failure:

```bash
uvx ossiq update-context <package> <project_path> --to <version>
```

or, over MCP, `ossiq_update_context` with `{"package": ..., "target_version": ..., "runtime": ...}`. `target_version`
is optional and defaults to the recommended version, so the same call also works as "explain the
recommendation in detail" with no `--to` at all.

Example — asking about `chalk 6.0.0` on a CommonJS project that's currently on `4.1.2`:

```json
{
  "package": "chalk",
  "registry": "npm",
  "from_version": "4.1.2",
  "to_version": "6.0.0",
  "module_system": {"from": "cjs", "to": "esm-only", "project_declares_esm": false},
  "comparison": {
    "verdict": "breaking",
    "reasons": ["6.0.0 crosses a known break: ESM-only from 6.0.0"],
    "recommended_version": "4.1.2",
    "better_available": "4.1.2"
  },
  "breaking_change": "ESM-only from 6.0.0",
  "module_system_note": "ESM-only: won't load via require() on Node 20.11.0",
  "latest_compatible_major": "4.1.2",
  "engine": {
    "requirement": {"node": ">=20.19.0"},
    "context_version": "20.11.0",
    "context_source": "provided",
    "compatible": false
  },
  "npm_cli_version": "10.2.4",
  "rejected_candidates": [{"version": "5.0.0", "reason": "ESM-only from 5.0.0"}]
}
```

**Read `comparison.verdict` first.** It holds the target up against OSS IQ's own recommendation:

- `recommended`: it *is* the recommendation.
- `suboptimal`: clean, but older than the recommendation.
- `breaking`, `vulnerable`, `deprecated`: the target has that problem. `reasons` lists every
  problem found.
- `beyond_recommendation`: clean, but past what OSS IQ recommends; check what held the
  recommendation back.

Any verdict other than `recommended` means take `better_available` unless you have a reason not
to. A diff with no `breaking_change` is **not** an approval on its own: a deprecated release older
than the recommendation has none.

This says: going to `6.0.0` hits the same ESM-only break as `5.0.0` (`module_system.to`), and
separately its `engines.node` requirement (`>=20.19.0`) is newer than what's actually installed
locally (`20.11.0`) — two independent reasons this specific version is risky, neither of which
`recommended_version` alone would have surfaced for an arbitrary target. `latest_compatible_major`
(`4.1.2`) is where `recommended_version` would fall back to instead. `rejected_candidates` lists
versions at or below the requested target that a normal scan already rejected along the way — use
it for "what else already failed on the path here", not as an exhaustive audit of every release.

For a package not yet installed, `from_version` is `null` and the payload otherwise has the same
shape — useful for previewing a brand-new dependency's own module-system/engine story before
adding it.
