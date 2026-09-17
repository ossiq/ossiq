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
the equivalent tools `ossiq_evaluate_dependency` / `ossiq_evaluate_updates`.

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

- **Check for the Fix** — a known CVE; check for a patched release.
- **Find alternative** — the package is gone or its upstream is abandoned/deprecated; migrate off it.
- **Consider alternative** — the upstream is winding down; plan a migration.
- **Check Release Notes** — a major version behind; review breaking changes before the bump.
- **Update Immediately** — a minor/patch behind, or a recommended version exists; bump it.
- **Constrained. Check newer version** — a minor/patch behind, but the declared range
  (e.g. `~7.3.0`) admits no newer version; widening the range is the real next step.

`latest_in_range` (newest version satisfying the declared constraint) and
`latest_in_major` (newest version sharing the installed major line) are always
present — equal to `from` when that step has nothing newer, never omitted.

### Module-system and API breaks

A recommended version is not always drop-in — semver alone can't see an npm package going
ESM-only or a PyPI package relocating a top-level API across a major. `to` already routes around a
known break when a compatible version exists; when every reachable version is affected, `to`
still lands on the newest one and `breaking_change` explains why instead of leaving the pick a
silent surprise:

```json
{
  "package": "chalk",
  "next_action": "Check Release Notes",
  "from": "4.1.2",
  "to": "4.1.2",
  "latest_in_range": "4.1.2",
  "latest_in_major": "4.1.2",
  "latest_compatible_major": "4.1.2",
  "module_system": "cjs",
  "recommended_module_system": "cjs",
  "breaking_change": null,
  "reasons": ["major version drift behind 5.2.0"],
  "cves": [],
  "transitive_impact": []
}
```

Here `latest_compatible_major` (4.1.2) matches `to` because chalk 5+ is ESM-only
(`require('chalk')` returns the module namespace object, not `.blue`) and this project's
`package.json` is not itself `"type": "module"` — `5.0.0` was rejected as a candidate for exactly
that reason (see its `rejected_candidates` entry on the full record). If every release past 4.x
were ESM-only, `to` would still be the newest of them and `breaking_change` would read something
like `"ESM-only from 5.0.0 — require('chalk') will fail; use dynamic import() or stay on 4.x"`.
Never treat `to` as safe to `require()`/`import` without checking `module_system` first when
`breaking_change` is non-null.

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

`engine_context_source` says what `engine_compatible` was checked against: `"detected"` means OSS
IQ actually found the installed Python/Node on this machine (`.venv`, `.python-version`, or a
`node --version` probe — disable with `--no-probe-runtime`); `"declared"` falls back to the
project's own manifest floor (`engines.node`/`requires-python`) when nothing could be detected;
`"none"` means neither was available, and `engine_compatible` is `null` in that case — absence of
evidence, not evidence of compatibility. When every reachable version conflicts, `to` still lands
on the newest one and `engine_compatible: false` names the concrete requirement and what was
detected instead of leaving it a silent runtime failure.
