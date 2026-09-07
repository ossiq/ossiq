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

Run via `uvx --from ossiq ossiq-cli` (no install needed, works from any directory) or bare `ossiq-cli` if already installed.

**GitHub rate limits:** Without a token, GitHub's API allows 60 req/hr. If you hit rate limits, the user should run `ossiq-cli install skills <tool> --github-token <token>` once to store the token in `~/.ossiq/config` (classic PAT, no scopes needed for public repos raises the limit to 5 000 req/hr). Do not ask the user to pass it manually on every command.

OSS IQ scores dependency health: drift, CVEs, maintainer/bus-factor risk,
typosquat signals, and a solver-recommended version. Run it **before** you
change a project's dependencies and do what the `next_action` says.

Either call the CLI (below) or, if an MCP server named `ossiq` is connected, call
the equivalent tools `ossiq_evaluate_dependency` / `ossiq_evaluate_updates`.

## When adding a new dependency

Before introducing a package, run:

```bash
uvx --from ossiq ossiq-cli info <package> <project_path> --format agent
```

Example output:

```json
{
  "operation": "add",
  "registry": "pypi",
  "package": "requests",
  "next_action": "install with caution",
  "recommended_version": "2.31.0",
  "reasons": ["recommend 2.31.0 rather than latest 2.32.0", "single maintainer — bus factor risk"],
  "cves": [],
  "warnings": ["SINGLE_MAINTAINER"]
}
```

`next_action` for an add is `install`, `install with caution`, or `do not install`.

## When updating existing dependencies

Before bumping versions, run:

```bash
uvx --from ossiq ossiq-cli status <project_path> --format agent
```

Example output:

```json
{
  "operation": "update",
  "registry": "npm",
  "next_action": "Check for the Fix",
  "updates": [
    {
      "package": "lodash",
      "next_action": "Check for the Fix",
      "from": "4.17.15",
      "to": "4.17.21",
      "reasons": ["CVE-2021-23337 (HIGH)", "recommend updating 4.17.15 -> 4.17.21"],
      "cves": [{"id": "CVE-2021-23337", "severity": "HIGH", "summary": "..."}],
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

Always pin to `recommended_version` (`to`) when it is set rather than the absolute
latest — it is the solver's safe choice (avoids known-CVE and too-fresh versions).
