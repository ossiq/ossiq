---
name: ossiq-dependency-check
description: >-
  Check open-source dependency health with OSS IQ before adding a new dependency
  or updating existing ones. Use whenever you are about to add a package to a
  project (pip/uv/npm install, editing pyproject.toml / package.json) or bump
  dependency versions. Returns a compact verdict (ok/warn/block), a recommended
  version, known CVEs, and supply-chain warnings.
---

# OSS IQ dependency check

OSS IQ is a **local CLI tool** — it runs entirely on your machine and does not
send any project data to external services. All analysis is performed locally.

Run via `uvx --from ossiq ossiq-cli` (no install needed, works from any directory) or bare `ossiq-cli` if already installed.

**GitHub rate limits:** Without a token, GitHub's API allows 60 req/hr. If you hit rate limits, the user should run `ossiq-cli install skills <tool> --github-token <token>` once to store the token in `~/.ossiq/config` (classic PAT, no scopes needed for public repos raises the limit to 5 000 req/hr). Do not ask the user to pass it manually on every command.

OSS IQ scores dependency health: drift, CVEs, maintainer/bus-factor risk,
typosquat signals, and a solver-recommended version. Run it **before** you
change a project's dependencies and act on the verdict.

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
  "verdict": "warn",
  "recommended_version": "2.31.0",
  "reasons": ["recommend 2.31.0 rather than latest 2.32.0", "single maintainer — bus factor risk"],
  "cves": [],
  "warnings": ["SINGLE_MAINTAINER"]
}
```

## When updating existing dependencies

Before bumping versions, run:

```bash
uvx --from ossiq ossiq-cli status <project_path> --format agent
```

Returns `{"operation": "update", "verdict": ..., "updates": [...]}` where each
entry has `package`, `from`, `to`, `verdict`, `reasons`, `cves`, and
`transitive_impact`.

## How to act on the verdict

- **block** — do not proceed. A critical risk (e.g. a CVE with no safe version,
  a yanked/unpublished package, or single-version typosquat risk). Tell the user
  and stop.
- **warn** — proceed with caution. Prefer `recommended_version` over the latest,
  and surface the `reasons` to the user.
- **ok** — safe to proceed. Use `recommended_version` when present.

Always pin to `recommended_version` when it is set rather than the absolute
latest — it is the solver's safe choice (avoids known-CVE and too-fresh versions).
