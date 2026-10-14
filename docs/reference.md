---
title: Reference
description: "Look up a command, a setting, a report column, an export field or an update rule. Eight pages, grouped by what you have in front of you."
---

# Reference

Look up one fact here: a flag, a column, a field or a rule. Pick the page by what you have in
front of you.

For tasks, see the [how-to guides](how-to/index.md). For the reasoning behind a recommendation,
see [Explanation](explanation/index.md).

## What you type

| Page | Look here for |
|---|---|
| [Commands](reference/commands.md) | Every command, with its arguments, options and exit codes |
| [Configuration](reference/configuration.md) | Global flags, `OSSIQ_*` environment variables, the config file, GitHub tokens, and the hosts a scan calls |

```{toctree}
:hidden:
:maxdepth: 1

reference/commands
reference/configuration
```

## What you get back

| Page | Look here for |
|---|---|
| [Console and HTML reports](reference/reports.md) | Every column, marker and `↳` row of `ossiq status`, `ossiq info` and the HTML report |
| [JSON export and agent format](reference/export-and-agent-format.md) | Every field of the `ossiq export` file, the `--format agent` decision, and the MCP tools |

```{toctree}
:hidden:
:maxdepth: 1

reference/reports
reference/export-and-agent-format
```

## What decided it

| Page | Look here for |
|---|---|
| [Update rules](reference/update-rules.md) | The five update strategy tiers, the version ladder, and the solver's cooldown, CVE, peer and override rules |
| [Constraints, overrides and aliases](reference/constraints.md) | The five constraint types, pip and uv constraint settings, npm `overrides` and npm package aliases |

```{toctree}
:hidden:
:maxdepth: 1

reference/update-rules
reference/constraints
```

## What you can build on

| Page | Look here for |
|---|---|
| [Python API](reference/python-api.md) | `scan()`, `ScanResult`, `ScanRecord`, `Settings` and the other types you can import |
| [Stability guarantees](reference/stability.md) | What stays the same across releases: the export schema, the CLI interface and repeatable scans |

```{toctree}
:hidden:
:maxdepth: 1

reference/python-api
reference/stability
```

## Common lookups

| You have | Go to |
|---|---|
| An option such as `--update-strategy` or `--pin-all` | [Commands](reference/commands.md) |
| An exit status, such as 75 | [Exit codes](reference/commands.md#exit-codes) |
| `OSSIQ_GITHUB_TOKEN`, or a question about which token a scan uses | [Token precedence](reference/configuration.md#token-precedence) |
| A label under *What's Next* | [What's Next labels](reference/reports.md#whats-next-labels) |
| `[NO RESOLUTION]`, `↳ ⚠` or another row under a package | [Sub-rows](reference/reports.md#sub-rows) |
| `✗ violation` or a `missing peer` row | [Peer Constraint Status](reference/reports.md#peer-constraint-status) |
| A field that is missing from your export | [Profiles](reference/export-and-agent-format.md#profiles) |
| A `next_action` an agent received | [Agent format](reference/export-and-agent-format.md#agent-format) |
| A recommendation older than the latest version | [Cooldown](reference/update-rules.md#cooldown) |
| `recommended_from_rung`, `latest_in_range` | [Version ladder](reference/update-rules.md#version-ladder) |
| `constraint_type: OVERRIDE` | [The five constraint types](reference/constraints.md#the-five-constraint-types) |
