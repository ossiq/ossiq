---
title: Stability guarantees
description: "What you can rely on when you build on OSS IQ: export schema versions that never rename or remove a field, stable command and flag names, and repeatable scans."
---

# Stability guarantees

OSS IQ makes four commitments to anyone who depends on its output in CI pipelines, scripts or
other tools. Part of the [reference](../reference.md).

| Commitment | In one line |
|---|---|
| [Export schema stability](#export-schema-stability) | Within a schema version, fields are never renamed or removed |
| [CLI interface stability](#cli-interface-stability) | Command names, flag names and exit codes change only through a deprecation |
| [Deterministic analysis](#deterministic-analysis) | The same inputs give the same output |
| [Metric deprecation](#metric-deprecation) | A deprecated field keeps its meaning until the next major schema version |

## Export schema stability

`schema_version` in the `metadata` block identifies the schema version of an export, for example
`"1.6"`. `ossiq export --schema-version` pins the output to one version. The available versions
are `1.5` and `1.6`, and the default is the latest.

A pinned document never carries a field that a later version added, so pinning `1.5` keeps
producing exactly the v1.5 shape.

Within a schema version:

- Existing fields are never renamed or removed.
- New optional fields can be added. Existing consumers are unaffected.

These rules hold from the release that ships a version. Until then, a version can still change.

When a schema version is deprecated, the previous version stays fully supported for at least
one major release cycle. The changelog announces the deprecation before the version is removed.

For the fields of each version, see
[JSON export](export-and-agent-format.md#json-export).

## CLI interface stability

Command names, flag names and exit codes are stable interfaces. A change follows the same
deprecation policy as schema versions: the old form keeps working, with a deprecation warning,
before it is removed.

## Deterministic analysis

Given the same lockfile and the same version of OSS IQ, a scan produces the same output. You can
run OSS IQ as a blocking CI gate and diff the results of two runs.

:::{note}
Two things outside OSS IQ change a result between runs:

- **Upstream data.** Registries and source code providers can remove a version or a repository
  at any time.
- **The date.** Version ages, the cooldown, EPSS scores and maintenance signals are measured
  against the day of the scan. To hold the published versions to a past date, pass
  `--cutoff-date`.
:::

## Metric deprecation

A deprecated field or metric keeps appearing in exports, with its original meaning, until the
next major schema version. Its removal comes with a migration note that names the replacement.
