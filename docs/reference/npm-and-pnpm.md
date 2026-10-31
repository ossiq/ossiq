---
title: npm and pnpm projects
description: "How OSS IQ tells an npm project from a pnpm one, which files it reads, and what apply and add write and run for each package manager."
---

# npm and pnpm projects

OSS IQ scans and updates JavaScript projects that use npm or pnpm. Both install from the npm
registry, so the analysis is the same for both. What differs is the files OSS IQ reads and writes,
and the command it runs to install. Part of the [reference](../reference.md).

## How OSS IQ picks the package manager

OSS IQ checks for pnpm first:

1. If `package.json` declares a manager, in `packageManager` (`"pnpm@10.4.1"`) or in
   `devEngines.packageManager`, OSS IQ uses that one.
2. If it declares none, a `pnpm-lock.yaml` or `pnpm-workspace.yaml` beside it makes the project a
   pnpm project.
3. Otherwise, a `package.json` makes it an npm project. The lockfile is optional.

A declaration wins over files, so a leftover `pnpm-lock.yaml` in a project that declares npm
does not make OSS IQ run pnpm. The `plan` header names the manager OSS IQ detected:

```text
───────────────────── OSS IQ — Plan: pnpm-workspace-config ─────────────────────
  Package Manager: pnpm  |  Direct: 0  |  Transitive: 0
...
Held by overrides you wrote — OSS IQ never rewrites those; update or remove them
to let these through:
  Override    Forces     Declared in            Keeps back
  lodash      4.17.21    pnpm-workspace.yaml    lodash@4.18.1
```

## Files OSS IQ reads

| | npm | pnpm |
|---|---|---|
| Manifest | `package.json` | `package.json` |
| Lockfile | `package-lock.json`, `lockfileVersion` 2 or 3 | `pnpm-lock.yaml`, `lockfileVersion` 9.0 (written by pnpm 9 and later) |
| Overrides you wrote | `overrides` in `package.json` | The `overrides` that pnpm records in `pnpm-lock.yaml` |
| Catalog ranges | — | `catalog:` ranges, as `pnpm-lock.yaml` records them |
| Release cutoff | — | `minimumReleaseAge` and `minimumReleaseAgeExclude` |

Overrides and package aliases follow the same rules under both managers. See
[Constraints, overrides and aliases](constraints.md).

## What `apply` and `add` write and run

| | npm | pnpm |
|---|---|---|
| Direct dependency | Range rewritten in `package.json` | Range rewritten in `package.json`, or in the catalog in `pnpm-workspace.yaml` for a `catalog:` dependency |
| Transitive pick | `overrides` entry in `package.json` | `overrides` entry in `pnpm-workspace.yaml` |
| Record of what OSS IQ wrote | `ossiq:metadata` in `package.json` | `ossiq:metadata` in `package.json` |
| `apply` runs | `npm install --ignore-scripts` | `pnpm install --ignore-scripts --no-frozen-lockfile` |
| Every [install pass](commands.md#install-passes) but the last adds | `--package-lock-only` | `--lockfile-only` |
| `add` runs | `npm install --ignore-scripts <package>@<version>` | `pnpm add --ignore-scripts <package>@<version>` |
| Restored when a run fails | `package.json`, `package-lock.json` | `package.json`, `pnpm-lock.yaml`, `pnpm-workspace.yaml` |
| New dependencies held to the cooldown | No. The plan flags young ones with `⚠` | Yes, through `minimumReleaseAge`. See [Cooldown](../explanation/cooldown.md#pnpm-holds-new-dependencies-to-the-cooldown) |

Both managers run without install scripts. A package that needs a postinstall step (a native build
or a downloaded binary, as with esbuild, sharp or prisma) needs `npm rebuild <name>` or
`pnpm rebuild <name>` afterwards.

Under pnpm, `apply` also checks that every target landed. When pnpm installed a different version
than the plan picked, the run ends with "Update Incomplete".

## Limits

- **`apply` and `add` need pnpm 10 or later on your `PATH`.** Without it, the run stops and leaves
  the project files as they were.
- **Older lockfiles are not read.** npm's `lockfileVersion` 1 and pnpm lockfiles older than 9.0
  stop the scan with a parsing error.
- **OSS IQ scans only the root project of a pnpm workspace.** It reads the root importer (`.`) of
  `pnpm-lock.yaml` and skips packages in other workspace folders.
- **OSS IQ reports an override from `package.json` as declared in `pnpm-workspace.yaml`.** pnpm 9
  and 10 also read overrides from the `pnpm` field of `package.json`, and OSS IQ labels those with
  the workspace file too.
