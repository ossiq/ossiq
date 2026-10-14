---
title: Constraints, overrides and aliases
description: "The five constraint types OSS IQ reports, how it reads pip constraint files, uv constraint and override settings and npm overrides, and how it tracks npm package aliases."
---

(constraint-provenance)=
# Constraints, overrides and aliases

`constraint_info` on a dependency records what controls its version beyond a plain manifest
entry: a pin, a constraints file or an override. Part of the [reference](../reference.md).

Most packages are installed the normal way: a manifest declares them, the resolver picks a
version, and the lockfile records it. This page covers the other cases. For why they matter, see
[Constraint provenance](../explanation/constraint-provenance.md).

| You have | Go to |
|---|---|
| A `constraint_type` value | [The five constraint types](#the-five-constraint-types) |
| A `-c constraints.txt` line | [pip: `-c` constraint files](#pip-constraint-files) |
| `constraint-dependencies` or `override-dependencies` | [uv: constraints and overrides](#uv-constraints-and-overrides) |
| An `overrides` block in `package.json` | [npm: `overrides`](#npm-overrides) |
| An `npm:<name>@<range>` specifier | [npm: package aliases](#npm-package-aliases) |

## The five constraint types

When several rules apply to one package, the highest wins: `OVERRIDE` > `ADDITIVE` > `PINNED` >
`NARROWED` > `DECLARED`.

| `ConstraintType` | Meaning | Set by | What it signals |
|---|---|---|---|
| `OVERRIDE` | A setting forces a version, whatever the dependency graph declares | npm `overrides`; uv `override-dependencies` | Removing or changing the override is the only fix |
| `ADDITIVE` | A separate file or setting narrows the allowed range without adding the package as a direct dependency | pip `-c constraints.txt`; uv `constraint-dependencies` | Whoever owns that file controls the update |
| `PINNED` | Exactly one version is allowed: `==x.y.z` (PyPI) or a bare `x.y.z` (npm) | An exact pin in the manifest | Automatic updates are blocked |
| `NARROWED` | A range with an upper bound: `>=x <y`, `~=x`, `==x.*` or a compound specifier | An upper bound in the manifest | The bound excludes newer versions |
| `DECLARED` | A loose specifier: any version, caret (`^x`), tilde (`~x`) or lower bound only (`>=x`) | The default | No constraint beyond normal resolution |

The same values appear as `constraint_type` in the
[JSON export](export-and-agent-format.md#constraint-fields), as node colors in the
[HTML report](reports.md#html-report), and as *Constraint Type* in
[`ossiq info`](reports.md#policy-compliance). `ConstraintSource` also carries:

| Field | Meaning |
|---|---|
| `source_file` | File that introduced a non-`DECLARED` constraint |
| `scope_path` | Ancestor chain a scoped npm override applies under; `None` for a flat override |
| `override_key`, `override_value` | The key and value of the npm override rule that governs the package |

(pip-constraint-files)=
## pip: `-c` constraint files

pip's [`-c` flag](https://pip.pypa.io/en/stable/reference/requirements-file-format/) in `requirements.txt` references a separate constraints file. Packages listed there are not installed as direct dependencies — they only narrow the version range for anything the resolver would pull in anyway.

```text
# requirements.txt
-c constraints.txt
requests==2.31.0
```

When OSS IQ encounters a `-c` directive, it reads the referenced file and tags every package that appears in both the resolved dependencies and the constraints file with `ConstraintType.ADDITIVE`. The `source_file` field is set to the `requirements.txt` that introduced the `-c` directive. Nested `-c` includes are followed recursively; circular includes are detected and skipped.

A package tagged `ADDITIVE` in pip classic means: something outside your direct dependency list is controlling its allowed version range. If a CVE hits that package, check whether the constraint file is the thing blocking the update.

(uv-constraints-and-overrides)=
## uv: `constraint-dependencies` and `override-dependencies`

uv exposes two settings under `[tool.uv]` in `pyproject.toml`:

- [`constraint-dependencies`](https://docs.astral.sh/uv/reference/settings/#constraint-dependencies) — PEP 508 specifiers that narrow allowed versions without adding direct dependencies. These map to `ConstraintType.ADDITIVE`.
- [`override-dependencies`](https://docs.astral.sh/uv/reference/settings/#override-dependencies) — PEP 508 specifiers that force a version regardless of what the dependency graph declares. These map to `ConstraintType.OVERRIDE`.

```toml
# pyproject.toml
[tool.uv]
constraint-dependencies = ["h11>=0.14.0"]
override-dependencies = ["urllib3==1.26.18"]
```

The distinction matters: a `constraint-dependencies` entry cooperates with the normal resolver — it adds a lower bound, an upper bound, or an exclusion. An `override-dependencies` entry *overrules* it. If a package under `override-dependencies` is later found vulnerable in the forced version, no amount of updating its parents will help — the override itself is the thing to remove.

Both lists are read from `pyproject.toml` at scan time. Matched packages in the resolved dependency tree are tagged accordingly, with `source_file` set to `pyproject.toml`.

(npm-overrides)=
## npm: `overrides`

npm's [`overrides`](https://docs.npmjs.com/cli/v9/configuring-npm/package-json#overrides) field in `package.json` forces a specific version (or range) for a matching package anywhere in the dependency tree, regardless of what each package's own `dependencies` declaration says.

```json
// package.json
{
  "overrides": {
    "semver": "^7.5.2",
    "lodash": {
      "dot-prop": "^6.0.1"
    }
  }
}
```

OSS IQ reads the `overrides` block from `package.json` (npm does not copy it into `package-lock.json`) and tags every installed copy of a matching package with `ConstraintType.OVERRIDE`, adding an `overridden` category to its `categories` list.

A *scoped* override forces a version only when the package appears as a dependency of a specific parent. For these, the `scope_path` field on `ConstraintSource` records the ancestor chain. In the preceding example, `dot-prop` carries `scope_path: ["lodash"]`: the override applies only when `lodash` pulls in `dot-prop`. A flat override like `semver` has `scope_path: null`.

The `scope_path` matters for remediation: a scoped override targeting `dot-prop` inside `lodash` does not affect `dot-prop` when pulled in by other packages. Removing it may leave `dot-prop` under `lodash` unprotected, or free it to resolve a patched version — depending on which direction the version was being forced.

### A rule may be keyed to a version range

`"minimatch@^9.0.0": "9.0.9"` forces only the edges whose range overlaps `^9.0.0`; a nested `minimatch` 10 elsewhere in the tree is left alone. OSS IQ marks each installed copy the rule governs — one the version sits inside the key of, or already at the value of — and records the rule's key and value on `ConstraintSource` (`override_key`, `override_value`). A `$name` value follows the root dependency of that name.

### Overrides decide whether an update is possible

npm nests a further copy of a package when a dependent's range cannot share the installed one, so an ordinary requirement never stops an update. An override does: it forces one version whatever the dependent declares. When a candidate needs a version an override *you* wrote rules out, the release is rejected and the override is named (`@vue/shared is held by an override in package.json`), and `plan` lists it under *Held by overrides you wrote*. OSS IQ never rewrites those; update or remove them to let the release through. An override OSS IQ wrote itself (recorded under `ossiq:metadata`) moves with the candidate instead, together with every other override that candidate's packages pin to each other.

### An override OSS IQ wrote is not flagged

OSS IQ records the rules it writes under `ossiq:metadata` (npm) or `[tool.ossiq.metadata]` (uv). While a rule still holds the recorded value, it is OSS IQ's to move: on npm, `ossiq apply` retires it and writes a fresh rule for the new version. So `status` shows no `⚑ override` marker for it, the Peer Constraint Status table reads `✓ satisfied` instead of `✓ via override`, and the HTML report draws the package as a plain dependency. `ossiq info` still names the rule, as `OVERRIDE (written by OSS IQ, from package.json)`. A rule you wrote, or edited since OSS IQ did, is yours and stays flagged. The JSON export keeps `constraint_type` at `OVERRIDE` and adds `constraint_ossiq_authored`.

### Peers are held to what the package declares, overrides or not

npm applies `overrides` to peer edges too. With `"typescript": "$typescript"`, npm installs the version your manifest names beside `@typescript-eslint/*` even when their peer range stops below it, and reports no `ERESOLVE`: the override silences npm's check, it does not make the pair compatible. OSS IQ reads the ranges packages *declare*, not the ones an override leaves them with, so it keeps refusing that release (see *Held by peer dependencies* in the [recommendation catalogue](../recommendations/catalogue.md#the-non-recommendations)). An override whose only job was to quiet that check can be removed.

### Family moves are keyed to a range

When OSS IQ moves a whole lockstep family it writes the key as the range from the old version to the new, `"@vue/shared@3.5.42 - 3.5.43": "3.5.43"`. A key naming only the old version would match nothing once every member of the family asks for the new one, and npm would nest further copies instead of moving the hoisted one.

### Matching is by exact tree name

An override entry is matched against packages by the literal name npm registered them under in the lockfile — not the package's canonical registry name. This matters for [package aliases](#npm-package-aliases): an override keyed `"chalk": "4.1.2"` tags a plain `chalk` dependency, but does nothing to `"chalk-legacy": "npm:chalk@4.1.2"`, because that alias is registered as `chalk-legacy`, not `chalk`. To override an aliased package, key the `overrides` entry with the alias name.

(npm-package-aliases)=
## npm: package aliases

npm lets a `package.json` entry install one real package under a different name, using `"npm:<real-name>@<range>"` as the version specifier:

```json
// package.json
{
  "dependencies": {
    "chalk-legacy": "npm:chalk@4.1.2",
    "chalk": ">4.1.2 <=5.3.0"
  }
}
```

This is how a project runs two versions of the same package side by side — commonly during a major-version migration, or when one dependency needs an old API another consumer has already moved past.

### Each alias is tracked as its own entry, with its own recommendation

`ScanRecord.package_name` holds the canonical name, which is `chalk` for both entries in the preceding example. `ScanRecord.dependency_name` holds the name `package.json` uses: `chalk-legacy` and `chalk`.

The two occurrences never share a recommendation. `chalk-legacy` is held at `4.1.2` because its own alias range pins it there, while plain `chalk` is free to move up to `5.3.0`. The solver still evaluates candidate versions for the underlying `chalk` package once, and both entries draw from the same candidate set.

That per-alias fitting also applies to the solver's [cooldown](#cooldown-rule). When the shared candidate falls outside one alias's own range, OSS IQ re-fits that alias to the newest version that satisfies its range. Like the solver, it still prefers a version older than the cooldown period when one exists. If no published version satisfies an alias's own range, that alias gets no recommendation; it never inherits a sibling's.

### Console output names the alias

The `status` and `plan` tables and the `apply` acknowledgement prompt all print the *Package* column as `chalk-legacy (chalk)` — the manifest key, with the canonical name after it — so two occurrences of one package are never two identical rows. `ossiq info <alias-name>` matches on the alias name directly and opens that one occurrence; `ossiq info <real-name>` matches every occurrence — aliased or not — and lists each as a separate `Occurrence n of m` block. In machine-readable output the two names stay separate fields: `package_name` is always canonical, and `dependency_name` carries the manifest key (in the JSON export always, in `--format agent` and the MCP tools only when it differs).

### `--override` accepts either spelling

`--override chalk-legacy==4.2.0` forces that one alias and leaves its siblings on their own recommendations. `--override chalk==4.2.0` names every occurrence at once, so on a project with several aliases of one package OSS IQ says which manifest keys it found and forces none of them — name the key to pick one. `--strategy-override` is canonical-only: `--strategy-override chalk=latest` retiers every occurrence, and an alias key is reported as not found rather than silently ignored.

### `plan` / `apply` cannot rewrite an alias's inner range

The update solver still computes a recommendation for each alias, but `apply` cannot write it back to `package.json` for an `npm:pkg@range` specifier. It leaves the alias entry untouched. Use the recommendation as a manual target and edit the alias range yourself.
