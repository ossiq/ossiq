---
title: JSON export and agent format
description: "The two machine-readable outputs of OSS IQ: the JSON file ossiq export writes, field by field, and the compact decision that --format agent and the MCP tools return."
---

# JSON export and agent format

OSS IQ has two machine-readable outputs: the JSON file `ossiq export` writes, and the compact
decision that `--format agent` and the MCP tools return. Part of the
[reference](../reference.md).

| You have | Go to |
|---|---|
| A key at the root of the export | [Root object](#root-object) |
| A field on a package entry | [Package fields](#package-fields) |
| A field that is missing from your export | [Profiles](#profiles) and [Schema versions](#schema-versions) |
| An entry in a `cve` array | [CVE fields](#cve-fields) |
| A `next_action` an agent received | [Agent format](#agent-format) |
| An MCP tool to call | [MCP tools](#mcp-tools) |

In both outputs, `null` means the value could not be measured. It never means "no risk".

## JSON export

`ossiq export` writes one `.json` file. Its options are in
[Commands](commands.md#export). To gate CI on it, see the
[GitHub Actions tutorial](../tutorials/tutorial-github-actions.md).

### Profiles

| Profile | Written by | Carries | Schema |
|---|---|---|---|
| Standard | `ossiq export` | Every direct dependency, the transitive packages that need attention, and the fields needed to decide what to do | [v1.6 standard](../../src/ossiq/ui/renderers/export/schemas/export_schema_v1.6_standard.json) |
| Full | `ossiq export --full` | Every transitive package, the dependency tree, provenance URLs and the raw upstream signals | [v1.6](../../src/ossiq/ui/renderers/export/schemas/export_schema_v1.6.json) |

`metadata.profile` names the profile. The schema files list every field; the tables on this page
say what each one means. A field marked *(`--full`)* appears in the full profile only.

### Schema versions

`--schema-version` pins the document to one version. The default is the latest, `1.6`.

| Version | Adds |
|---|---|
| `1.6` | `registry_status`, `deprecation_message`, `constraint_ossiq_authored` and `unresolved_peers` on package entries; `strategy.widening_authorized`; `peer_repairs` at the root |
| `1.5` | The baseline. Schemas: [standard](../../src/ossiq/ui/renderers/export/schemas/export_schema_v1.5_standard.json), [full](../../src/ossiq/ui/renderers/export/schemas/export_schema_v1.5.json) |

A document pinned to `1.5` omits every field `1.6` added. For what stays stable across
versions, see [Stability guarantees](stability.md#export-schema-stability).

### Root object

| Key | Contents |
|---|---|
| `metadata` | `schema_version`, `profile`, `export_timestamp`, `update_strategy`, `data_completeness` (the status of each external source) and `warnings` |
| `project` | `name`, `path` and `registry` |
| `runtime_context` | The runtime that engine requirements were checked against: `engine_versions`, `engine_context_source` (`provided`, `detected`, `declared` or `none`), `npm_cli_version`, `project_declares_esm` and `runtime_mismatch` |
| `summary` | Counts: packages by role, `packages_with_cves`, `total_cves`, `packages_outdated`, `project_epss`, and how many packages are unmaintained, deprecated or unmeasured |
| `production_packages` | Array of `PackageMetrics` |
| `development_packages` | Array of `PackageMetrics` |
| `transitive_packages` | Array of `TransitivePackageMetrics`, one for each package and installed version. The standard profile keeps only the entries that need attention |
| `ignored_packages` | Declared dependencies the scan left out, each with `name`, `spec` and `reason` |
| `upgrade_paths` | Constraint-widening opportunities for a project without a lockfile |
| `manifest_lock_divergent` | Names of packages whose manifest entry and lockfile entry disagree. Regenerate the lockfile before you act on their recommendation |
| `peer_repairs` | Peers installed out of reach, and how `ossiq apply` puts them back (npm). See [Peer fields](#peer-fields) |
| `dependency_tree` | *(`--full`)* The tree under each direct production dependency. Each node points at a `transitive_packages` entry through `ref` |
| `constraint_type_map` | *(`--full`)* Lookup for the `ct` integer on a tree node: `0` `DECLARED`, `1` `NARROWED`, `2` `PINNED`, `3` `ADDITIVE`, `4` `OVERRIDE` |

## Package fields

Every entry in `production_packages` and `development_packages` is a `PackageMetrics` object.
[Transitive entries](#transitive-entries) carry most of the same fields.

### Identity and drift fields

| Field | Meaning |
|---|---|
| `package_name` | Canonical registry name |
| `dependency_name` | Name the manifest uses, when it is an [npm alias](#npm-package-aliases); otherwise `null` or the same as `package_name` |
| `is_optional_dependency` | The package is a development or optional dependency |
| `installed_version` | Version resolved in the lockfile |
| `latest_version` | Newest version the registry publishes |
| `time_lag_days` | Days between the publish dates of the installed and the latest version |
| `releases_lag` | Releases published between the installed and the latest version |
| `version_age_days` | *(`--full`)* Days since the installed version was published |
| `extras` | PyPI extras requested, for example `["security"]` |
| `repo_url`, `homepage_url`, `package_url`, `license`, `purl` | *(`--full`)* Provenance: repository, homepage and registry URLs, SPDX license identifiers, and the Package URL |

### Recommendation fields

| Field | Meaning |
|---|---|
| `recommended_version` | Version the solver recommends. `null` when the package is already at the best version |
| `recommended_from_rung` | [Version ladder](#version-ladder) rung the recommendation came from: `solver`, `in_range`, `in_major` or `latest` |
| `requires_constraint_widening` | `true` when the rung is `in_major` or `latest`, so the target lies outside the declared range. `ossiq apply` writes it only when the tier is `latest` or `cutting-edge`, or `strategy.widening_authorized` is `true` |
| `next_action` | The label the *What's Next* column and the HTML report show. `null` when nothing is due. See [What's Next labels](reports.md#whats-next-labels) |
| `strategy` | The [update strategy](#update-strategy) verdict: `motives`, `withheld_reason`, `requires_widening`, `escalation`, `widening_authorized`. `null` when the selector did not run for the package |
| `latest_in_range` | Newest version the declared range admits. Equal to `installed_version` when the range admits nothing newer |
| `latest_in_major` | Newest version on the installed major line, under the same rule |
| `latest_compatible_major` | Newest version, on the installed major or a later one, with no known module-system or API break |
| `latest_preserving_module_system` | Newest version that code on the installed module system can still load, whatever the runtime |
| `rejected_candidates` | Releases that would have been recommended but were held back, each with `version` and `reason`. At most one for each ladder rung |
| `update_transitive_impacts` | What the recommended update does to transitive packages: `package_name`, `current_version`, `projected_version`, `new_constraint`, `driven_by`, `has_conflict`, `conflict_detail` |

### Compatibility fields

These describe the recommended version.

| Field | Meaning |
|---|---|
| `module_system` | Module format of the installed version: `esm-only`, `cjs` or `dual`. npm only |
| `recommended_module_system` | Module format of the recommended version. npm only |
| `module_system_note` | What the scan's runtime means for loading the package's ESM-only releases from CommonJS code |
| `breaking_change` | Why the recommended version is flagged as a known break, for example `ESM-only from 5.0.0` |
| `engine_requirement` | Runtime the recommended version requires, for example `{"node": ">=20.19.0"}` |
| `engine_compatible` | `false` when `engine_requirement` conflicts with `runtime_context`. `null` means no evidence either way |

### Constraint fields

| Field | Meaning |
|---|---|
| `constraint_type` | `DECLARED`, `NARROWED`, `PINNED`, `ADDITIVE` or `OVERRIDE`. See [The five constraint types](constraints.md#the-five-constraint-types) |
| `constraint_ossiq_authored` | `true` when the `OVERRIDE` is one OSS IQ wrote, not yours. `constraint_type` stays `OVERRIDE` either way. See [npm: `overrides`](#npm-overrides) |
| `version_constraint_declared` | Version specifier your manifest declares. `null` for an unconstrained dependency |
| `version_constraint` | *(`--full`)* Effective specifier the solver used. Read `version_constraint_declared` for what your manifest says |
| `constraint_source_file` | *(`--full`)* File that introduced a non-`DECLARED` constraint, for example `package.json` |
| `dependency_path` | *(`--full`)* Ancestor chain from the root; `null` for a direct dependency |

A report from before v1.2 has no `constraint_type`. The HTML report's Explorer then falls back
to the specifier: a bare version such as `1.2.3` counts as `PINNED`, and a specifier that
contains `<` counts as `NARROWED`.

### Lifecycle fields

| Field | Meaning |
|---|---|
| `is_prerelease` | The installed version is a pre-release |
| `is_yanked` | The installed version was yanked or unpublished |
| `is_deprecated` | The installed version, or the whole package, is deprecated or archived |
| `is_package_unpublished` | The whole package was removed from the registry (npm only) |
| `registry_status` | The registry's verdict on the whole package: `active`, `deprecated`, `archived` or `quarantined`. `null` when the registry gave none, which is not the same as `active`. npm reports `deprecated` when the `latest` release is deprecated; PyPI reports its [PEP 792](https://peps.python.org/pep-0792/) status |
| `deprecation_message` | The maintainer's note (npm) or the index's stated reason (PyPI), verbatim. It often names the replacement |

### Security and maintenance fields

| Field | Meaning |
|---|---|
| `cve` | Known vulnerabilities in the installed version. See [CVE fields](#cve-fields) |
| `epss` | Highest EPSS score among the package's CVEs |
| `runs_code_at_install`, `install_execution_reason` | Whether installing the version executes code, and what indicated it |
| `dependency_health_action` | Advisory verdict of the triage matrix: `retain`, `patch`, `refactor` or `evict`. It answers "is this dependency healthy long-term?"; `next_action` says what to do now |
| `maintenance_state` | Most probable state: `maintained`, `winding_down`, `abandoned` or `deprecated` |
| `maintenance_risk` | P(abandoned) + P(deprecated), the value that feeds triage |
| `deprecation_signals`, `deprecation_successor` | End-of-life markers found for the package, and the replacement they name |
| `archived` | The upstream repository is archived |
| `maintenance_coverage` | *(`--full`)* Fraction of the maintenance observations that were available |
| `gap_cv`, `median_gap_days`, `silence_days`, `silence_p`, `commits_sampled`, `span_days` | *(`--full`)* Commit-gap measurements from the repository's last 100 commits |
| `flow_trend`, `engagement_buckets` | *(`--full`)* Direction of the issue and pull-request flow, and the raw buckets behind it |
| `days_since_push` | *(`--full`)* Days since the last push to the upstream repository |

[Repository stability](../explanation/repository-stability.md) explains the maintenance fields.

(peer-fields)=
### Peer fields (npm)

| Field | Meaning |
|---|---|
| `unresolved_peers` | Peers the package declares that nothing installed *where the package looks* satisfies. Each has `package_name`, `spec`, `optional` and `installed_elsewhere` |
| `peer_repairs` (root) | How `ossiq apply` puts such peers back. Each has `package_name` and `suggested_constraint` to add to the manifest, `is_dev_dependency`, the `requirers` that need it, and `family_moves` |

Both are empty for PyPI projects. See [Unresolved peers](#unresolved-peers).

### Transitive entries

A `TransitivePackageMetrics` entry differs from `PackageMetrics` in these ways:

- **It adds `required_by`:** the direct dependencies whose subtree installs the package. These
  are the manifest entries to change to move it. The full profile also adds `id`, which tree
  nodes reference.
- **It leaves out** `dependency_name`, `dependency_path`, `version_constraint`,
  `version_constraint_declared`, `constraint_type`, `extras`, `breaking_change`,
  `recommended_from_rung`, `requires_constraint_widening`, `update_transitive_impacts` and
  `strategy`. In the full profile, `dependency_tree` holds the paths and constraints.
- **It omits a field that could not be determined,** where a direct entry carries `null`.

### CVE fields

| Field | Meaning |
|---|---|
| `id` | Primary identifier: a CVE, GHSA or OSV ID |
| `cve_ids` | All aliases for the vulnerability |
| `severity` | `LOW`, `MEDIUM`, `HIGH` or `CRITICAL` |
| `summary` | Description of the vulnerability |
| `affected_ranges` | Affected intervals in the registry's own syntax, for example `>=12.0.0 <12.0.1`. A release inside any of them is affected |
| `fixed_in` | Releases that close an affected interval. Empty when no fix is published |
| `fix_age_days` | Days a fix has been available |
| `epss` | EPSS exploitation probability, 0 to 1 |
| `link` | URL of the upstream advisory |
| `source`, `package_name`, `package_registry`, `published` | *(`--full`)* Reporting database, affected package, its registry, and the publication date |
| `affected_versions` | *(`--full`)* Versions the advisory enumerates. Always empty for npm; read `affected_ranges` |

A CVE on a transitive package appears on its entry in `transitive_packages`. `required_by`
names the direct dependencies that pull the package in.

## Agent format

`ossiq status --format agent` and `ossiq info --format agent` print a compact JSON decision in
place of the console report. `ossiq update-context` always prints one. The
[MCP tools](#mcp-tools) return the same shapes. To set an agent up, see
[Coding agents](../getting-started.md#coding-agents).

### `next_action`

Every decision leads with a `next_action` string.

| Decision | From | Values |
|---|---|---|
| Add | `info`, `add`, `ossiq_evaluate_dependency` | `install`, `install with caution` or `do not install` |
| Update, on each entry | `status`, `ossiq_evaluate_updates` | A [What's Next label](reports.md#whats-next-labels), or `no action needed` |
| Update, at the top level | `status`, `ossiq_evaluate_updates` | The most urgent entry label, or `no action needed` |

`do not install` covers a package its registry deprecated, archived or quarantined, and a
deprecated release you asked for by version. `reasons` quotes the registry's note.

An update entry's label can differ from `next_action` in the JSON export, because the agent
format escalates two cases:

- A CVE that the recommended version does not clear reads `Check for the Fix`.
- An installed version that is gone from the registry, with nothing else due, reads
  `Find alternative`.

### Update entries

The `updates` list has one entry for each direct dependency.

| Field | Meaning |
|---|---|
| `from`, `to` | The installed version and the target |
| `latest_in_range`, `latest_in_major` | The [version ladder](#version-ladder) |
| `requires_constraint_widening` | `true` when `to` is reachable only by widening the declared range. `plan` reports the pick under *Requires constraint widening* and does not write it, unless the tier is `latest` or `cutting-edge` |
| `widening_authorized` | `true` when a CVE or end-of-life motive carried the pick past its tier. `apply` writes it after its widening confirmation |
| `motives` | Why the tier let the package move |
| `dependency_health` | The triage verdict (`retain`, `patch`, `refactor` or `evict`), with a `question` that says what it answers: long-term health, not what to do now |
| `cves` | The package's CVEs, each with its `epss` when scored |
| `unresolved_peers` | npm only. Peers the package cannot load, whatever its `next_action`. Each has `package`, `spec`, `optional` and `installed_elsewhere` |

The decision also carries `update_strategy`, and on npm `peer_repairs` when a copy that
satisfies the range is installed out of reach. Each repair has the `package` and
`suggested_constraint` that `apply` adds to the manifest, `is_dev_dependency`, the `requirers`,
and the `family_moves`. `unresolved_peers` and `peer_repairs` are omitted when empty. Run
`ossiq plan` to review a repair and `ossiq apply` to make it.

### Runtime

Engine requirements are checked against the runtime the project runs on.

| Caller | Where the runtime comes from |
|---|---|
| MCP tools | The required `runtime` argument: `{"node": "22.12.0"}`, `{"python": "3.11"}`, or the string `"unknown"`. A missing `runtime` returns a "Runtime Not Provided" error; the MCP server never probes its own `PATH` |
| CLI | A probe of the installed runtime (`--probe-runtime`, on by default), or `--engine node=20.11.0` to state it |

Either way, the version is held to the floor the project declares. `engine_context_source` reads
`provided` when a stated version binds.

OSS IQ also reads the project's own version pin: `.nvmrc`, `.node-version`, `.tool-versions`,
`mise.toml`, `volta.node`, `.python-version` or `.venv/pyvenv.cfg`. A pin that disagrees with the
runtime is reported as `runtime_context.runtime_mismatch`, and as a warning in `status`.

### `update-context` comparison

`ossiq update-context` and `ossiq_update_context` also return `comparison`, which judges the
target you asked about against OSS IQ's own recommendation:

| Field | Meaning |
|---|---|
| `verdict` | `recommended`, `suboptimal`, `breaking`, `vulnerable`, `deprecated` or `beyond_recommendation` |
| `reasons` | Why the verdict is what it is |
| `better_available` | The version to take instead |

## MCP tools

`ossiq mcp` serves three read-only tools. Every tool requires `runtime`
(see [Runtime](#runtime)).

| Tool | Answers | Required | Optional |
|---|---|---|---|
| `ossiq_evaluate_dependency` | Should the agent add this package? | `package`, `runtime` | `version`, `project_path`, `registry_type` |
| `ossiq_evaluate_updates` | Which direct dependencies should move, and to what? | `project_path`, `runtime` | `production`, `update_strategy`, `strategy_overrides`, `allow_partial` |
| `ossiq_update_context` | What breaks between the installed version and this target? | `package`, `runtime` | `target_version`, `project_path`, `registry_type` |

Nothing changes in the project until you run `ossiq apply` and confirm.
