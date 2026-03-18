
# Reference


## Data Model

The `ossiq` domain model is located in the `ossiq.domain` module. It defines the core entities used for analysis.

### Project

A software project being analyzed. Each `Project` contains a `name` and lists of its direct production and development `dependencies`.

For full details, see [`ossiq/domain/project.py`](https://github.com/ossiq/ossiq/tree/main/src/ossiq/domain/project.py).

### Package

A dependency of a `Project`. A `Package` is defined by its `name` and contains a list of all its available `versions`.

For full details, see [`ossiq/domain/package.py`](https://github.com/ossiq/ossiq/tree/main/src/ossiq/domain/package.py).

### Version Models

The version-related models capture details from different sources and are aggregated into a single `Version` object.

The primary `Version` object aggregates `package_data` (from a package registry) and `repository_data` (from a source code repository). Other data classes like `Commit` and `User` provide granular detail about the source code history.

For a complete definition of all version-related data classes, see [`ossiq/domain/version.py`](https://github.com/ossiq/ossiq/tree/main/src/ossiq/domain/version.py).

---

## System Behavior

### Dependency Resolution

-   **Dependency Graph**: The system operates on a flat list of dependencies resolved from a lockfile (e.g., `package-lock.json`).
-   **Transitive Dependencies**: Transitive dependency resolution is not performed. The tool relies on the dependency resolution of the target project's native package manager (e.g., `npm`, `pip`, `uv`).

### Data Provenance

Package metadata is sourced from ecosystem-specific repositories (e.g., npm registry, PyPI). This is handled by a set of adapters in the `ossiq.adapters` module (e.g., `ossiq.adapters.api_npm`).

### Analysis Output

A single analysis run produces a `ProjectMetrics` object.

**Class**: `ossiq.service.project.ScanResult`

**Description**: Contains an analysis of each dependency, including version lags, time lags, and associated vulnerabilities.


## Data Sources

OSS IQ aggregates data from the following public sources:

| Source | Purpose |
|---|---|
| [OSV](https://osv.dev/) | Open-source vulnerability database (CVEs, security advisories) |
| [ClearlyDefined](https://clearlydefined.io/) | License and curation data for open-source packages |
| [NPM Registry](https://www.npmjs.com/) | Package metadata and version history for JavaScript packages |
| [PyPI](https://pypi.org/) | Package metadata and version history for Python packages |
| [GitHub](https://github.com/) | Repository activity, releases, and maintainer signals |


## Outputs

OSS IQ produces three categories of analysis — metrics, security, and supply chain exposure — delivered across four output formats.

### Metrics

Each dependency produces a `PackageMetrics` record with the following measurements:

| Metric | Field | Description |
|---|---|---|
| Version lag | `time_lag_days` | Days elapsed since `latest_version` was published |
| Release lag | `releases_lag` | Releases between `installed_version` and `latest_version` |
| Drift status | — | Semantic classification: MAJOR, MINOR, PATCH, LATEST, or NO_DIFF |

#### Metrics Operationalization

`time_lag_days` and `releases_lag` are deterministic numbers. Teams use them to define thresholds that match their risk tolerance and enforce them automatically in CI.

A typical starting point:

| Threshold | Field | Recommended starting value |
|---|---|---|
| Maximum version age | `time_lag_days` | 365 days |
| Maximum release distance | `releases_lag` | — (use `time_lag_days` first) |

Use the JSON export to evaluate thresholds in a CI step:

```bash
# Fail if any production package is more than 365 days behind
MAX_LAG_DAYS=365
jq --argjson max "$MAX_LAG_DAYS" \
  '[.production_packages[] | select(.time_lag_days != null and .time_lag_days > $max)] | length' \
  ossiq-report.json
```

Start with a permissive threshold to baseline your project, then tighten it incrementally as tech debt is resolved. This avoids blocking CI on day one while still creating measurable improvement targets.

For a complete GitHub Actions setup with CVE gating and outdated-package blocking, see the [Version Lag and CVE Quality Gate tutorial](/tutorials/tutorial-github-actions.md).

### Security

Each `PackageMetrics` record contains a `cve` array. Each entry includes:

| Field | Description |
|---|---|
| `id` | Primary vulnerability identifier (CVE, GHSA, or OSV ID) |
| `cve_ids` | All aliases for this vulnerability (CVE, GHSA, OSV IDs) |
| `source` | Database that reported the vulnerability |
| `severity` | LOW, MEDIUM, HIGH, or CRITICAL |
| `summary` | Description of the vulnerability |
| `affected_versions` | List of affected version strings |
| `published` | Publication date (ISO 8601, nullable) |
| `link` | URL to the upstream advisory |

**Transitive CVEs.** When a transitive dependency has CVEs, OSS IQ surfaces them in the `transitive_packages` array. The `dependency_path` field on each entry traces the ancestor chain from the project root to the affected package.

### Supply Chain Exposure

OSS IQ identifies two version constraint risk patterns using the `version_constraint` field:

| Risk | Condition | Signal |
|---|---|---|
| Pinned version | `version_constraint` is an exact version (e.g. `1.2.3`) | Prevents automatic updates |
| Upper-bound constraint | `version_constraint` contains `<` | Actively excludes newer versions |

### Output Formats

#### Console — Scan Table

The `scan` command prints two dependency tables — one for production packages, one for development — to the terminal. Each row shows `package_name`, CVE count, drift status, `installed_version`, `latest_version`, `releases_lag`, and `time_lag_days`.

#### Console — Package Detail

The `package` command prints a six-section report for a single dependency:

1. **Drift status** — version comparison with an ASCII time-lag progress bar
2. **Dependency tree trace** — ancestor path from the project root to the package
3. **Policy compliance** — `version_constraint`, resolved version, and latest version
4. **Security advisories** — per-CVE `severity`, `id`, source, and `summary`
5. **Via transitive dependencies** — CVEs inherited from entries in `transitive_packages`
6. **Licenses** — SPDX identifiers from the `license` field

#### HTML Report

The `scan --presentation html` command produces a self-contained HTML file embedding an interactive Vue.js single-page application. The report includes the full dependency tables and the **Transitive Dependency Explorer**: an interactive D3 tree that visualises the `transitive_packages` dependency graph.

The Explorer supports:

- Color-coded nodes by risk type (CVE, pinned version, upper-bound constraint)
- Fuzzy search and toggle filters (CVE, Pinned, UBC)
- Click to focus a node and highlight all ancestor and descendant paths
- Alt+Click to collapse or expand a subtree
- Dashed curved links between nodes sharing an identical `package_name@installed_version`
- Zoom and pan

For full Explorer interaction details, see [EXPLORER.md](https://github.com/ossiq/ossiq/blob/main/frontend/EXPLORER.md).

#### JSON Export

The `export --output-format json` command writes a single `.json` file conforming to [export schema v1.1](../src/ossiq/ui/renderers/export/schemas/export_schema_v1.1.json). The root object contains:

| Key | Contents |
|---|---|
| `metadata` | `schema_version` and `export_timestamp` |
| `project` | `name`, `path`, and `registry` |
| `summary` | Aggregate counts: packages, CVEs, outdated |
| `production_packages` | Array of `PackageMetrics` |
| `development_packages` | Array of `PackageMetrics` |
| `transitive_packages` | Array of `PackageMetrics` with `dependency_path` set |

#### CSV Export

The `export --output-format csv` command writes a folder named `export_{project_name}/` containing three files and a [Frictionless Data](https://frictionlessdata.io/) descriptor:

| File | Contents |
|---|---|
| `summary.csv` | One row of project metadata and aggregate counts |
| `packages.csv` | One row per package with all `PackageMetrics` fields |
| `cves.csv` | One row per CVE with all `CVEInfo` fields |
| `datapackage.json` | Schema references and foreign key relationships |

## Versioning & Stability Guarantees

OSS IQ makes four commitments to users who depend on its output in CI pipelines, scripts, or downstream tooling.

### Export Schema Stability

Each export schema version is identified by `schema_version` in the `metadata` block (e.g. `"1.1"`). The `export --schema-version` flag pins output to a specific version.

Within a schema version:

- Existing fields are never renamed or removed.
- New optional fields may be added — existing consumers are unaffected.

When a schema version is deprecated, the previous version remains fully supported for at least one major release cycle. Deprecation is announced in the changelog before the version is removed.

### CLI Interface Stability

Command names, flag names, and exit codes are considered stable interfaces. Changes follow the same deprecation policy as schema versions: the old form continues to work with a deprecation warning before it is removed.

### Deterministic Analysis

Given the same lockfile and the same version of OSS IQ, a scan always produces the same output. This makes OSS IQ safe to run as a blocking CI gate and suitable for diffing results between runs.

:::{note}
Package registries and source code providers may remove versions or repositories at any time. OSS IQ cannot control this. Scan results may differ between runs if upstream data changes.
:::

:::{note}
Risk scores are time-dependent by design. The same lockfile analyzed at different points in time will produce different scores. A CVE's risk weight increases the longer it remains unpatched (survival analysis). A new library with high release activity signals different risk than an established library with a stable, slow release cycle &mdash; and that signal shifts as the library matures.
:::


### Metric Deprecation

When a field or metric is deprecated, it continues to appear in exports with its original semantics until the next major schema version. Removal is always accompanied by a migration note describing the replacement field or approach.
