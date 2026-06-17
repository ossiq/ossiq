
# Reference


## Public API

ossiq exposes a stable library interface for programmatic use. Install without extras for the core scanner (`pip install ossiq`); install with `[cli]` to also get the terminal CLI (`pip install 'ossiq[cli]'`).

```python
from ossiq import scan, ScanResult, ScanRecord, Settings, CVE, Package, VersionsDifference, unit_of_work
```

### `scan(uow)`

```python
def scan(uow: unit_of_work.AbstractProjectUnitOfWork) -> ScanResult
```

Runs a full dependency health scan against the project described by `uow`. Fetches package metadata, CVEs, and version history from the appropriate registry; runs the SAT solver to produce update recommendations; and returns a `ScanResult`. Must be called inside the `uow` context manager.

```python
from ossiq import scan, Settings, unit_of_work
from ossiq.unit_of_work.uow_project import ProjectUnitOfWork

settings = Settings.load_from_env()
uow = ProjectUnitOfWork(settings, project_path=".")
result = scan(uow)
```

### `ScanResult`

Aggregated output of a single scan run. Returned by `scan()`.

| Field | Type | Description |
|---|---|---|
| `project_name` | `str` | Name from the project manifest |
| `project_path` | `str` | Absolute path to the project root |
| `packages_registry` | `str` | Registry used (`"npm"` or `"pypi"`) |
| `production_packages` | `list[ScanRecord]` | Direct production dependencies |
| `optional_packages` | `list[ScanRecord]` | Dev / optional dependencies |
| `transitive_packages` | `list[ScanRecord]` | Indirect dependencies |
| `manifest_lock_divergent` | `list[str]` | Package names where the manifest and lockfile disagree |
| `upgrade_paths` | `list[UpgradePath]` | Cross-constraint widening opportunities (library projects only) |

### `ScanRecord`

Per-package analysis record. Each entry in the `ScanResult` lists above is one `ScanRecord`.

| Field | Type | Description |
|---|---|---|
| `package_name` | `str` | Canonical package name |
| `installed_version` | `str` | Version currently installed |
| `latest_version` | `str \| None` | Most recent published version |
| `recommended_version` | `str \| None` | Solver-recommended update target |
| `recommended_version_reason` | `RecommendationReason \| None` | Why this version was chosen |
| `time_lag_days` | `int \| None` | Days between installed and latest version |
| `releases_lag` | `int \| None` | Number of releases between installed and latest |
| `versions_diff_index` | `VersionsDifference` | Semantic drift classification |
| `cve` | `list[CVE]` | Known vulnerabilities for the installed version |
| `version_constraint` | `str \| None` | Version specifier from the manifest |
| `constraint_info` | `ConstraintSource` | How the version was constrained (see Constraint Provenance) |
| `dependency_path` | `list[str] \| None` | Ancestor chain for transitive packages |
| `update_transitive_impacts` | `list[TransitiveImpact]` | How updating this package affects transitive deps |
| `peer_violations` | `list[PeerRequirement]` | Peer requirements the installed version fails to satisfy |
| `constraint_conflict` | `list[str]` | Conflicting constraints that blocked the solver |
| `purl` | `str \| None` | Package URL (PURL) identifier |
| `license` | `list[str] \| None` | SPDX license identifiers |

### `Settings`

Pydantic model holding runtime configuration. Load from environment variables with `Settings.load_from_env()` or construct directly.

| Field | Default | Description |
|---|---|---|
| `github_token` | `None` | GitHub personal access token for repository enrichment |
| `cache_destination` | `~/.ossiq_cache.sqlite3` | Path to the SQLite HTTP cache |
| `cache_ttl` | `24` | Cache time-to-live in hours |
| `verbose` | `False` | Emit detailed progress output |
| `debug` | `False` | Enable debug logging |
| `cutoff_date` | `None` | Treat versions published after this date as invisible |
| `cooldown_period` | `7` | Days a new version must age before the solver recommends it |

All fields can be set via environment variables prefixed with `OSSIQ_` (e.g. `OSSIQ_GITHUB_TOKEN`).

### `CVE`

A single vulnerability record attached to a `ScanRecord`.

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Primary identifier (CVE, GHSA, or OSV ID) |
| `cve_ids` | `tuple[str, ...]` | All aliases for this vulnerability |
| `severity` | `Severity` | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `summary` | `str` | Human-readable description |
| `affected_versions` | `tuple[str, ...]` | Version strings confirmed vulnerable |
| `published` | `str \| None` | ISO 8601 publication date |
| `link` | `str` | URL to the upstream advisory |

### `Package`

Metadata about a package as returned by its registry.

| Field | Type | Description |
|---|---|---|
| `name` | `str` | Registry name |
| `canonical_name` | `str \| None` | Normalised name (lowercased, hyphens unified) |
| `latest_version` | `str \| None` | Most recent stable release |
| `repo_url` | `str \| None` | Source code repository URL |
| `homepage_url` | `str \| None` | Project homepage |
| `license` | `str \| None` | SPDX license string |
| `is_deprecated` | `bool` | Package has been deprecated by its maintainer |
| `is_unpublished` | `bool` | Package has been removed from the registry |

### `VersionsDifference`

Semantic drift classification between two versions.

| Field | Type | Description |
|---|---|---|
| `diff_index` | `int` | Numeric severity: 0 = no diff, 1 = patch, 2 = minor, 3 = major, 4 = build, 5 = prerelease |
| `diff_name` | `str` | Human-readable label: `"LATEST"`, `"PATCH"`, `"MINOR"`, `"MAJOR"`, etc. |

### `unit_of_work`

Module alias for `ossiq.unit_of_work.core`. Exposes `AbstractProjectUnitOfWork`, the base class for the scan context. Use `ossiq.unit_of_work.uow_project.ProjectUnitOfWork` (the concrete implementation) to construct a scan context for a real project on disk.

```python
from ossiq.unit_of_work.uow_project import ProjectUnitOfWork

uow = ProjectUnitOfWork(
    settings=settings,
    project_path="/path/to/project",
    production=True,          # production deps only
    ignore_packages=("pytest",),
)
with uow:
    result = scan(uow)
```

---

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

## Constraint Provenance

Most packages in a scan report were installed the normal way: a manifest declared them, the resolver picked a version, and the lockfile recorded it. The `ConstraintSource` field on a `Dependency` tracks when that was *not* the case — when an extra mechanism outside the normal dependency graph was controlling the version.

### The five constraint types

Priority ordering (highest wins when multiple rules apply): `OVERRIDE` > `ADDITIVE` > `PINNED` > `NARROWED` > `DECLARED`.

| `ConstraintType` | What it means | How it gets set |
|---|---|---|
| `DECLARED` | Loose specifier in the manifest: open (`any`), caret (`^x`), tilde (`~x`), or lower-bound only (`>=x`). | Default |
| `NARROWED` | Explicit range with an upper bound in the manifest: `>=x <y`, `~=x`, `==x.*`, or a compound specifier. | Version specifier in the manifest contains an upper bound. |
| `PINNED` | Exactly one version allowed: `==x.y.z` (PyPI) or a bare `x.y.z` (npm). | Exact-version pin in the manifest. |
| `ADDITIVE` | A separate file or setting narrowed the allowed version range without adding the package as a direct dependency. | pip `-c constraints.txt`; uv `constraint-dependencies`. |
| `OVERRIDE` | A setting forced a specific version, bypassing what the normal dependency graph would have resolved. | npm `overrides`; uv `override-dependencies`. |

### Why you need to watch this

When a normal dependency becomes vulnerable, the fix is straightforward: update it, the resolver picks a patched version, done. Constraints and overrides break that flow. They impose version rules *from outside* the normal dependency graph. A constraint can pin a transitive package to a range that still contains a vulnerable version — and nothing in the lock file makes this obvious. You can stare at the lockfile, see `h11==0.13.0`, and have no idea that a rule somewhere else is preventing you from resolving `0.14.0`.

This is the failure mode described in [Against Upper-Bound Version Constraints in Libraries](https://iscinumpy.dev/post/bound-version-constraints/): once a constraint caps a package below a patched version, *you* cannot fix it unilaterally. The person who wrote the constraint has to release a patch first. At scale, with many transitive constraints scattered across `pyproject.toml` entries and nested overrides, this creates invisible debt that surfaces only when a CVE forces a full audit.

The key insight: **a constraint doesn't just describe what version is installed — it describes who has the power to change it.** An `OVERRIDE` means someone decided this package's own version declarations don't matter. An `ADDITIVE` constraint means a separate authority is narrowing the resolution space. Both are worth tracking separately from ordinary declared dependencies.

OSS IQ surfaces `constraint_info` so you can see which packages are under a constraint, what kind of constraint, and which file introduced it — before a CVE forces you to find out.

### Constraint provenance by package manager

#### pip classic — `-c` constraint files

pip's [`-c` flag](https://pip.pypa.io/en/stable/reference/requirements-file-format/) in `requirements.txt` references a separate constraints file. Packages listed there are not installed as direct dependencies — they only narrow the version range for anything the resolver would pull in anyway.

```
# requirements.txt
-c constraints.txt
requests==2.31.0
```

When OSS IQ encounters a `-c` directive, it reads the referenced file and tags every package that appears in both the resolved dependencies and the constraints file with `ConstraintType.ADDITIVE`. The `source_file` field is set to the `requirements.txt` that introduced the `-c` directive. Nested `-c` includes are followed recursively; circular includes are detected and skipped.

A package tagged `ADDITIVE` in pip classic means: something outside your direct dependency list is controlling its allowed version range. If a CVE hits that package, check whether the constraint file is the thing blocking the update.

#### uv — `constraint-dependencies` and `override-dependencies`

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

#### npm — `overrides`

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

OSS IQ reads the `overrides` block from `package-lock.json` (where npm records the resolved overrides) and tags matching packages with `ConstraintType.OVERRIDE`, adding an `overridden` category to their `categories` list.

For *scoped* overrides — where a version is forced only when a package appears as a dependency of a specific parent — the `scope_path` field on `ConstraintSource` records the ancestor chain. In the example above, `dot-prop` would carry `scope_path: ["lodash"]`, meaning the override applies only when `dot-prop` is pulled in by `lodash`. A flat override like `semver` has `scope_path: null`.

The `scope_path` matters for remediation: a scoped override targeting `dot-prop` inside `lodash` does not affect `dot-prop` when pulled in by other packages. Removing it may leave `dot-prop` under `lodash` unprotected, or free it to resolve a patched version — depending on which direction the version was being forced.

---

## System Behavior

### Dependency Resolution

-   **Dependency Graph**: The system operates on a flat list of dependencies resolved from a lockfile (e.g., `package-lock.json`).
-   **Transitive Dependencies**: Transitive dependency resolution is not performed. The tool relies on the dependency resolution of the target project's native package manager (e.g., `npm`, `pip`, `uv`).

### Update Solver (`plan` / `apply`)

-   **Single pass.** The solver recommends versions against the *current* lockfile. Applying a plan
    re-resolves the tree, which can surface further recommendations; re-run `plan` until it reports
    no updates (most projects converge in one or two passes).
-   **Cooldown.** Candidate versions younger than `--cooldown-period` days (default 7) receive a
    heavy soft-penalty in the solver; recommendations that are still younger than the cooldown after
    solving are withheld into the plan's *Held for cooldown* section and never applied.
-   **CVE bypass.** When the installed version of a package carries a CVE, its recommendation is
    exempt from the cooldown hold. CVE-affected candidate versions themselves are hard-forbidden.
-   **New transitive dependencies.** Packages entering the tree for the first time are resolved by
    the native package manager at apply time, outside the cooldown. The plan projects their version
    and age and flags entries younger than the cooldown with `⚠`. Under `--cutoff-date`, projections
    exclude versions published after the cutoff for deterministic time-travel runs.
-   **Forced versions (`--override pkg==version`).** Bypass the solver and the cooldown for one
    package. Persistence per ecosystem:

| Ecosystem | Direct dependency | Transitive dependency |
|---|---|---|
| npm | specifier rewritten to the exact version | persistent `overrides` entry in `package.json` |
| uv | specifier rewritten to `==version` | persistent `override-dependencies` entry under `[tool.uv]` |
| pip classic | constraints-file pin for the run | constraints-file pin for the run (not persistent) |

    Forced packages are reported with `ConstraintType.OVERRIDE` on subsequent scans, so they remain
    visible until the override is removed.

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

OSS IQ surfaces constraint risk through the `constraint_type` field on each `PackageMetrics` record. Five tiers are recognized, ordered from highest to lowest concern:

| Risk tier | `constraint_type` | Signal |
|---|---|---|
| Override | `OVERRIDE` | Version forced outside the dependency graph — removing the override is the only fix |
| Additive constraint | `ADDITIVE` | A separate constraints file is narrowing the range; the constraint file owner controls the update |
| Pinned version | `PINNED` | Exactly one version allowed — automatic updates are blocked |
| Narrowed range | `NARROWED` | An upper bound in the manifest actively excludes newer versions |
| Declared | `DECLARED` | Loose specifier; no constraint risk beyond normal dependency resolution |

For reports produced by OSS IQ before v1.2 (which lack a `constraint_type` field), the Explorer and export consumers fall back to heuristics on the `version_constraint` string: a bare semver (e.g. `1.2.3`) is treated as `PINNED`; a specifier containing `<` is treated as `NARROWED`.

### Output Formats

#### Console — Scan Table

The `status` command prints two dependency tables — one for production packages, one for development — to the terminal. Each row shows `package_name`, CVE count, drift status, `installed_version`, `latest_version`, `releases_lag`, and `time_lag_days`.

#### Console — Package Detail

The `info` command prints a six-section report for a single dependency:

1. **Drift status** — version comparison with an ASCII time-lag progress bar
2. **Dependency tree trace** — ancestor path from the project root to the package
3. **Policy compliance** — `version_constraint`, resolved version, and latest version
4. **Security advisories** — per-CVE `severity`, `id`, source, and `summary`
5. **Via transitive dependencies** — CVEs inherited from entries in `transitive_packages`
6. **Licenses** — SPDX identifiers from the `license` field

#### HTML Report

The `status --presentation html` command produces a self-contained HTML file embedding an interactive Vue.js single-page application. The report includes the full dependency tables and the **Transitive Dependency Explorer**: an interactive D3 tree that visualises the `transitive_packages` dependency graph.

The Explorer supports:

- Color-coded nodes by risk type — six priority tiers: CVE (red), OVERRIDE (orange dash-dot), ADDITIVE (green dotted), PINNED (orange solid-thick), NARROWED (yellow dashed), DECLARED (blue)
- Fuzzy search and toggle filters (CVE, Narrowed, Override/Pinned)
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
