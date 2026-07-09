
# Reference


## Public API

ossiq exposes a stable library interface for programmatic use. Install without extras for the core scanner (`pip install ossiq`); install with `[cli]` to also get the terminal CLI (`pip install 'ossiq[cli]'`).

```python
from ossiq import scan, ScanResult, ScanRecord, Settings, CVE, Package, VersionsDifference, AbstractProjectSources
```

### `scan(sources)`

```python
def scan(sources: AbstractProjectSources) -> ScanResult
```

Runs a full dependency health scan against the project described by `sources`. Fetches package metadata, CVEs, and version history from the appropriate registry; runs the SAT solver to produce update recommendations; and returns a `ScanResult`. Must be called inside the `sources` context manager.

```python
from ossiq import scan, Settings
from ossiq.sources.project_sources import ProjectSources

settings = Settings.load_from_env()
sources = ProjectSources(settings, project_path=".")
with sources:
    result = scan(sources)
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
| `cache_destination` | `~/.ossiq/cache.sqlite3` | Path to the SQLite HTTP cache |
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

### `AbstractProjectSources`

Base class for the scan context, exported from `ossiq.sources.core`. Use `ossiq.sources.project_sources.ProjectSources` (the concrete implementation) to construct a scan context for a real project on disk.

```python
from ossiq.sources.project_sources import ProjectSources

sources = ProjectSources(
    settings=settings,
    project_path="/path/to/project",
    production=True,          # production deps only
    ignore_packages=("pytest",),
)
with sources:
    result = scan(sources)
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

(update-solver)=
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

#### Console

The `status` command prints a project-wide report; the `info` command prints a deep-dive for a single package. Every section, column, and status marker of both reports is documented in [Console Reports](#console-reports).

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

The `export --output-format json` command writes a single `.json` file conforming to [export schema v1.4](../src/ossiq/ui/renderers/export/schemas/export_schema_v1.4.json) by default. The root object contains:

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

(console-reports)=
## Console Reports

This section describes the terminal output of `ossiq-cli status` (project-wide report) and `ossiq-cli info` (single-package report): what each part shows, what each column and status marker means, and what to do when a marker signals a problem.

### `status` — project report

```bash
ossiq-cli status [PROJECT_PATH]
```

The report has up to six parts, printed in this order. Parts with nothing to show are omitted.

1. **Header** — project name, registry (`npm` or `pypi`), path, and counts: production packages, development packages, and transitive packages with an update recommendation.
2. **Dependency table** — one row per direct dependency, grouped into *Production* and *Development* sections.
3. **Transitive Recommendations** — transitive packages the solver recommends updating.
4. **New transitive dependencies** — packages that would enter the tree if the recommended updates were applied.
5. **Peer Constraint Status** — peer dependency requirements and whether the installed versions satisfy them (npm projects only).
6. **Constraint Widening Opportunities** — for library projects, dependency ranges that could safely be widened.

#### Dependency table

| Column | Meaning |
|---|---|
| Package | Package name. |
| CVEs | Number of known vulnerabilities affecting the installed version. Empty when there are none. |
| Status | Semantic drift between installed and latest version: `Latest`, `Patch`, `Minor`, `Major`, `Prerelease`, `Build`, or `N/A` when the latest version is unknown. |
| Installed | Version resolved in the lockfile, with a lifecycle marker when one applies (see below). |
| Recommended | Solver-recommended update target. The column appears only when at least one package has a recommendation or a constraint conflict. Yellow when the recommendation is older than the latest version — usually held back by the [cooldown](#update-solver) or by a constraint. `[NO RESOLUTION]` when no published version satisfies all constraints. |
| Latest | Most recent published version, or `N/A` when the registry reports none. |
| Lag | Time between the installed and the latest version. Red when it exceeds `--lag-threshold-delta` (default `1y`). |

Lifecycle markers on the Installed column:

| Marker | Meaning |
|---|---|
| `[UNPUBLISHED]` | The installed version has been removed from the registry. |
| `[YANKED]` | The installed version was yanked by its maintainer. |
| `[DEPRECATED]` | The installed version, or the whole package, is deprecated. |
| `[pre]` | The installed version is a pre-release. |

A row with a recommendation can carry indented sub-rows describing what applying that recommendation would do to the rest of the dependency tree:

| Sub-row | Meaning |
|---|---|
| `↳ <package> <current> → <projected>` | Updating the parent also moves this transitive package. When more than three packages would move, a count is shown instead of the list. |
| `+ <package> <version> (new dep)` | Updating the parent introduces this package into the tree. Listed with full detail in **New transitive dependencies**. |
| `↳ ⚠ <package>: <detail>` | The update collides with a constraint on this transitive package. See [When an update is blocked](#update-blocked). |
| `✗ no actionable update found` | Every candidate update collides with a transitive constraint; the solver has no version to recommend. See [When an update is blocked](#update-blocked). |
| `↳ no version satisfies: <specifiers>` | The constraints on this package contradict each other — no published version satisfies all of them at once. Shown together with `[NO RESOLUTION]`. |

#### Transitive Recommendations

Transitive packages — packages your direct dependencies pull in — for which the solver recommends a different version, most often because the installed version carries a CVE or is far behind. With `--security`, the list narrows to packages with CVEs only. To turn these recommendations into an executable update plan, run `ossiq-cli plan` (see [Update Solver](#update-solver)).

| Column | Meaning |
|---|---|
| Package | Transitive package name. |
| Installed | Version currently resolved in the lockfile. |
| CVEs | Number of known vulnerabilities for the installed version. |
| Age | Age of the installed version. Red past one year. |
| Recommended | Version the solver recommends within all parent constraints. |

#### New transitive dependencies

Packages that are not in the tree today but would be pulled in by the recommended updates. Their versions are resolved by the native package manager at apply time, outside the solver's cooldown hold, so fresh entries are flagged rather than withheld: a `⚠` before the package name means the projected version is younger than the cooldown period and deserves a look before you apply (see [Cooldown as Supply-Chain Quarantine](explanation.md#cooldown-as-supply-chain-quarantine) for why).

| Column | Meaning |
|---|---|
| Package | New package name, prefixed with `⚠` when younger than the cooldown period. |
| Version | Version the package manager is projected to resolve. |
| Constraint | Version range declared by the package that requires it. |
| Age | Age of the projected version, in days. |
| Required By | The direct dependency whose update introduces this package. |

(peer-constraint-status)=
#### Peer Constraint Status

npm packages can declare `peerDependencies`: versions of *other* packages they expect to find installed next to them but do not install themselves (the classic example is a plugin declaring which framework versions it works with). npm enforces these at install time, but overrides, `--legacy-peer-deps`, and `--force` installs can leave the tree in a state npm never checked. OSS IQ re-validates every peer requirement against the lockfile on every scan. PyPI has no peer dependency mechanism, so this table only appears for npm projects.

| Column | Meaning |
|---|---|
| Package | The package the requirement applies to. |
| Installed | Its installed version. |
| Peer Constraint | The version range the requirer expects. |
| Required By | The package that declares the peer requirement. |
| Status | One of the three values below. |

| Status | Meaning |
|---|---|
| `✓ satisfied` | The installed version is inside the required range. |
| `✓ via override` | The installed version satisfies the range, but it is forced by an `overrides` entry rather than resolved normally. The override — not the resolver — is what keeps this pair compatible; re-check this row whenever the override changes. |
| `✗ violation` | The installed version is outside the range the requirer declared. |

**What `✗ violation` means.** Two packages you ship disagree about a third. The requirer was built and tested against the declared peer range; running it against a version outside that range can fail at runtime — missing exports, changed APIs — even though installation succeeded. Typical causes: an `overrides` entry forcing a version out of range, an install with `--legacy-peer-deps` or `--force`, or one package updated past what its peers allow.

Recovery paths, from most to least preferred:

1. **Update the requirer.** A newer release of the *Required By* package may accept the installed version. `ossiq-cli info <requirer>` shows whether one exists and what constrains it.
2. **Move the violated package into the range.** Upgrade or downgrade it to a version inside the peer constraint — after checking that nothing else in the tree needs the version you are moving away from.
3. **Remove or adjust the override** when one is the cause. See [Constraint Provenance](#constraint-provenance) for how overrides are tracked.
4. **Accept it knowingly.** If you have verified the pair works together, you can leave it — the row keeps appearing on every scan as a standing reminder.

#### Constraint Widening Opportunities

Shown for library projects only: dependency ranges in your manifest whose upper bound excludes versions that already exist and resolve cleanly.

| Column | Meaning |
|---|---|
| Package | Direct dependency with a narrowed range. |
| Current Range | The range declared in the manifest today. |
| Latest In-Range | Newest version the current range allows. |
| Latest Available | Newest version published on the registry. |
| Suggested Range | Widened range that admits the latest available version. |

(update-blocked)=
### When an update is blocked by a transitive constraint

Sometimes you cannot move a direct dependency forward even though a newer version exists. A direct dependency is one node in a graph: each of its versions declares its own requirements on transitive packages, and other parents in your tree constrain those same packages. The solver recommends a version only when the whole subtree still resolves.

A concrete case: your project depends on `A` and `B`. `A 2.0` requires `C >= 3`, but the latest `B` still requires `C < 3`. No version of `C` satisfies both, so `A` cannot reach 2.0. The report shows `A` with a newer *Latest*, a *Recommended* that stays behind (or none), and a `↳ ⚠ C: …` sub-row naming the collision. `✗ no actionable update found` means every candidate version of `A` hits such a collision. `[NO RESOLUTION]` with `↳ no version satisfies: …` is the harder variant: the constraints already contradict each other in the current tree, before any update.

Your options, roughly in order:

1. **Wait for upstream.** The owner of the blocking constraint (here `B`) has to publish a release that widens its range — you cannot fix their constraint unilaterally. This is the failure mode described in [Constraint Provenance](#constraint-provenance); `ossiq-cli info <blocking package>` shows who declares the constraint.
2. **Update or replace the other parent.** A newer version of `B` may already accept `C >= 3`; if `B` is abandoned, replacing it removes the constraint entirely.
3. **Force the version:** `ossiq-cli apply --override pkg==version` bypasses the solver for one package. You take on the compatibility risk the constraint was protecting against; the override persists in your manifest and is reported as `OVERRIDE` on every subsequent scan until removed (see [Update Solver](#update-solver)).
4. **Stay put deliberately.** The current version keeps resolving. The report keeps showing the lag, so the debt stays visible instead of silent.

### `info` — package report

```bash
ossiq-cli info PACKAGE_NAME [PROJECT_PATH]
```

A deep-dive into one package. When the package is installed in the project, the report has the sections below, in order; empty sections are omitted. When it is not installed, the report switches to [prospective mode](#info-prospective).

**Header.** Package name and installed version; role tags `DIRECT` and/or `TRANSITIVE` (both, when the package appears in both roles); a lifecycle marker (`[UNPUBLISHED]`, `[YANKED]`, `[DEPRECATED]`, `[pre]` — same meanings as in the status table); license; registry URL.

**Warnings.** A panel of package health findings: `✗` marks critical findings (these block `ossiq-cli add` unless `--force` is passed), `!` marks notices. Examples: a package with a single published version (typosquatting risk), a single maintainer (bus-factor risk).

**Health Metrics.** Registry-level signals: downloads over the last month, number of published versions, maintainer count, age of the latest version, age of the recommended version (when it differs from the latest), and cooldown remaining — days until the latest release is old enough to clear the [cooldown period](explanation.md#cooldown-as-supply-chain-quarantine).

**Occurrences.** A package can appear in the tree more than once — for example as a direct dependency and, at a different version, as a transitive one. Each occurrence gets its own block of the five sections below, labelled `Occurrence n of m`.

**Drift Status.** Status (same values as the status table), installed version, latest version, time lag (red past 180 days), and how many releases behind the installed version is.

**Dependency Tree.** The ancestor path from the project root down to this package (`← you are here`). For a direct dependency the path is just `root → package`; for a transitive one it names every intermediate package — useful for seeing *which* direct dependency is responsible for pulling this package in.

**Policy Compliance.** How the installed version relates to the rules that produced it:

| Row | Meaning |
|---|---|
| Constraint | Version specifier from the manifest, or `—` for transitive packages without one. |
| Resolved | The installed version. |
| Latest | Most recent published version. |
| Recommended | Solver-recommended target, when one exists. Yellow when held below the latest. |
| Resolution | `NO VALID VERSION — conflicting constraints: <specifiers>` when the solver found no version satisfying all constraints. See [When an update is blocked](#update-blocked). |
| Constraint Type | Shown only when the version is controlled by something beyond a plain manifest entry (`PINNED`, `NARROWED`, `ADDITIVE`, `OVERRIDE`), with the file that introduced it. See [Constraint Provenance](#constraint-provenance). |

**Recommendation Rationale.** Why the solver picked the recommended version — and, just as important, why it rejected the others:

- *Eliminated (hard constraints)* — versions that can never be chosen: outside a parent's range, affected by a CVE, yanked, or pre-release without `--allow-prerelease`.
- *Penalised (soft constraints)* — versions that remain eligible but are scored down, e.g. younger than the cooldown period.
- The closing `✓` line states the selection: the latest eligible version, or the best stable candidate when the latest was eliminated or penalised.

If the version you expected is not the recommendation, this section names the exact rule that removed it.

**Peer Requirements.** Every peer constraint other packages place on this one, with the same markers as the status report's [Peer Constraint Status](#peer-constraint-status) table: `✓` satisfied, `✓ … via override`, `✗` violated (the installed version is shown in red next to the violated range). The recovery paths are the same too.

**Security Advisories.** Known vulnerabilities in the installed version of *this* package: severity, advisory ID, source database, and summary — or `✓ No known vulnerabilities`.

**Transitive CVEs.** Vulnerabilities in packages *downstream* of this one — exposure you carry because this package pulls the affected ones in. Grouped per affected `package@version`, worst severity first. Updating this package may or may not resolve them; run `ossiq-cli info <affected package>` to see what constrains each one.

**Licenses.** Listed only when the package's occurrences carry more than one SPDX identifier; a single unambiguous license is already shown in the header.

(info-prospective)=
#### Prospective mode

When the package is not installed in the project, `info` evaluates it as a candidate instead: the header carries a `PROSPECTIVE` tag and the registry description, followed by health metrics, the recommendation rationale, and security advisories. This is the same pre-installation check that `ossiq-cli add` runs before installing.

### Agent format

Both commands accept `--format agent`, which replaces the human report with a compact JSON verdict (`ok` / `warn` / `block`) for AI coding agents and scripts. See [AI Agent Integration](getting-started.md#ai-agent-integration-mcp--skills).

(install-skills)=
## Install Skills

```bash
ossiq-cli install skills [TOOL] [--github-token TOKEN] [--dev PATH]
```

Installs the OSS IQ skill and a local MCP server so AI coding agents check dependency health before they add or update a package. For the task-oriented walkthrough, see [AI Agent Integration](getting-started.md#ai-agent-integration-mcp--skills).

| Argument / option | Default | Description |
|---|---|---|
| `TOOL` | `all` | Which tool to install for: `claude`, `codex`, `copilot`, or `all`. |
| `--github-token`, `-T` | — | GitHub token to store during installation (see [GitHub token handling](#install-skills-token)). When omitted, the command prompts for one interactively; leave the prompt blank to skip. |
| `--dev` | — | Path to a local ossiq-cli source checkout. Switches the installed skill and MCP server to run from that checkout instead of the PyPI release (see [Development mode](#install-skills-dev)). |

### What the command writes

All changes are made under your home directory; the command never touches the current project.

| Tool | Skill | MCP server |
|---|---|---|
| `claude` | writes `~/.claude/skills/ossiq/SKILL.md` | adds an `ossiq` entry to `mcpServers` in `~/.claude/mcp.json` |
| `codex` | writes `~/.codex/skills/ossiq/SKILL.md` | adds an `ossiq` entry to `mcpServers` in `~/.codex/mcp.json` |
| `copilot` | inserts a fenced block into `~/.copilot/copilot-instructions.md` | — (Copilot has no MCP server registry) |

The MCP entry registers a **local stdio server** — the tool launches `ossiq-cli mcp` as a subprocess on your machine. No remote service is involved, and nothing is sent anywhere beyond the registry and GitHub API calls a normal scan makes.

The command is **idempotent** — safe to re-run at any time (for example after changing the token or switching development mode on or off):

- `mcp.json` is merged: only the `ossiq` entry under `mcpServers` is replaced; every other server entry is preserved.
- The Copilot instructions block is delimited by `<!-- ossiq-skill:start -->` / `<!-- ossiq-skill:end -->` markers. On re-run the block between the markers is replaced; the rest of the file — including your own instructions — is untouched.

(install-skills-token)=
### GitHub token handling

OSS IQ uses the token only to raise the GitHub API rate limit from 60 to 5 000 requests per hour; **no scopes or permissions are needed**. See [GitHub Personal Access Token](getting-started.md#github-personal-access-token) for how to create a read-only one.

The token is resolved in this order:

1. The `--github-token` / `-T` option.
2. An interactive prompt. Leaving it blank skips token setup entirely — everything else still installs, and you can re-run the command later to add a token.

When a token is provided, it is written to **two places**, in plain text:

| Location | Purpose |
|---|---|
| `~/.ossiq/config` — as an `OSSIQ_GITHUB_TOKEN=…` line (dotenv format) | Used by every `ossiq-cli` invocation, including ones you run yourself. |
| The `env` block of the `ossiq` entry in each tool's `mcp.json` | Passed to the MCP server subprocess, which does not read your shell environment. |

Because both files store the token unencrypted, prefer a fine-grained token restricted to public repositories with no additional permissions. To rotate or remove a token, re-run `install skills` with the new value, or edit the two files directly.

(install-skills-dev)=
### Development mode (`--dev`)

When you are working on ossiq-cli itself, `--dev <path>` points every installed integration at your local checkout instead of the PyPI release:

```bash
ossiq-cli install skills claude --dev ~/Projects/ossiq/ossiq-cli
```

Two substitutions are made:

- **MCP server** — registered as `uv run --directory <path> ossiq-cli mcp`, so the server always runs your current working tree.
- **SKILL.md** — every `uvx --from ossiq ossiq-cli` invocation in the skill text is rewritten to `uvx --from <path> --no-cache ossiq-cli`. The `--no-cache` flag makes `uvx` rebuild from source on each call, so the agent picks up your edits without a reinstall.

To switch back to the released package, re-run the command without `--dev`.

## Versioning & Stability Guarantees

OSS IQ makes four commitments to users who depend on its output in CI pipelines, scripts, or downstream tooling.

### Export Schema Stability

Each export schema version is identified by `schema_version` in the `metadata` block (e.g. `"1.4"`). The `export --schema-version` flag pins output to a specific version.

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
