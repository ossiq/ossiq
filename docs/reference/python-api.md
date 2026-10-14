---
title: Python API
description: "The names you can import from the ossiq package: scan(), ScanResult, ScanRecord, Settings, CVE, Package and VersionsDifference, field by field."
---

# Python API

Import `scan` and its result types from `ossiq` to run a scan from Python. Part of the
[reference](../reference.md).

`pip install ossiq` installs both the library and the `ossiq` command. The `[cli]` extra still
resolves, but it is empty.

```python
from ossiq import scan, ScanResult, ScanRecord, Settings, CVE, Package, VersionsDifference, AbstractProjectSources
```

| Name | What it is |
|---|---|
| [`scan()`](#scansources) | Runs one scan and returns a `ScanResult` |
| [`ScanResult`](#scanresult) | The whole scan: project facts and three lists of `ScanRecord` |
| [`ScanRecord`](#scanrecord) | One package: versions, CVEs, recommendation, maintenance signals |
| [`Settings`](#settings) | Runtime configuration |
| [`CVE`](#cve) | One vulnerability on a `ScanRecord` |
| [`Package`](#package) | Registry metadata for one package |
| [`VersionsDifference`](#versionsdifference) | How far apart two versions are |
| [`AbstractProjectSources`](#abstractprojectsources) | The scan context: which project, which options |

## `scan(sources)`

```python
def scan(sources: AbstractProjectSources, progress: ScanProgress | None = None) -> ScanResult
```

Runs a full scan of the project that `sources` describes and returns a `ScanResult`. It fetches
package metadata, CVEs and version history, then runs the solver to produce update
recommendations. Call it inside the `sources` context manager.

`progress` is an optional `ossiq.service.project.scan.ScanProgress` with three callbacks, for
driving a progress indicator:

| Callback | Called with | When |
|---|---|---|
| `on_step_start` | `ScanStep` | A scan step starts: `project`, `packages`, `repositories`, `vulnerabilities`, `epss`, `versions`, `solver` |
| `on_step_done` | `ScanStep`, `DataSourceStatus`, optional diagnostics | A step that reports an outcome finishes |
| `on_budget` | a tuple of `RateLimitBudget` | Before the fetches that spend an API quota |

```python
from ossiq import scan, Settings
from ossiq.sources.project_sources import ProjectSources

settings = Settings.load()
sources = ProjectSources(settings, project_path=".")
with sources:
    result = scan(sources)
```

## `ScanResult`

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
| `ignored_packages` | `list[IgnoredDependency]` | Packages excluded from the scan (git/URL-hosted, or via `--ignore`) |
| `peer_repairs` | `list[PeerRepair]` | Peers installed only out of their requirers' reach, and how `apply` puts them back (npm only; see [Unresolved peers](#unresolved-peers)) |
| `project_epss` | `ProjectEpss \| None` | Project-level EPSS summary |
| `project_stability` | `ProjectStability \| None` | Project-level maintenance summary |
| `data_completeness` | `DataCompleteness` | Status of each external source for this scan. See [Partial data](../recommendations/partial-data.md) |
| `engine_context` | `EngineContext` | Runtime versions the engine checks ran against, and where they came from |
| `runtime_mismatch` | `RuntimeMismatch \| None` | The project's own runtime pin (`.nvmrc`, `.python-version`) when it disagrees with `engine_context` |
| `declares_esm` | `bool` | The project's manifest declares `"type": "module"` (npm only) |
| `npm_cli_version` | `str \| None` | Detected npm CLI version, for display |
| `source_warnings` | `list[str]` | Non-fatal problems found while reading the project, such as a tree with more than one registry |

## `ScanRecord`

The analysis record for one package. Each entry in the three package lists of a `ScanResult` is one `ScanRecord`.

| Field | Type | Description |
|---|---|---|
| `package_name` | `str` | Canonical package name |
| `dependency_name` | `str \| None` | Name the manifest uses. It differs from `package_name` for an npm alias (see [npm: package aliases](#npm-package-aliases)) |
| `is_optional_dependency` | `bool` | Whether this is a dev / optional dependency |
| `installed_version` | `str` | Version currently installed |
| `latest_version` | `str \| None` | Most recent published version |
| `recommended_version` | `str \| None` | Solver-recommended update target |
| `recommended_version_reason` | `RecommendationReason \| None` | Why this version was chosen |
| `recommended_from_rung` | `RecommendationRung \| None` | Which version-ladder rung `recommended_version` came from: `SOLVER`/`IN_RANGE` sit inside `version_constraint`; `IN_MAJOR`/`LATEST` require widening it first. See [Version ladder](#version-ladder) |
| `compatibility` | `CompatibilityFacts` | The version ladder and what is true of the picked version: `latest_in_range`, `latest_in_major`, `latest_compatible_major`, `latest_preserving_module_system`, `module_system`, `module_system_note`, `recommended_module_system`, `breaking_change`, `engine_requirement`, `engine_compatible` |
| `strategy_selection` | `StrategySelection \| None` | The update-strategy selector's verdict. `None` for a transitive or ignored package |
| `rejected_candidates` | `list[RejectedCandidate]` | Releases that would have been recommended but were held back, at most one per ladder rung |
| `time_lag_days` | `int \| None` | Days between the publish dates of the installed and the latest version |
| `releases_lag` | `int \| None` | Releases published after `installed_version`, up to `latest_version` |
| `version_age_days` | `int \| None` | Days since `installed_version` was published |
| `latest_release_age_days` | `int \| None` | Days since `latest_version` was published |
| `versions_diff_index` | `VersionsDifference` | Semantic drift classification |
| `cve` | `list[CVE]` | Known vulnerabilities for the installed version |
| `epss` | `float \| None` | Highest EPSS score among the package's CVEs |
| `version_constraint` | `str \| None` | Effective version specifier the solver used. For a transitive package it can come from a parent, not from your manifest |
| `version_constraint_declared` | `str \| None` | Version specifier your manifest declares. `None` for a transitive package or an unconstrained dependency |
| `extras` | `list[str] \| None` | Extras/features requested for this dependency |
| `constraint_info` | `ConstraintSource` | What controls the version beyond a plain manifest entry. See [Constraint types](constraints.md#the-five-constraint-types) |
| `dependency_path` | `list[str] \| None` | Ancestor chain for transitive packages |
| `repo_url` | `str \| None` | Source code repository URL |
| `repository` | `Repository \| None` | Repository activity data (commits, releases) when available |
| `homepage_url` | `str \| None` | Project homepage |
| `package_url` | `str \| None` | Registry page URL for the package |
| `is_installed_prerelease` | `bool` | Installed version is a pre-release |
| `is_installed_yanked` | `bool` | Installed version was yanked or unpublished |
| `is_installed_deprecated` | `bool` | Installed version, or the package, is deprecated |
| `registry_status` | `RegistryStatus \| None` | The registry's verdict on the whole package: `active`, `deprecated`, `archived` or `quarantined`. `None` when the registry gave none |
| `deprecation_message` | `str \| None` | The maintainer's note (npm) or the index's stated reason (PyPI), verbatim |
| `is_installed_package_unpublished` | `bool` | The whole package has been removed from the registry |
| `all_constraints` | `list[str]` | Every version specifier from each direct parent (transitive packages only) |
| `installed_copies` | `list[InstalledCopy]` | Every physical copy of the package in the tree, newest first. One entry unless the package manager nests copies (npm) |
| `update_transitive_impacts` | `list[TransitiveImpact]` | How updating this package affects transitive deps |
| `peer_requirements` | `list[PeerRequirement]` | All peer requirements other packages place on this one |
| `peer_violations` | `list[PeerRequirement]` | Peer requirements the installed version fails to satisfy |
| `unresolved_peers` | `list[UnresolvedPeer]` | Peers this package declares that nothing installed where it looks can satisfy (npm only; see [Unresolved peers](#unresolved-peers)) |
| `constraint_conflict` | `list[str]` | Conflicting constraints that blocked the solver |
| `purl` | `str \| None` | Package URL (PURL) identifier |
| `license` | `list[str] \| None` | SPDX license identifiers |
| `maintenance` | `MaintenanceAssessment \| None` | Maintenance-state verdict. `None` when no observation was available |
| `triage` | `TriageResult \| None` | Recommended action from the EPSS and maintenance matrix |
| `stability` | `RepositoryStability \| None` | Commit-gap and engagement-flow signals. `None` when no commit was sampled |
| `deprecation` | `DeprecationEvidence \| None` | End-of-life markers found in registry and repository metadata |
| `signal_coverage` | `SignalCoverage` | Whether the GitHub activity channels could be read for this package |
| `days_since_push` | `int \| None` | Days since the last push to the upstream repository |
| `runs_code_at_install` | `bool \| None` | Installing the version executes code (a build backend, an npm lifecycle script) |
| `install_execution_reason` | `str \| None` | What indicated `runs_code_at_install` |

A `None` in a measured field means the signal could not be measured, never that the package
carries no risk. [Repository stability](../explanation/repository-stability.md) explains the
maintenance fields.

## `Settings`

Pydantic model that holds runtime configuration. `Settings.load()` reads the config file and the
environment; `Settings.load(config_file)` reads that file in place of the default one. You can
also construct `Settings(...)` directly, which reads only the environment.

| Field | Default | Description |
|---|---|---|
| `github_token` | `None` | GitHub token for repository enrichment. Set it with `OSSIQ_GITHUB_TOKEN`, or leave it unset and log in with [`ossiq auth login`](#auth) |
| `github_auth` | `auto` | `auto` offers a GitHub login when no token is found; `off` never does |
| `github_client_id` | OSS IQ's OAuth app | Client ID of the GitHub OAuth app used for login (public, not a secret) |
| `cache_destination` | `~/.config/ossiq/cache.sqlite3` | Path to the SQLite HTTP cache |
| `cache_ttl` | `24` | Cache time-to-live in hours |
| `stability_cache_ttl` | `168` | Hours to keep GitHub stability data (commits, activity, README) |
| `verbose` | `False` | Emit detailed progress output |
| `debug` | `False` | Enable debug logging |
| `traceback` | `False` | Show full traceback on error instead of logging to file |
| `skip_pypi_enrichment` | `False` | Disable PyPI metadata fetching for transitive constraint enrichment |
| `cutoff_date` | `None` | Treat versions published after this date as invisible |
| `cooldown_period` | `7` | Days a new version must age before the solver recommends it |
| `stability` | `True` | Measure upstream repository stability |
| `stability_responsiveness` | `None` | The GraphQL engagement-flow channel. `None` means on when a GitHub token is available |
| `probe_runtime` | `True` | Detect the installed Python, Node.js and npm versions |
| `engine_versions` | `{}` | Runtime versions to check against in place of the probe, for example `{"node": "20.11.0"}` |
| `runtime_unknown` | `False` | Treat the runtime as unknown: no probe, no provided version, the project's declared floor only |

Every field can also come from an environment variable prefixed with `OSSIQ_` (for example
`OSSIQ_COOLDOWN_PERIOD`), or from the [config file](configuration.md#config-file). [Settings](configuration.md#settings)
lists the variable and flag for each one.

## `CVE`

A single vulnerability record attached to a `ScanRecord`.

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Primary identifier (CVE, GHSA, or OSV ID) |
| `cve_ids` | `tuple[str, ...]` | All aliases for this vulnerability |
| `source` | `CveDatabase` | Database this record came from |
| `package_name` | `str` | Name of the affected package |
| `package_registry` | `ProjectPackagesRegistry` | Registry the affected package belongs to (`"npm"` or `"pypi"`) |
| `severity` | `Severity` | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `summary` | `str` | Human-readable description |
| `affected_versions` | `tuple[str, ...]` | Versions the advisory enumerates. Always empty for npm, whose advisories publish only ranges |
| `affected_ranges` | `tuple[AffectedRange, ...]` | Affected version intervals. Use these, not `affected_versions`, to judge exposure |
| `published` | `str \| None` | ISO 8601 publication date |
| `link` | `str` | URL to the upstream advisory |
| `epss` | `float \| None` | EPSS exploitation probability, 0 to 1 |
| `fix_available` | `bool` | A fixed release is published |
| `fix_versions` | `tuple[str, ...]` | Releases that fix the vulnerability |
| `fix_age_days` | `int \| None` | Days a fix has been available |

## `Package`

Metadata about a package as returned by its registry.

| Field | Type | Description |
|---|---|---|
| `registry` | `ProjectPackagesRegistry` | Registry this package belongs to (`"npm"` or `"pypi"`) |
| `name` | `str` | Registry name |
| `canonical_name` | `str \| None` | Normalized name (lowercased, hyphens unified) |
| `latest_version` | `str \| None` | Most recent stable release |
| `next_version` | `str \| None` | Next release after `latest_version`, when known |
| `repo_url` | `str \| None` | Source code repository URL |
| `homepage_url` | `str \| None` | Project homepage |
| `description` | `str \| None` | Registry-provided package description |
| `author` | `str \| None` | Package author |
| `package_url` | `str \| None` | Registry page URL for the package |
| `license` | `str \| None` | SPDX license string |
| `registry_status` | `RegistryStatus \| None` | The registry's verdict on the package: `active`, `deprecated`, `archived` or `quarantined` (PyPI's [PEP 792](https://peps.python.org/pep-0792/) vocabulary). npm reports `deprecated` when the `latest` release is deprecated. `None` when the registry gave none, which is not the same as `active` |
| `is_deprecated` | `bool` | The registry reports the package `deprecated` or `archived`. Derived from `registry_status`; `quarantined` does not count |
| `deprecation_message` | `str \| None` | The maintainer's note (npm) or the index's stated reason (PyPI), verbatim |
| `is_unpublished` | `bool` | Package has been removed from the registry |
| `maintainers_count` | `int \| None` | Number of registered maintainers |
| `downloads_recent` | `int \| None` | Downloads in the most recent reporting period |
| `classifiers` | `list[str]` | Trove classifiers (PyPI); empty on npm |
| `all_releases_yanked` | `bool` | Every release of the package is yanked |

## `VersionsDifference`

Semantic drift classification between two versions.

| Field | Type | Description |
|---|---|---|
| `version1` | `str` | The first version being compared (typically the installed version) |
| `version2` | `str` | The second version being compared (typically the latest version) |
| `diff_index` | `int` | Numeric severity: 0 = latest (no diff), 1 = build, 2 = prerelease, 3 = patch, 4 = minor, 5 = major, 10 = no diff available (unpublished/unknown) |
| `diff_name` | `str` | Human-readable label, such as `"LATEST"`, `"PATCH"`, `"MINOR"` or `"MAJOR"` |

## `AbstractProjectSources`

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

The other keyword arguments mirror the CLI's flags:

| Argument | CLI flag |
|---|---|
| `production` | `--production` |
| `ignore_packages` | `--ignore` |
| `allow_prerelease` | `--allow-prerelease` |
| `allow_prerelease_packages` | `--allow-prerelease-package` |
| `strategy` | `--update-strategy` and `--strategy-override`, as an `ossiq.strategy.overrides.StrategyPlan` |
| `rewrite_versions` | `--rewrite-versions` |
| `narrow_package_registry` | `--registry-type` |

## Domain model

The exported types build on the entities in `ossiq.domain`. For their full definitions, read
the source:

- [`ossiq/domain/project.py`](https://github.com/ossiq/ossiq/blob/main/src/ossiq/domain/project.py):
  `Project`, a name and its direct production and development dependencies.
- [`ossiq/domain/package.py`](https://github.com/ossiq/ossiq/blob/main/src/ossiq/domain/package.py):
  `Package`, a registry package and its versions.
- [`ossiq/domain/version.py`](https://github.com/ossiq/ossiq/blob/main/src/ossiq/domain/version.py):
  `Version`, which joins registry data with repository data, plus `Commit` and `User`.
