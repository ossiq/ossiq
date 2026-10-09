
# Reference


## Public API

ossiq exposes a stable library interface for programmatic use. `pip install ossiq` gives you both the library and the `ossiq` command — there are no extras to choose between. (The `[cli]` extra still resolves, but it is empty and kept only for backwards compatibility.)

```python
from ossiq import scan, ScanResult, ScanRecord, Settings, CVE, Package, VersionsDifference, AbstractProjectSources
```

### `scan(sources)`

```python
def scan(sources: AbstractProjectSources, on_step: Callable[[str], None] | None = None) -> ScanResult
```

Runs a full dependency health scan against the project described by `sources`. Fetches package metadata, CVEs, and version history from the appropriate registry; runs the SAT solver to produce update recommendations; and returns a `ScanResult`. Must be called inside the `sources` context manager. `on_step` is an optional callback invoked with a short label at each scan phase (useful for driving a progress indicator).

```python
from ossiq import scan, Settings
from ossiq.sources.project_sources import ProjectSources

settings = Settings.load()
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
| `ignored_packages` | `list[IgnoredDependency]` | Packages excluded from the scan (git/URL-hosted, or via `--ignore`) |
| `peer_repairs` | `list[PeerRepair]` | Peers installed only out of their requirers' reach, and how `apply` puts them back (npm only; see [Unresolved peers](#unresolved-peers)) |

### `ScanRecord`

Per-package analysis record. Each entry in the `ScanResult` lists above is one `ScanRecord`.

| Field | Type | Description |
|---|---|---|
| `package_name` | `str` | Canonical package name |
| `dependency_name` | `str \| None` | Name actually used in the manifest — differs from `package_name` for npm aliases (see [npm — package aliases](#npm-package-aliases)) |
| `is_optional_dependency` | `bool` | Whether this is a dev / optional dependency |
| `installed_version` | `str` | Version currently installed |
| `latest_version` | `str \| None` | Most recent published version |
| `recommended_version` | `str \| None` | Solver-recommended update target |
| `recommended_version_reason` | `RecommendationReason \| None` | Why this version was chosen |
| `recommended_from_rung` | `RecommendationRung \| None` | Which version-ladder rung `recommended_version` came from: `SOLVER`/`IN_RANGE` sit inside `version_constraint`; `IN_MAJOR`/`LATEST` require widening it first — see [Version ladder](#version-ladder) |
| `latest_in_range` | `str \| None` | Newest version satisfying `version_constraint`; equals `installed_version` when the range admits nothing newer, `None` only when undeterminable |
| `latest_in_major` | `str \| None` | Newest version sharing `installed_version`'s major line; equals `installed_version` when that line is exhausted, `None` only when undeterminable |
| `time_lag_days` | `int \| None` | Days between installed and latest version |
| `releases_lag` | `int \| None` | Number of releases between installed and latest |
| `version_age_days` | `int \| None` | Age of the installed version in days |
| `versions_diff_index` | `VersionsDifference` | Semantic drift classification |
| `cve` | `list[CVE]` | Known vulnerabilities for the installed version |
| `version_constraint` | `str \| None` | Version specifier from the manifest |
| `extras` | `list[str] \| None` | Extras/features requested for this dependency |
| `constraint_info` | `ConstraintSource` | How the version was constrained (see Constraint Provenance) |
| `dependency_path` | `list[str] \| None` | Ancestor chain for transitive packages |
| `repo_url` | `str \| None` | Source code repository URL |
| `repository` | `Repository \| None` | Repository activity data (commits, releases) when available |
| `homepage_url` | `str \| None` | Project homepage |
| `package_url` | `str \| None` | Registry page URL for the package |
| `is_installed_prerelease` | `bool` | Installed version is a pre-release |
| `is_installed_yanked` | `bool` | Installed version was yanked by its maintainer |
| `is_installed_deprecated` | `bool` | Installed version, or the package, is deprecated |
| `is_installed_package_unpublished` | `bool` | Installed version has been removed from the registry |
| `all_constraints` | `list[str]` | Every version specifier from each direct parent (transitive packages only) |
| `update_transitive_impacts` | `list[TransitiveImpact]` | How updating this package affects transitive deps |
| `peer_requirements` | `list[PeerRequirement]` | All peer requirements other packages place on this one |
| `peer_violations` | `list[PeerRequirement]` | Peer requirements the installed version fails to satisfy |
| `unresolved_peers` | `list[UnresolvedPeer]` | Peers this package declares that nothing installed where it looks can satisfy (npm only; see [Unresolved peers](#unresolved-peers)) |
| `constraint_conflict` | `list[str]` | Conflicting constraints that blocked the solver |
| `purl` | `str \| None` | Package URL (PURL) identifier |
| `license` | `list[str] \| None` | SPDX license identifiers |

### `Settings`

Pydantic model holding runtime configuration. Load from the config file and environment variables with `Settings.load()`, or construct directly.

| Field | Default | Description |
|---|---|---|
| `github_token` | `None` | GitHub token for repository enrichment. Set it with `OSSIQ_GITHUB_TOKEN`, or leave it unset and log in with [`ossiq auth login`](#auth) |
| `github_auth` | `auto` | `auto` offers a GitHub login when no token is found; `off` never does |
| `github_client_id` | OSS IQ's OAuth app | Client ID of the GitHub OAuth app used for login (public, not a secret) |
| `cache_destination` | `~/.config/ossiq/cache.sqlite3` | Path to the SQLite HTTP cache |
| `cache_ttl` | `24` | Cache time-to-live in hours |
| `verbose` | `False` | Emit detailed progress output |
| `debug` | `False` | Enable debug logging |
| `traceback` | `False` | Show full traceback on error instead of logging to file |
| `skip_pypi_enrichment` | `False` | Disable PyPI metadata fetching for transitive constraint enrichment |
| `cutoff_date` | `None` | Treat versions published after this date as invisible |
| `cooldown_period` | `7` | Days a new version must age before the solver recommends it |

Every field can also come from an environment variable prefixed with `OSSIQ_` (for example
`OSSIQ_COOLDOWN_PERIOD`), or from the [config file](#configuration).

### `CVE`

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
| `affected_versions` | `tuple[str, ...]` | Version strings confirmed vulnerable |
| `published` | `str \| None` | ISO 8601 publication date |
| `link` | `str` | URL to the upstream advisory |

### `Package`

Metadata about a package as returned by its registry.

| Field | Type | Description |
|---|---|---|
| `registry` | `ProjectPackagesRegistry` | Registry this package belongs to (`"npm"` or `"pypi"`) |
| `name` | `str` | Registry name |
| `canonical_name` | `str \| None` | Normalised name (lowercased, hyphens unified) |
| `latest_version` | `str \| None` | Most recent stable release |
| `next_version` | `str \| None` | Next release after `latest_version`, when known |
| `repo_url` | `str \| None` | Source code repository URL |
| `homepage_url` | `str \| None` | Project homepage |
| `description` | `str \| None` | Registry-provided package description |
| `author` | `str \| None` | Package author |
| `package_url` | `str \| None` | Registry page URL for the package |
| `license` | `str \| None` | SPDX license string |
| `is_deprecated` | `bool` | Package has been deprecated by its maintainer |
| `is_unpublished` | `bool` | Package has been removed from the registry |
| `maintainers_count` | `int \| None` | Number of registered maintainers |
| `downloads_recent` | `int \| None` | Downloads in the most recent reporting period |

### `VersionsDifference`

Semantic drift classification between two versions.

| Field | Type | Description |
|---|---|---|
| `version1` | `str` | The first version being compared (typically the installed version) |
| `version2` | `str` | The second version being compared (typically the latest version) |
| `diff_index` | `int` | Numeric severity: 0 = latest (no diff), 1 = build, 2 = prerelease, 3 = patch, 4 = minor, 5 = major, 10 = no diff available (unpublished/unknown) |
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

Other optional keyword arguments mirror the CLI's own flags: `allow_prerelease`, `allow_prerelease_packages`, `strategy` (an `ossiq.strategy.overrides.StrategyPlan` — the update-strategy tier and any per-package overrides), `rewrite_versions`, and `narrow_package_registry` (force a specific registry instead of auto-detecting).

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

(npm-overrides)=
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

OSS IQ reads the `overrides` block from `package.json` (npm does not copy it into `package-lock.json`) and tags every installed copy of a matching package with `ConstraintType.OVERRIDE`, adding an `overridden` category to its `categories` list.

For *scoped* overrides — where a version is forced only when a package appears as a dependency of a specific parent — the `scope_path` field on `ConstraintSource` records the ancestor chain. In the example above, `dot-prop` would carry `scope_path: ["lodash"]`, meaning the override applies only when `dot-prop` is pulled in by `lodash`. A flat override like `semver` has `scope_path: null`.

The `scope_path` matters for remediation: a scoped override targeting `dot-prop` inside `lodash` does not affect `dot-prop` when pulled in by other packages. Removing it may leave `dot-prop` under `lodash` unprotected, or free it to resolve a patched version — depending on which direction the version was being forced.

**A rule may be keyed to a version range.** `"minimatch@^9.0.0": "9.0.9"` forces only the edges whose range overlaps `^9.0.0`; a nested `minimatch` 10 elsewhere in the tree is left alone. OSS IQ marks each installed copy the rule governs — one the version sits inside the key of, or already at the value of — and records the rule's key and value on `ConstraintSource` (`override_key`, `override_value`). A `$name` value follows the root dependency of that name.

**Overrides decide whether an update is possible.** npm nests a further copy of a package when a dependent's range cannot share the installed one, so an ordinary requirement never stops an update. An override does: it forces one version whatever the dependent declares. When a candidate needs a version an override *you* wrote rules out, the release is rejected and the override is named (`@vue/shared is held by an override in package.json`), and `plan` lists it under *Held by overrides you wrote*. OSS IQ never rewrites those; update or remove them to let the release through. An override OSS IQ wrote itself (recorded under `ossiq:metadata`) moves with the candidate instead, together with every other override that candidate's packages pin to each other.

**Peers are held to what the package declares, overrides or not.** npm applies `overrides` to peer edges too. With `"typescript": "$typescript"`, npm installs the version your manifest names beside `@typescript-eslint/*` even when their peer range stops below it, and reports no `ERESOLVE`: the override silences npm's check, it does not make the pair compatible. OSS IQ reads the ranges packages *declare*, not the ones an override leaves them with, so it keeps refusing that release (see *Held by peer dependencies* in the [recommendation catalogue](recommendations/catalogue.md#the-non-recommendations)). An override whose only job was to quiet that check can be removed.

**Family moves are keyed to a range.** When OSS IQ moves a whole lockstep family it writes the key as the range from the old version to the new, `"@vue/shared@3.5.42 - 3.5.43": "3.5.43"`. A key naming only the old version would match nothing once every member of the family asks for the new one, and npm would nest further copies instead of moving the hoisted one.

**Matching is by exact tree name.** An override entry is matched against packages by the literal name npm registered them under in the lockfile — not the package's canonical registry name. This matters for [package aliases](#npm-package-aliases): an override keyed `"chalk": "4.1.2"` tags a plain `chalk` dependency, but does nothing to `"chalk-legacy": "npm:chalk@4.1.2"`, because that alias is registered as `chalk-legacy`, not `chalk`. To override an aliased package, key the `overrides` entry with the alias name.

(npm-package-aliases)=
#### npm — package aliases

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

**Each alias is tracked as its own entry, with its own recommendation.** `ScanRecord.package_name` holds the canonical (real) name — `chalk` for both rows above — and `ScanRecord.dependency_name` holds the name actually used in `package.json` — `chalk-legacy` and `chalk`. The two occurrences never share a recommendation: `chalk-legacy` is held at `4.1.2` because its own alias range pins it there, while plain `chalk` is free to move up to `5.3.0`, even though the solver evaluates candidate versions for the underlying `chalk` package once and both entries draw from the same candidate set.

That per-alias fitting also applies to the solver's [cooldown](#update-solver): when the shared candidate the solver would otherwise recommend falls outside one alias's own range, OSS IQ re-fits that alias to the newest version that satisfies its range and (like the solver itself) still prefers one older than the cooldown period when one exists. If no published version satisfies an alias's own range, that alias is reported with no recommendation rather than inheriting a sibling's.

**Console output names the alias.** The `status` and `plan` tables and the `apply` acknowledgement prompt all print the *Package* column as `chalk-legacy (chalk)` — the manifest key, with the canonical name after it — so two occurrences of one package are never two identical rows. `ossiq info <alias-name>` matches on the alias name directly and opens that one occurrence; `ossiq info <real-name>` matches every occurrence — aliased or not — and lists each as a separate `Occurrence n of m` block. In machine-readable output the two names stay separate fields: `package_name` is always canonical, and `dependency_name` carries the manifest key (in the JSON export always, in `--format agent` and the MCP tools only when it differs).

**`--override` accepts either spelling.** `--override chalk-legacy==4.2.0` forces that one alias and leaves its siblings on their own recommendations. `--override chalk==4.2.0` names every occurrence at once, so on a project with several aliases of one package OSS IQ says which manifest keys it found and forces none of them — name the key to pick one. `--strategy-override` is canonical-only: `--strategy-override chalk=latest` retiers every occurrence, and an alias key is reported as not found rather than silently ignored.

**`plan` / `apply` cannot rewrite an alias's inner range.** The update solver still computes a per-alias recommendation as described above, but writing it back to `package.json` is unsupported for `npm:pkg@range` specifiers — the alias entry is left untouched by `apply`. Use the recommendation as a manual target and edit the alias range yourself.

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
-   **Cooldown.** The cooldown shapes the recommendation itself, not just what `apply` will write:
    a direct dependency is recommended the newest version at least `--cooldown-period` days old
    (default 7), so a settled `0.9.0` is preferred over a two-day-old `0.10.0` rather than the
    latter being recommended and then refused. When *every* reachable version is younger than the
    cooldown, no version is recommended at all — `status` shows a blank *Recommended* cell and
    **Wait for cooldown**, and the plan lists the package under *Held for cooldown* so you still
    know what is coming. Transitive candidates additionally receive a heavy soft-penalty in the
    solver, and anything still younger than the cooldown after solving is withheld the same way.
    A version with no publish date in the registry is never withheld.
-   **CVE and end-of-life bypass.** When the installed version carries a CVE or the package is
    abandoned/deprecated, waiting out a cooldown is not an option: the newest reachable version is
    recommended even if it is fresh, and the plan marks it `↳ cooldown bypassed`. CVE-affected
    candidate versions themselves are hard-forbidden.
-   **New transitive dependencies.** Packages entering the tree for the first time are resolved by
    the native package manager at apply time, outside the cooldown. The plan projects their version
    and age and flags entries younger than the cooldown with `⚠`. Under `--cutoff-date`, projections
    exclude versions published after the cutoff for deterministic time-travel runs.
-   **Peer dependencies (npm).** Every release declares its own `peerDependencies`, and which of
    them are optional; the solver reads them from the registry metadata the scan already fetched,
    so there are no extra requests. A release is refused when:

    - an installed package peer-requires this one outside the release's version, unless that
      package moves in the same plan. `vue` pins `@vue/server-renderer` to its own version and
      `@vue/server-renderer` peer-pins `vue` back, so the two move together or not at all;
    - its own peers cannot be met by what the tree will hold. A peer already installed must be
      in range; a *required* peer that is not installed is installed by npm, so it must exist,
      and so must whatever *it* peer-requires (four levels deep). An *optional* peer that is not
      installed binds nothing, and one that is installed is enforced, as npm enforces it;
    - two direct picks would end on versions that peer-require each other out, or a pick would
      contradict where a transitive or `--ignore`d package ends up. The pick that conflicts gives
      way, to the newest release that does not.

    A range the installed versions already violate is existing drift, not a reason to refuse a
    bump. The refusal is named: `↳ 7.0.2 rejected: @typescript-eslint/utils peer-requires typescript`,
    and the plan lists the package under *Held by peer dependencies*. PyPI has no peers, so none
    of this applies there.
-   **Lockstep families (npm).** When a package pins its dependencies exactly, bumping it moves
    them too. If an older copy of one of them stays hoisted because something else still wants it,
    npm nests the new family under the bumped package and leaves two copies of each side by side.
    That is installable but wrong for anything that loads the hoisted copy: this is how
    `@vue/test-utils` lost `@vue/server-renderer`. Where the pinned copy has to move, the plan moves
    it in place with an `overrides` entry keyed to the copy instead of nesting a second one, and
    refuses the bump, naming the specs, when another user of the shared copy cannot take the new
    version.
-   **Peer repairs (npm).** An already-split tree is repaired the same way; see
    [Unresolved peers](#unresolved-peers).
-   **Forced versions (`--override pkg==version`).** Bypass the solver and the cooldown for one
    package. Persistence per ecosystem:

| Ecosystem | Direct dependency | Transitive dependency |
|---|---|---|
| npm | specifier rewritten to the exact version | persistent `overrides` entry in `package.json` |
| uv | specifier rewritten to `==version` | persistent `override-dependencies` entry under `[tool.uv]` |
| pip classic | constraints-file pin for the run | constraints-file pin for the run (not persistent) |

    Forced packages are reported with `ConstraintType.OVERRIDE` on subsequent scans, so they remain
    visible until the override is removed.

(update-strategy)=
### Update Strategy

`--update-strategy` picks which tier of the **dependency update pyramid** a run targets — five
tiers, each a strict superset of the one below: `security` (the smallest diff that clears an
exploitable CVE), `deprecation` (also end-of-life packages), `standard` (also plain drift, the
default — preserves pre-strategy behaviour), `latest` (also widens the declared constraint to
reach the newest version), and `cutting-edge` (also prereleases). `--strategy-override
pkg=tier` runs one package at a different tier than the rest of the run (repeatable); `--override
pkg==version` still wins over both when given for the same package.

Every surface echoes which tier answered: `status`/`plan`/`html` print it in the header, `export`
writes it to `metadata.update_strategy` (plus a per-package `strategy` object on `PackageMetrics`
carrying `motives` / `withheld_reason` / `requires_widening` / `escalation` / `widening_authorized`,
null when the selector never ran for that package), and `--format agent` / both MCP tools carry
`update_strategy` and a per-entry `motives`. A withheld package's `plan`/`status` output names the
lowest tier that would move it ("N more updates available under --update-strategy X").

`security` and `deprecation` move a package only on a qualifying CVE or end-of-life marker, so a
run at either tier whose vulnerability data did not arrive would print *"nothing to do"* character
for character identically to a clean project. `status`, `plan` and `export` refuse that answer
instead — a non-zero exit with a *Security Data Incomplete* error, or the same error as an MCP
error payload — unless `--allow-partial` (MCP: `allow_partial`) says to accept it. Every other
tier is unaffected and still exits 0: drift alone justifies a move there, so a degraded run
produces a thinner answer rather than an empty one. A degraded `repositories` step is never
grounds for refusing; it thins `deprecation`'s coverage rather than emptying its result.

`apply` treats reaching `latest`/`cutting-edge` for a package as the authorization to widen its
declared constraint — but asks for a second, separate confirmation before doing so, in addition to
the usual "proceed with N updates?" prompt. `--yes` skips both.

Full design, the two-axis (motive × reach) model, and a worked example across all five tiers live
in `src/ossiq/strategy/README.md`.

### Plan and apply options

`plan` and `apply` accept the same options, so a `plan` previews the matching `apply` exactly.
Both take an optional project path (default: `.`).

| Option | Description |
|---|---|
| `--registry-type npm\|pypi`, `-r` | Analyze one ecosystem of a polyglot repository |
| `--production` | Leave out development dependencies |
| `--update-strategy TIER` | Target one tier of the update pyramid: `security`, `deprecation`, `standard` (default), `latest` or `cutting-edge`. See [Update Strategy](#update-strategy) |
| `--strategy-override PKG=TIER` | Run one package at a different tier (repeatable) |
| `--allow-prerelease` | Include pre-release versions for every package |
| `--allow-prerelease-package NAME` | Include pre-release versions for one package (repeatable) |
| `--ignore NAME`, `-i` | Leave a package out of the plan (repeatable) |
| `--override PKG==VERSION` | Force an exact version, bypassing the solver and the cooldown (repeatable) |
| `--pin-all` | Write an exact `==version` for every updated direct dependency |
| `--rewrite-versions` | Include dependencies already pinned with `==x.y.z`, and rewrite their pin |
| `--allow-partial` | `plan` only. Accept a result built on incomplete data (see [Update Strategy](#update-strategy)) |
| `--yes`, `-y` | `apply` only. Skip the confirmation prompts |

An exact pin (`==x.y.z`) is frozen by default, so an update never moves an intentional pin.
`--pin-all` and `--rewrite-versions` change how each kind of specifier is written:

| Flags | `>=x` (declared) | `~=x` (narrowed) | `==x` (pinned) |
|---|---|---|---|
| *(none)* | lockfile-only update | rewrite to `~=new` | skipped |
| `--pin-all` | rewrite to `==new` | rewrite to `==new` | skipped |
| `--rewrite-versions` | lockfile-only update | rewrite to `~=new` | rewrite to `==new` |
| `--pin-all --rewrite-versions` | rewrite to `==new` | rewrite to `==new` | rewrite to `==new` |

To keep every direct dependency pinned, pin once, then upgrade and re-pin in one pass:

```bash
ossiq apply --pin-all
ossiq apply --pin-all --rewrite-versions --ignore django
```

(version-ladder)=
### Version ladder

`latest_version` alone can leave a package with nowhere to go: a dependency held
back on a major version by an API break (e.g. `pydantic==1.10.13`, where 2.x moved
`BaseSettings` to a separate package) has a `latest_version` the project cannot
take, and historically `recommended_version` then fell back to `None` — the
dependency was never touched even though a safe newer patch existed.

Every `ScanRecord` instead carries the full ladder of reachable versions:

| Field | Meaning |
|---|---|
| `latest_in_range` | Newest version satisfying the declared `version_constraint` |
| `latest_in_major` | Newest version sharing `installed_version`'s major line |
| `latest_version` | Newest version overall (unchanged) |

Each rung is either a real version newer than `installed_version`, or exactly
equal to it when that step admits nothing newer — never omitted, so "already at
the top of this rung" and "not analysed" are never confused. A rung is `None`
only when genuinely undeterminable (no release data, or the declared constraint
is satisfiable only *below* `installed_version`, signalling a manifest/lockfile
divergence).

`recommended_version` is set by the [update-strategy](#update-strategy) selector, which picks a
rung from this ladder according to the run's tier — `latest_in_range`, then `latest_in_major`,
then `latest_version`, taking the first (or, for freshness tiers, the newest) rung the tier
reaches. `recommended_from_rung` records which rung it came from:

-   **`SOLVER` / `IN_RANGE`** — inside `version_constraint`; `plan`/`apply`/`update`
    write these directly.
-   **`IN_MAJOR` / `LATEST`** — only reachable by widening `version_constraint` first.
    `build_update_plan` withholds these into `UpdatePlan.held_for_widening` (reported by `plan`
    under *Requires constraint widening*) unless the run's strategy tier authorizes reaching that
    far (`latest`/`cutting-edge`, or an escalating CVE/end-of-life motive) — see
    [Update Strategy](#update-strategy). `--override` bypasses this, same as it bypasses the
    cooldown.

The ladder itself reports plain registry facts — no cooldown, no CVE filtering, no strategy —
so `latest_in_range`/`latest_in_major` may differ from what `recommended_version` actually
settles on once those guardrails apply.

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

The `ossiq html` command produces a self-contained HTML file embedding an interactive Vue.js single-page application. The report includes the full dependency tables and the **Transitive Dependency Explorer**: an interactive D3 tree that visualises the `transitive_packages` dependency graph.

The dependency table shows the same version ladder the console does. Under **Latest**, a dim `in range <version>` line names the newest version the declared constraint already admits, and `in major <version>` the newest in the installed major line; each appears only when it sits below the registry's latest, which is exactly when something is holding the package back. A `widen` badge on **Rec. Version** means the recommendation lies outside the declared range, so `ossiq apply` will not write it without the range being widened first. Selecting a package opens a **Version Ladder** block with every rung and the one the recommendation came from. **What's Next** carries the label the scan decided, so it never disagrees with `ossiq status`.

The Explorer supports:

- Color-coded nodes by risk type — six priority tiers: CVE (red), OVERRIDE (orange dash-dot), ADDITIVE (green dotted), PINNED (orange solid-thick), NARROWED (yellow dashed), DECLARED (blue)
- Fuzzy search and toggle filters (CVE, Narrowed, Override/Pinned)
- Click to focus a node and highlight all ancestor and descendant paths
- Alt+Click to collapse or expand a subtree
- Dashed curved links between nodes sharing an identical `package_name@installed_version`
- Zoom and pan

For full Explorer interaction details, see [EXPLORER.md](https://github.com/ossiq/ossiq/blob/main/frontend/EXPLORER.md).

#### JSON Export

The `export` command writes a single `.json` file conforming to [export schema v1.6](../src/ossiq/ui/renderers/export/schemas/export_schema_v1.6.json) (the latest; `--schema-version 1.5` still produces a [v1.5](../src/ossiq/ui/renderers/export/schemas/export_schema_v1.5.json) document). The root object contains:

| Key | Contents |
|---|---|
| `metadata` | `schema_version` and `export_timestamp` |
| `project` | `name`, `path`, and `registry` |
| `summary` | Aggregate counts: packages, CVEs, outdated |
| `production_packages` | Array of `PackageMetrics` |
| `development_packages` | Array of `PackageMetrics` |
| `transitive_packages` | Array of `PackageMetrics` with `dependency_path` set |

Since v1.6, npm projects also report peer dependencies that cannot be loaded: every `PackageMetrics` entry (production, development and transitive) may carry `unresolved_peers`, each with `package_name`, `spec`, `optional` and `installed_elsewhere`. A peer is unresolved when nothing installed *where the package looks for it* satisfies it: npm resolves a peer from the requirer's own location, so a copy nested under some other package does not count. The root object carries `peer_repairs`, which is how `ossiq apply` puts such peers back: `package_name` and `suggested_constraint` to add to the manifest, `is_dev_dependency`, the `requirers` that need it, and the `family_moves` (stale copies of its exact-pinned family that move with it, as keyed overrides). Both are empty for PyPI projects and absent from a document pinned to v1.5.

Since v1.5, every `PackageMetrics` entry (production, development, and transitive) also carries `epss` (the highest EPSS among the package's CVEs), `runs_code_at_install` with `install_execution_reason`, and the maintenance-state fields: `maintenance_state`, `maintenance_risk` (P(abandoned) + P(deprecated), the value that feeds triage), `maintenance_coverage` (fraction of the five maintenance observations that were available), `gap_cv`, `median_gap_days`, `silence_days`, `silence_p`, `commits_sampled`, `span_days`, `flow_trend`, `deprecation_signals`, `deprecation_successor`, `days_since_push`, `archived`, and `dependency_health_action` (the triage matrix's advisory verdict). Any of them may be `null` when the underlying signal could not be measured — that means "unknown," never "no risk." See [Repository stability](explanation/repository-stability.md) for what each field means.

Every `PackageMetrics` entry also carries the [version ladder](#version-ladder): `latest_in_range` and `latest_in_major` (both `null` only when undeterminable, equal to `installed_version` when that rung has nothing newer), `latest_preserving_module_system` (the newest release code on the installed module system can still load, whatever the runtime) with `module_system_note` (what the scan's runtime means for the package's ESM-only releases), plus `recommended_from_rung` on production/development entries naming which rung `recommended_version` came from (`solver`, `in_range`, `in_major`, or `latest`). `TransitivePackageMetrics` carries `latest_in_range`/`latest_in_major` but not `recommended_from_rung`; on transitive entries the two rung fields are omitted entirely (rather than `null`) when undeterminable, per the schema's existing null-dropping convention for that array.

Every entry also carries `next_action`: the same label the status table's **What's Next** column and the HTML report show, so a consumer never has to re-derive it and cannot arrive at a different answer (`null`, and omitted on transitive entries, when nothing is due). Note that the `--format agent` payload's field of the same name applies two further escalations on top of this label — a CVE with no available fix, and an installed version gone from the registry — so the two can legitimately differ. Production and development entries additionally carry `requires_constraint_widening`: `true` when `recommended_from_rung` is `in_major` or `latest`, meaning the target lies outside the declared range. `ossiq apply` does not write it unless the package's tier is `latest` or `cutting-edge`, or `strategy.widening_authorized` (v1.6 and later) is `true` because a CVE or end-of-life motive carried the pick past its tier.

(console-reports)=
## Console Reports

This section describes the terminal output of `ossiq status` (project-wide report) and `ossiq info` (single-package report): what each part shows, what each column and status marker means, and what to do when a marker signals a problem.

### `status` — project report

```bash
ossiq status [PROJECT_PATH]        # default: only what needs action
ossiq status --full [PROJECT_PATH] # every package, every column
```

By default the report is deliberately narrow: it shows only the packages that need
attention (a version behind, a CVE, an unmaintained upstream, or an unsolvable
constraint) and a four-column table. `--full` shows every package and the detail
columns.

The report has up to six parts, printed in this order. Parts with nothing to show are omitted.

1. **Header** — project name, registry (`npm` or `pypi`), path, and counts: production packages, development packages, and transitive packages with an update recommendation.
2. **Dependency table** — one row per direct dependency, grouped into *Production* and *Development* sections.
3. **Transitive Recommendations** — transitive packages the solver recommends updating.
4. **New transitive dependencies** — packages that would enter the tree if the recommended updates were applied.
5. **Peer Constraint Status** — peer dependency requirements and whether the installed versions satisfy them (npm projects only; violations only unless `--full`). Peers that are installed but out of reach are not here: they appear as [unresolved-peer rows](#unresolved-peers) under the package that declares them.
6. **Constraint Widening Opportunities** — for library projects, dependency ranges that could safely be widened.

#### Dependency table

Default columns: **Package**, **CVEs**, **Installed**, **Latest**, **Recommended**, **What's
Next**. `--full` adds **EPSS**, **Update Mode**, **Lag**, and **State**.

| Column | Meaning |
|---|---|
| Package | Package name. |
| CVEs | Number of known vulnerabilities affecting the installed version. Empty when there are none. |
| EPSS | *(`--full`)* Probability that the package's worst known CVE sees exploitation in the next 30 days. `—` means no CVE carries a score, which is unknown rather than safe. |
| Update Mode | *(`--full`)* Semantic drift between installed and latest version: `Latest`, `Patch`, `Minor`, `Major`, `Prerelease`, `Build`, or `N/A` when the latest version is unknown. |
| Installed | Version resolved in the lockfile, with a lifecycle marker when one applies (see below). |
| Latest | Newest version the registry publishes, ignoring your declared range. This is what **Update Mode** and **Lag** are measured against. `—` when it could not be determined. |
| Recommended | Solver-recommended update target — clamped into your declared range, so it is often *not* the Latest version. Yellow when the recommendation is older than the latest version — usually held back by the [cooldown](#update-solver) or by a constraint. `[NO RESOLUTION]` when no published version satisfies all constraints. Blank when no acceptable target was found at all — including when every newer version is still inside the [cooldown](#update-solver), in which case *What's Next* reads **Wait for cooldown**. |
| Lag | *(`--full`)* Time between the installed and the latest version. Red when it exceeds `--lag-threshold-delta` (default `1y`). |
| State | *(`--full`)* Maintenance-state verdict for the upstream repository: `maintained`, `winding_down`, `abandoned`, or `deprecated`. `—` when the package could not be assessed. See [Repository Stability](explanation/repository-stability.md). |
| What's Next | The single next action for this package (first match wins): **Check for the Fix** (a CVE with EPSS ≥ 10%), **Find alternative** (at the latest version but abandoned/deprecated), **Consider alternative** (upstream winding down), **Check Release Notes** (a major version behind), **Update Immediately** (a minor or patch behind, with a newer version inside the declared range), **Wait for cooldown** (a newer version exists, but every version reachable from here is younger than the cooldown period — there is nothing settled enough to move to yet, so no version is recommended at all), **Constrained. Check newer version** (a minor or patch behind, but the declared range admits no bump — widening it is the real next step), **Withheld by strategy** (a bump is available and the range admits it, but the run's `--update-strategy` tier admitted no motive to take it — the sub-row names the lowest tier that would). Blank when nothing is due. On terminals too narrow to fit the widest label on one line — under 110 columns, or under 157 with `--full` — **Constrained. Check newer version** is shortened to **Constrained**; the `--full` sub-row below the package still names the range and what it caps. This is a display width only: the label in `--format agent`, the JSON export, the MCP tools and the HTML report is always the full one. |

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
| `↳ <specifier> caps this below <latest>[; <version> is the newest in the current major line]` | *(`--full`)* The declared range is what holds the package behind the registry's latest. Drawn only when the range genuinely admits nothing newer than what is installed — when it does admit a bump, the blocker is something else and draws its own row. The trailing clause appears only when the newest version within the installed major line differs from the latest overall. Shown with **Constrained. Check newer version**. |
| `↳ <version> is <n> days old; nothing older to move to before the <n>-day cooldown` | *(`--full`)* Every release newer than the installed one is younger than `--cooldown-period`, so no version was recommended. Names the release being waited on. Not drawn when a CVE or end-of-life motive is in play — those escalate past the cooldown rather than waiting it out. Shown with **Wait for cooldown**. |
| `↳ no motive admitted at <tier>; available under --update-strategy <tier>` | *(`--full`)* The run's update strategy, not the declared range, is what left this package without a target. Shown with **Withheld by strategy**. |

#### Transitive Recommendations

Transitive packages — packages your direct dependencies pull in — for which the solver recommends a different version, most often because the installed version carries a CVE or is far behind. With `--update-strategy security`, the list narrows to packages with CVEs only. To turn these recommendations into an executable update plan, run `ossiq plan` (see [Update Solver](#update-solver)).

Columns: **Package**, **CVEs**, **Installed**, **Recommended**, **What's Next**; `--full` adds **EPSS**. The **Recommended** version is the one the solver picks within all parent constraints; **What's Next** follows the same rules as the dependency table.

#### New transitive dependencies

Packages that are not in the tree today but would be pulled in by the recommended updates. Their versions are resolved by the native package manager at apply time, outside the solver's cooldown hold, so fresh entries are flagged rather than withheld: a `⚠` before the package name means the projected version is younger than the cooldown period and deserves a look before you apply (see [Cooldown as Supply-Chain Quarantine](explanation/index.md#cooldown-as-supply-chain-quarantine) for why).

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

1. **Update the requirer.** A newer release of the *Required By* package may accept the installed version. `ossiq info <requirer>` shows whether one exists and what constrains it.
2. **Move the violated package into the range.** Upgrade or downgrade it to a version inside the peer constraint — after checking that nothing else in the tree needs the version you are moving away from.
3. **Remove or adjust the override** when one is the cause. See [Constraint Provenance](#constraint-provenance) for how overrides are tracked.
4. **Accept it knowingly.** If you have verified the pair works together, you can leave it — the row keeps appearing on every scan as a standing reminder.

(unresolved-peers)=
#### Unresolved peers

A peer requirement can be *satisfied* (the table above) and still be *unreachable*. npm resolves a peer from the requiring package's own location, looking in its own `node_modules` and then up the tree, so a copy nested under some other package does not count. When the only copy of a peer sits where its requirer cannot see it, the requirer fails when it loads, for example `Cannot find module '@vue/server-renderer'`, although no version range anywhere is violated. A lockfile does not show this as a conflict, which is why OSS IQ reports it separately.

It usually comes from bumping a package that pins its dependencies exactly. After `vue` moved from 3.5.42 to 3.5.43, npm kept the 3.5.42 copies hoisted for other packages, nested the whole 3.5.43 family under `vue/node_modules/`, and pruned the hoisted `@vue/server-renderer`: `@vue/test-utils` only declares it as an *optional* peer, and an optional peer never keeps a package installed.

An unresolved peer is shown as a `↳` row under the package that declares it, in every mode (not only `--full`), and a package that has one stays on the default table even when it is otherwise up to date:

| Row | Meaning |
|---|---|
| `↳ missing peer host ^1: nothing installed where this package looks for it` | A required peer that npm should have installed is not installed where the package looks. |
| `↳ optional peer @vue/server-renderer 3.x is installed only out of reach (3.5.43); this package cannot load it` | A copy exists, but only nested under another package. |

The same entries are listed under **Unresolved Peers** in [`ossiq info`](#info-package-report) and exported as `unresolved_peers` (schema 1.6).

An *optional* peer that is installed nowhere is normal and is **not** reported. It is reported only when a copy exists out of reach, because that is the layout in which a package that imports it unguarded breaks.

**What `plan` and `apply` do about it.** When an out-of-reach copy satisfies the range the package declares, the plan proposes a repair and lists it under *Repairs unresolved peers*: the peer is added to `devDependencies` (or `dependencies`, when a production package needs it) at a range in the style of the family it belongs to, tilde by default, so that npm places it where its requirers resolve it. The stale hoisted copies of its exact-pinned family move with it, each as a keyed `overrides` entry (see [npm — `overrides`](#npm-overrides)); one that another package still pins to the old version is left alone. A peer already declared anywhere in your manifest is never rewritten. `ossiq apply` writes the repair; a second `ossiq plan` then reports nothing.

By hand, the same repair is `npm install --save-dev @vue/server-renderer@~3.5.43`, plus an `overrides` entry for each stale copy that blocks the hoist.

When no out-of-reach copy satisfies the declared range there is nothing OSS IQ can repair: the row stays, and the fix is to update the package that declares the peer, or the peer itself.

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

1. **Wait for upstream.** The owner of the blocking constraint (here `B`) has to publish a release that widens its range — you cannot fix their constraint unilaterally. This is the failure mode described in [Constraint Provenance](#constraint-provenance); `ossiq info <blocking package>` shows who declares the constraint.
2. **Update or replace the other parent.** A newer version of `B` may already accept `C >= 3`; if `B` is abandoned, replacing it removes the constraint entirely.
3. **Force the version:** `ossiq apply --override pkg==version` bypasses the solver for one package. You take on the compatibility risk the constraint was protecting against; the override persists in your manifest and is reported as `OVERRIDE` on every subsequent scan until removed (see [Update Solver](#update-solver)).
4. **Stay put deliberately.** The current version keeps resolving. The report keeps showing the lag, so the debt stays visible instead of silent.

(info-package-report)=
### `info` — package report

```bash
ossiq info PACKAGE_NAME [PROJECT_PATH]
```

A deep-dive into one package. When the package is installed in the project, the report has the sections below, in order; empty sections are omitted. When it is not installed, the report switches to [prospective mode](#info-prospective).

**Header.** Package name and installed version; role tags `DIRECT` and/or `TRANSITIVE` (both, when the package appears in both roles); a lifecycle marker (`[UNPUBLISHED]`, `[YANKED]`, `[DEPRECATED]`, `[pre]` — same meanings as in the status table); license; registry URL.

**Warnings.** A panel of package health findings: `✗` marks critical findings (these block `ossiq add` unless `--force` is passed), `!` marks notices. Examples: a package with a single published version (typosquatting risk), a single maintainer (bus-factor risk).

**Health Metrics.** Registry-level signals: downloads over the last month, number of published versions, maintainer count, age of the latest version, age of the recommended version (when it differs from the latest), and cooldown remaining — days until the latest release is old enough to clear the [cooldown period](explanation/index.md#cooldown-as-supply-chain-quarantine).

For an installed package, this block also shows the two risk pipelines:

| Row | Meaning |
|---|---|
| EPSS | Probability that the package's worst known CVE sees exploitation in the next 30 days. |
| Gap CV | Coefficient of variation of inter-commit gaps from the [repository's last 100 commits](explanation/repository-stability.md), and how many commits it spans. `too few gaps` below 20 sampled gaps. |
| ↳ silence | Days since the most recent sampled commit, and the empirical probability (`p`) of a silence this long, from the repository's own history. |
| Last pushed | Time since the last push to the upstream repository. |
| Repository archived | Shown only when the upstream repository is archived. |
| Triage | The recommended action and why. |
| Fix available | How long a fix for a known CVE has been published without being applied. |
| Runs code at install | Whether installing the package executes code, and what indicated it. |

Any of these can render `—`: it means the signal could not be measured, never that the package carries no risk.

**Occurrences.** A package can appear in the tree more than once — for example as a direct dependency and, at a different version, as a transitive one. Each occurrence gets its own block of the five sections below, labelled `Occurrence n of m`.

**Drift Status.** Status (same values as the status table), installed version, latest version, time lag (red past 180 days), how many releases behind the installed version is, and the next recommended action (same rule as the status table's **What's Next** column; blank when nothing is due).

**Dependency Tree.** The ancestor path from the project root down to this package (`← you are here`). For a direct dependency the path is just `root → package`; for a transitive one it names every intermediate package — useful for seeing *which* direct dependency is responsible for pulling this package in.

**Policy Compliance.** How the installed version relates to the rules that produced it:

| Row | Meaning |
|---|---|
| Constraint | Version specifier from the manifest, or `—` for transitive packages without one. |
| Resolved | The installed version. |
| In Range | Newest version the declared constraint already admits — reachable with no manifest edit. Dimmed when it equals the installed version, which means the range admits nothing newer; omitted only when it could not be determined. |
| In Major | Newest version sharing the installed major line, under the same rules. |
| Compatible Major | Newest version across majors at or above the installed one that carries no known module-system or API break. Shown only when it differs from **In Major**, i.e. when a known break sits in between. |
| Latest | Most recent published version. |
| Recommended | Solver-recommended target, when one exists. Yellow when held below the latest. When reaching it requires widening the declared constraint (an out-of-range ladder pick), a dim `(requires widening <constraint> — same major/new major)` caveat is appended — `ossiq update`/`apply` hold these back rather than writing them automatically. The rung it came from is marked `← recommended` in the ladder rows above. |
| Resolution | `NO VALID VERSION — conflicting constraints: <specifiers>` when the solver found no version satisfying all constraints. See [When an update is blocked](#update-blocked). |
| Constraint Type | Shown only when the version is controlled by something beyond a plain manifest entry (`PINNED`, `NARROWED`, `ADDITIVE`, `OVERRIDE`), with the file that introduced it. See [Constraint Provenance](#constraint-provenance). |

**Recommendation Rationale.** Why the solver picked the recommended version — and, just as important, why it rejected the others:

- *Eliminated (hard constraints)* — versions that can never be chosen: outside a parent's range, affected by a CVE, yanked, or pre-release without `--allow-prerelease`.
- *Penalised (soft constraints)* — versions that remain eligible but are scored down, e.g. younger than the cooldown period.
- The closing `✓` line states the selection: the latest eligible version, or the best stable candidate when the latest was eliminated or penalised.

If the version you expected is not the recommendation, this section names the exact rule that removed it.

**Peer Requirements.** Every peer constraint other packages place on this one, with the same markers as the status report's [Peer Constraint Status](#peer-constraint-status) table: `✓` satisfied, `✓ … via override`, `✗` violated (the installed version is shown in red next to the violated range). The recovery paths are the same too.

**Unresolved Peers.** Peers this package declares that nothing within its reach satisfies, each with its range, whether it is optional, and the versions installed out of reach (or `not installed`). Drawn only when there are any; see [Unresolved peers](#unresolved-peers).

**Security Advisories.** Known vulnerabilities in the installed version of *this* package: severity, advisory ID, source database, and summary — or `✓ No known vulnerabilities`.

**Transitive CVEs.** Vulnerabilities in packages *downstream* of this one — exposure you carry because this package pulls the affected ones in. Grouped per affected `package@version`, worst severity first. Updating this package may or may not resolve them; run `ossiq info <affected package>` to see what constrains each one.

**Licenses.** Listed only when the package's occurrences carry more than one SPDX identifier; a single unambiguous license is already shown in the header.

(info-prospective)=
#### Prospective mode

When the package is not installed in the project, `info` evaluates it as a candidate instead: the header carries a `PROSPECTIVE` tag and the registry description, followed by health metrics, the recommendation rationale, and security advisories. This is the same pre-installation check that `ossiq add` runs before installing.

### Agent format

Both commands accept `--format agent`, which replaces the human report with a compact JSON decision for AI coding agents and scripts. The same shape is returned by the MCP tools. See [Coding agents](getting-started.md#coding-agents).

**Runtime.** The MCP tools `ossiq_evaluate_updates`, `ossiq_evaluate_dependency` and `ossiq_update_context` require a `runtime` argument keyed by the project's registry (`{"node": "22.12.0"}` or `{"python": "3.11"}`), or the literal `"unknown"`. A missing `runtime` is a titled error, and the MCP server never probes its own `PATH`. On the CLI the runtime is probed by default (`--probe-runtime`). `--engine node=20.11.0` (repeatable) states it instead. Either way it is held to the project's declared floor, and reported as `engine_context_source: "provided"` when it binds. A version pin the project keeps (`.nvmrc`, `.node-version`, `.tool-versions`, `mise.toml`, `volta.node`, `.python-version`, `.venv/pyvenv.cfg`) that disagrees with the runtime is reported as `runtime_context.runtime_mismatch`, and as a warning in `status`.

**`update-context` comparison.** `ossiq update-context` / `ossiq_update_context` also return `comparison`: a `verdict` for the requested target against OSS IQ's own recommendation (`recommended`, `suboptimal`, `breaking`, `vulnerable`, `deprecated` or `beyond_recommendation`), the `reasons` behind it, and `better_available`.

Every decision leads with a `next_action` string:

- **add** (`info` / `add`): `install`, `install with caution`, or `do not install`.
- **update** (`status`): per entry — `Check for the Fix`, `Find alternative`, `Consider alternative`, `Check Release Notes`, or `Update Immediately`. The top-level `next_action` is the most urgent of those, or `no action needed` when no entry has an action due.

Each entry's `dependency_health` object (the triage matrix's advisory verdict: `retain`, `patch`, `refactor`, `evict`) carries a `question` stating what it answers: long-term health, not what to do now. Each CVE under `cves` carries its `epss` when scored.

The `updates` list has one entry per direct dependency; one with nothing due reads `no action needed`. Each entry carries the [version ladder](#version-ladder) (`latest_in_range`, `latest_in_major`) alongside `from`/`to`, and sets `requires_constraint_widening: true` when `to` is only reachable by widening the declared constraint. `plan` reports such a pick as *Requires constraint widening* rather than writing it, unless the package's tier is `latest` or `cutting-edge`, or a CVE or end-of-life motive carried the pick past its tier. In that last case the entry also sets `widening_authorized: true`, and `apply` writes the pick after its widening confirmation.

On npm, an entry for a package that declares a peer nothing within its reach can satisfy carries `unresolved_peers`, whatever its `next_action`. Each item has `package`, `spec`, `optional` and `installed_elsewhere` (the versions installed out of reach; empty when the peer is installed nowhere). When a copy that satisfies the range is installed elsewhere, the decision also carries `peer_repairs`: the `package` and `suggested_constraint` that `apply` adds to the manifest, `is_dev_dependency`, the `requirers` that need it, and the `family_moves` that bring stale copies of its family to the same version, in the shape of `transitive_impact`. Both fields are omitted when empty, and never appear for PyPI projects. Run `ossiq plan` to review the repair and `ossiq apply` to make it.

(install-skills)=
## Install Skills

```bash
ossiq install skills [TOOL] [--via uvx|npx|ossiq] [--dev PATH]
```

Installs the OSS IQ skill and a local MCP server so AI coding agents check dependency health before they add or update a package. For the task-oriented walkthrough, see [Coding agents](getting-started.md#coding-agents).

| Argument / option | Default | Description |
|---|---|---|
| `TOOL` | `all` | Which tool to install for: `claude`, `codex`, `copilot`, or `all`. |
| `--via` | detected | How the skill and MCP server run OSS IQ: `uvx`, `npx`, or a bare `ossiq` on `PATH`. By default this matches the channel you ran the command from (see [How the skill runs OSS IQ](#install-skills-runner)). Cannot be combined with `--dev`. |
| `--dev` | — | Path to a local ossiq source checkout. Switches the installed skill and MCP server to run from that checkout instead of the PyPI release (see [Development mode](#install-skills-dev)). |

### What the command writes

All changes are made under your home directory; the command never touches the current project.

| Tool | Skill | MCP server |
|---|---|---|
| `claude` | writes `~/.claude/skills/ossiq/SKILL.md` | adds an `ossiq` entry to `mcpServers` in `~/.claude/mcp.json` |
| `codex` | writes `~/.codex/skills/ossiq/SKILL.md` | adds an `ossiq` entry to `mcpServers` in `~/.codex/mcp.json` |
| `copilot` | inserts a fenced block into `~/.copilot/copilot-instructions.md` | — (Copilot has no MCP server registry) |

The MCP entry registers a **local stdio server** — the tool launches OSS IQ's `mcp` command as a subprocess on your machine, through the same runner the skill uses. No remote service is involved, and nothing is sent anywhere beyond the registry and GitHub API calls a normal scan makes.

The command is **idempotent** — safe to re-run at any time (for example after switching development mode on or off):

- `mcp.json` is merged: only the `ossiq` entry under `mcpServers` is replaced; every other server entry is preserved.
- The Copilot instructions block is delimited by `<!-- ossiq-skill:start -->` / `<!-- ossiq-skill:end -->` markers. On re-run the block between the markers is replaced; the rest of the file — including your own instructions — is untouched.

(install-skills-runner)=
### How the skill runs OSS IQ

Every command in the installed skill, and the MCP entry, runs OSS IQ the way you ran
`install skills`. The command prints the result, for example
`the skill runs ossiq as: npx --yes @ossiq/cli`.

| You ran | Skill commands | MCP server |
|---|---|---|
| `uvx ossiq install skills`, or any PyPI install with `uvx` on `PATH` | `uvx ossiq …` | `<path to uvx> ossiq mcp` |
| `npx @ossiq/cli install skills`, or `ossiq` installed with `npm install -g` | `npx --yes @ossiq/cli …` | `<path to npx> --yes @ossiq/cli mcp`; on Windows `cmd /c npx --yes @ossiq/cli mcp` |
| a PyPI install without `uv`, or a standalone binary | `ossiq …` | `<absolute path to ossiq> mcp` |

A permanent install gets its channel's runner too: `uvx` uses a copy installed with
`uv tool install`, and both runners work from any directory. To write a bare `ossiq` instead,
pass `--via ossiq`. The `npx` entry needs `node` on the `PATH` your MCP client starts servers with.

(install-skills-login)=
### GitHub login

The command writes no GitHub token, either to `mcp.json` or to a config file. The MCP server uses
your [GitHub login](#auth) from the system secret store. Without a login, the first tool call
returns a login code for the agent to show you; see
[Log in through an MCP client](how-to/github-login.md#log-in-through-an-mcp-client). The command
prints `auth login`, through the same runner, as the next step.

(install-skills-dev)=
### Development mode (`--dev`)

When you are working on ossiq itself, `--dev <path>` points every installed integration at your local checkout instead of the PyPI release:

```bash
ossiq install skills claude --dev ~/Projects/ossiq
```

Two substitutions are made:

- **MCP server** — registered as `uv run --directory <path> ossiq mcp`, so the server always runs your current working tree.
- **SKILL.md** — every command in the skill text runs `uvx --from <path> --no-cache ossiq`. The `--no-cache` flag makes `uvx` rebuild from source on each call, so the agent picks up your edits without a reinstall.

To switch back to the released package, re-run the command without `--dev`.

(auth)=
## Auth

```bash
ossiq auth login [--no-wait | --resume]
ossiq auth status
ossiq auth logout
```

Logs in to GitHub with a one-time code, through the
[OAuth device flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#device-flow).
Scans can then make 5,000 GitHub API requests an hour instead of 60. For step-by-step instructions,
see [Log in to GitHub](how-to/github-login.md).

| Command | What it does |
|---|---|
| `auth login` | Prints a URL and a one-time code. With a terminal, waits for approval and stores the login; without one, exits with status 75. Does nothing when a working login exists |
| `auth login --no-wait` | Prints the code and exits with status 75, even with a terminal |
| `auth login --resume` | Checks a login started earlier, by `auth login` or by a scan, and stores it once approved |
| `auth status` | Shows which token scans use, its source, GitHub account, scope, expiry and secret store. Always exits 0 |
| `auth logout` | Deletes the stored login from this machine. GitHub lists the authorization until you revoke it at [github.com/settings/applications](https://github.com/settings/applications) |

### Exit codes

| Status | Meaning |
|---|---|
| `0` | Done: logged in, already logged in, logged out, or nothing to remove |
| `1` | Failed: no login to resume, login cancelled or expired, GitHub unreachable, or no secret store. The message names the cause and the next step |
| `75` | Waiting for approval. Approve the code on GitHub, then run `ossiq auth login --resume` or the next scan |

A scan that shows a login code without a terminal also exits with status 75.

### Token precedence

Scans use the first token found, in this order:

1. The global `--github-token` (`-T`) flag. Avoid it: a token on the command line shows up in
   shell history and process listings.
2. The `OSSIQ_GITHUB_TOKEN` environment variable.
3. The `GITHUB_TOKEN` environment variable.
4. The stored GitHub login.
5. `OSSIQ_GITHUB_TOKEN` in the [config file](#configuration). The file is plaintext, so prefer the
   login.

A token from the flag or the environment never touches the secret store. `ossiq auth status` shows
which source won.

### When a scan logs in

A scan that finds no token starts the login itself and shows the code on stderr. With a terminal
it waits for approval; without one it exits with status 75. Only scanning commands log in:
`status`, `html`, `export`, `info`, `add`, `update-context`, `plan` and `apply`.

A scan skips the login, and runs at 60 requests an hour, when:

- `OSSIQ_GITHUB_AUTH` is `off`, in the environment or the config file;
- the `CI` environment variable is set to anything but `0` or `false`;
- the machine has no usable secret store.

In the first two cases the scan ignores the stored login as well. The MCP server offers the login
once per session; after a cancelled or expired code, its scans run without a token.

### Storage

The login lives in the operating system's secret store, through the
[keyring](https://pypi.org/project/keyring/) library:

| Item | Value |
|---|---|
| Secret store | macOS Keychain, Windows Credential Manager, or Secret Service or KWallet on Linux |
| Service name | `dev.ossiq.github` |
| Entries | `oauth_tokens` (the login) and `device_pending` (a login waiting for approval) |
| Timeout | A call with no answer after 3 minutes, such as an unanswered dialog, marks the store unavailable for the rest of the run |

The pending entry holds GitHub's device code, which stays secret until the login is approved.

### Tokens

- **Scope:** none. The token can read public data only.
- **Lifetime:** the access token lasts 8 hours, and OSS IQ refreshes it before it expires. The
  refresh token lasts about 6 months. GitHub replaces both on every refresh.
- **Validation:** OSS IQ checks a stored token with one `GET /user` request, at most once every
  10 minutes per process. A revoked token is discarded, and the next scan offers a new login.
- **Never written or printed:** no token, and no device code, appears in config files, `mcp.json`,
  the HTTP cache, logs, `--verbose` output, exports or HTML reports.

(configuration)=
## Configuration

OSS IQ reads settings from command-line flags, environment variables and a config file. For each
setting, the first source that sets it wins:

1. Command-line flags
2. Environment variables
3. The config file
4. Built-in defaults

### Configuration directory

OSS IQ keeps its files in `~/.config/ossiq/`, or in `$XDG_CONFIG_HOME/ossiq/` when
`XDG_CONFIG_HOME` is set:

| File | Contents |
|---|---|
| `config` | Optional settings, one `OSSIQ_*=value` per line |
| `cache.sqlite3` | HTTP cache for registry and GitHub responses. Move it with `--cache-destination`; skip it for one run with `--no-cache` |

The GitHub login is not in this directory; it lives in the [system secret store](#auth).

### Config file

The config file uses dotenv format: `KEY=value` lines and `#` comments. Any `OSSIQ_*` variable
from the following table can go in it:

```bash
# ~/.config/ossiq/config
OSSIQ_COOLDOWN_PERIOD=14
OSSIQ_CACHE_TTL=48
```

To read a different file, pass it before the command: `ossiq --config ./ossiq.conf status`. That
file then replaces the default one.

### Environment variables

Global flags go before the command, for example
`ossiq --cutoff-date 2025-01-01 --cooldown-period 14 status`.

| Variable | Flag | Default | Effect |
|---|---|---|---|
| `OSSIQ_GITHUB_TOKEN` | `--github-token`, `-T` | — | GitHub token, for CI and containers. See [Auth](#auth) |
| `GITHUB_TOKEN` | — | — | Used when `OSSIQ_GITHUB_TOKEN` is unset |
| `OSSIQ_GITHUB_AUTH` | — | `auto` | `off` stops scans from offering a GitHub login |
| `OSSIQ_GITHUB_CLIENT_ID` | — | OSS IQ's app | Client ID of the GitHub OAuth app used for login. Set it only to log in through your own OAuth app, with device flow enabled |
| `OSSIQ_CACHE_DESTINATION` | `--cache-destination` | `~/.config/ossiq/cache.sqlite3` | HTTP cache file |
| `OSSIQ_CACHE_TTL` | `--cache-ttl` | `24` | Hours to keep cached responses |
| `OSSIQ_STABILITY_CACHE_TTL` | `--stability-cache-ttl` | `168` | Hours to keep GitHub stability data (commits, activity, README) |
| `OSSIQ_CUTOFF_DATE` | `--cutoff-date`, `-C` | today | Hide versions published after this date (23:59:59 UTC), to reproduce a past state |
| `OSSIQ_COOLDOWN_PERIOD` | `--cooldown-period` | `7` | Days a new version must age before the solver recommends it. `0` turns the cooldown off |
| `OSSIQ_STABILITY` | `--stability` / `--no-stability` | on | Measure upstream repository stability |
| `OSSIQ_STABILITY_RESPONSIVENESS` | `--stability-responsiveness` / `--no-stability-responsiveness` | on with a token | The GraphQL engagement-flow channel |
| `OSSIQ_PROBE_RUNTIME` | `--probe-runtime` / `--no-probe-runtime` | on | Detect the installed Python, Node and npm versions |
| `OSSIQ_VERBOSE` | `--verbose`, `-v` | off | Detailed progress output |
| `OSSIQ_DEBUG` | `--debug`, `-d` | off | Debug logging |

## Versioning & Stability Guarantees

OSS IQ makes four commitments to users who depend on its output in CI pipelines, scripts, or downstream tooling.

### Export Schema Stability

Each export schema version is identified by `schema_version` in the `metadata` block (e.g. `"1.6"`). The `export --schema-version` flag pins output to a specific version; the versions available are `1.5` and `1.6`, and the default is the latest. A pinned document never carries a field a later version added, so pinning `1.5` keeps producing exactly the v1.5 shape.

Within a schema version:

- Existing fields are never renamed or removed.
- New optional fields may be added — existing consumers are unaffected.

One exception was made while v1.5 was still unreleased: `triage_action` was renamed to
`dependency_health_action` in place, because agents read the old name as the answer to "should I
update?". No released version carried the old name. Once a version ships, the rule above holds
without exception.

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
