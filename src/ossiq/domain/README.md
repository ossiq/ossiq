# Domain Model Specifications

This document lists the external specifications that define or inform the domain models in this package.

---

## Registry Health Fields

`Package` and `PackageVersion` carry explicit flags for the two ways a package can become unavailable or inadvisable to use. These are set by the registry adapters and surfaced through `ScanRecord` into all export formats and UI renderers.

### `Package` flags

| Field | Registry | Meaning |
|-------|----------|---------|
| `is_deprecated: bool` | npm | The package's latest version carries a `deprecated` field — the whole package is considered deprecated. Set via `npm deprecate <pkg>`. |
| `is_unpublished: bool` | npm | `time.unpublished` is present in the packument — the entire package was removed from the registry. |

### `PackageVersion` flags

| Field | Registry | Meaning |
|-------|----------|---------|
| `is_deprecated: bool` | npm | This specific version's manifest has a truthy `deprecated` field. |
| `is_yanked: bool` | PyPI | The version exists on PyPI but is marked yanked — excluded from normal resolution. |
| `is_unpublished: bool` | npm | The version was individually deleted after release (present in `time` but absent from `versions`), or the entire package was unpublished (all versions inherit this flag). |

### `ScanRecord` derived flags

| Field | Derived from | Meaning |
|-------|-------------|---------|
| `is_installed_yanked` | `version.is_yanked or version.is_unpublished` | Installed version was pulled from the registry (covers both PyPI yanked and npm unpublished). |
| `is_installed_deprecated` | `version.is_deprecated or package.is_deprecated` | Installed version or its parent package is deprecated. |
| `is_installed_package_unpublished` | `package.is_unpublished` | The entire package has been removed from the registry. |

Display priority in all renderers: **UNPUBLISHED** > **YANKED** > **DEPRECATED** > pre-release.

---

## Versioning

### Semantic Versioning (SemVer)
**Spec**: https://semver.org/
**Applies to**: `Version`, `PackageVersion`, `RepositoryVersion`, `normalize_version()`

The foundational versioning scheme used by both npm and (loosely) Python packaging. A version takes the form `MAJOR.MINOR.PATCH[-pre-release][+build]`. The `VersionsDifference` model maps version drift to one of: `DIFF_MAJOR`, `DIFF_MINOR`, `DIFF_PATCH`, `DIFF_PRERELEASE`, `DIFF_BUILD`.

### PEP 440 — Python Version Identification
**Spec**: https://peps.python.org/pep-0440/
**Applies to**: `normalize_version()`, `PackageVersion.version`

Python's versioning scheme. Supports epochs (`1!1.0`), pre-releases (`1.0a1`, `1.0rc1`), post-releases (`1.0.post1`), dev releases (`1.0.dev1`), and local versions (`1.0+local`). The `normalize_version()` function strips PEP 440 operators (`==`, `>=`, `~=`, etc.) to extract a bare version string.

---

## Version Constraints

### Python — Dependency Specifiers (PEP 508)
**Spec**: https://packaging.python.org/en/latest/specifications/dependency-specifiers/
**Applies to**: `Dependency.version_defined`, `PackageVersion.version_constraint`

Defines the syntax for expressing Python package requirements:

| Operator | Meaning |
|----------|---------|
| `==` | Exact match (supports `.*` wildcard) |
| `!=` | Exclusion |
| `>=`, `<=`, `>`, `<` | Inclusive/exclusive bounds |
| `~=` | Compatible release (`~=1.4` means `>=1.4,<2`) |
| `===` | Arbitrary equality (string match, discouraged) |

Multiple constraints are combined with commas: `>=1.2,<2.0,!=1.3`.

Extras are specified in brackets: `requests[security,tests]>=2.28`.

Environment markers make dependencies conditional:
```
argparse; python_version < "2.7"
pywin32; sys_platform == "win32"
```

Available marker variables: `python_version`, `python_full_version`, `os_name`, `sys_platform`, `platform_machine`, `platform_python_implementation`, `implementation_name`, `implementation_version`, `extra`.

### npm — Semver Ranges
**Spec**: https://docs.npmjs.com/cli/v11/configuring-npm/package-json#dependencies
**Applies to**: `Dependency.version_defined`, `PackageVersion.version_constraint`

npm version constraints use the [node-semver](https://github.com/npm/node-semver) library:

| Syntax | Meaning |
|--------|---------|
| `1.2.3` | Exact version |
| `>1.2.3`, `>=1.2.3`, `<2.0.0`, `<=2.0.0` | Comparators |
| `^1.2.3` | Compatible with (same major): `>=1.2.3 <2.0.0` |
| `~1.2.3` | Approximately equivalent (same minor): `>=1.2.3 <1.3.0` |
| `1.2.x` or `1.2.*` | Any patch in minor |
| `*` or `""` | Any version |
| `1.2.3 - 2.0.0` | Hyphen range (inclusive) |
| `1.0.0 \|\| 2.0.0` | Union of ranges |

Non-registry forms (stored in `Dependency.source`): git URLs, GitHub shorthand (`user/repo`), local paths (`file:../pkg`), and tarball URLs.

---

## Dependency Categories

### npm — Dependency Fields
**Spec**: https://docs.npmjs.com/cli/v11/configuring-npm/package-json#devdependencies
**Applies to**: `Dependency.categories`

| Field | Category value | Meaning |
|-------|---------------|---------|
| `dependencies` | _(none / default)_ | Required at runtime |
| `devDependencies` | `development` | Development/build tooling only |
| `peerDependencies` | `peer` | Must be provided by the consuming project |
| `optionalDependencies` | `optional` | Non-fatal if missing; overlaps with `dependencies` |
| `bundleDependencies` | `bundled` | Included in the package tarball on publish |

`peerDependenciesMeta` can mark individual peer deps as `optional: true`.

### Python — Optional Dependencies (Extras)
**Spec**: https://packaging.python.org/en/latest/specifications/pyproject-toml/#project-optional-dependencies
**Applies to**: `Dependency.categories`

Declared under `[project.optional-dependencies]` in `pyproject.toml`. Keys are extra names (e.g., `dev`, `test`, `docs`). These become part of package metadata and are installable via `pip install pkg[extra]`. Stored in `Dependency.categories` as the extra name.

### Python — Dependency Groups (PEP 735)
**Spec**: https://packaging.python.org/en/latest/specifications/dependency-groups/
**Applies to**: `Dependency.categories`

Declared under `[dependency-groups]` in `pyproject.toml`. Unlike `optional-dependencies`, groups are **not** included in built distribution metadata — they are strictly for local development tooling. Groups support `{include-group = "other"}` for composition.

```toml
[dependency-groups]
test = ["pytest>7", "coverage"]
docs = ["sphinx", {include-group = "test"}]
```

---

## Manifest Files

### pyproject.toml
**Spec**: https://packaging.python.org/en/latest/specifications/pyproject-toml/
**Applies to**: `Manifest`, `PackageManagerType` (UV, POETRY, PDM, PIP)

The standard Python project manifest. Key tables for dependency management:

| Table | Purpose |
|-------|---------|
| `[build-system]` | Build backend declaration (`requires`, `build-backend`) |
| `[project]` | Core metadata: `name`, `version`, `dependencies`, `optional-dependencies` |
| `[dependency-groups]` | Dev-only dependency groups (PEP 735) |
| `[tool.uv]` | uv-specific configuration |
| `[tool.poetry.dependencies]` | Poetry dependency declarations |

### package.json
**Spec**: https://docs.npmjs.com/cli/v11/configuring-npm/package-json
**Applies to**: `Manifest`, `PackageManagerType` (NPM, YARN, PNPM)

The npm ecosystem manifest. Shared by npm, Yarn, and pnpm. Relevant fields: `name`, `version`, `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`, `bundleDependencies`, `engines`.

### requirements.txt
**Spec**: https://pip.pypa.io/en/stable/reference/requirements-file-format/
**Applies to**: `Manifest` (PIP_CLASSIC)

Legacy pip format. One requirement per line using PEP 508 syntax, with pip-specific options (`-r`, `-c`, `-e`, `--index-url`). No standard for extras or groups. Used by `PIP_CLASSIC` package manager type.

---

## Lockfiles

### pylock.toml (PEP 751)
**Spec**: https://packaging.python.org/en/latest/specifications/pylock-toml/
**Applies to**: `Lockfile` (PIP)

The emerging standard Python lockfile format. Key structure:

```toml
lock-version = "1.0"
created-by = "uv 0.5.0"
requires-python = ">=3.11"

[[packages]]
name = "requests"
version = "2.31.0"
marker = "python_version >= '3.8'"
```

Each `[[packages]]` entry may have a mutually exclusive source: `[packages.sdist]`, `[[packages.wheels]]`, `[packages.vcs]`, `[packages.directory]`, or `[packages.archive]`. Cryptographic hashes (SHA-256) are required for reproducibility.

### uv.lock
**Spec**: https://docs.astral.sh/uv/concepts/resolution/#lockfile
**Applies to**: `Lockfile` (UV)

uv's proprietary TOML lockfile. Uses CEL-based version parsing for format compatibility. Contains resolved package versions with hashes and source information.

### poetry.lock
**Spec**: https://python-poetry.org/docs/basic-usage/#installing-with-poetrylock
**Applies to**: `Lockfile` (POETRY)

Poetry's TOML lockfile. Contains `[[package]]` entries with `name`, `version`, `description`, `category`, `optional`, `python-versions`, and `dependencies`.

### package-lock.json
**Spec**: https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json
**Applies to**: `Lockfile` (NPM)

npm's lockfile. Supports `lockfileVersion` 1, 2, and 3. Version 3 (npm 7+) uses a flat `packages` map keyed by `node_modules/` path:

| Field | Meaning |
|-------|---------|
| `version` | Exact resolved version |
| `resolved` | Download URL |
| `integrity` | SRI hash (`sha512-...`) |
| `dev` | `true` if dev dependency |
| `optional` | `true` if optional |
| `peer` | `true` if peer dependency |
| `dependencies` | Nested overrides (v1 compat) |

### yarn.lock
**Spec**: https://yarnpkg.com/features/lock-protocol
**Applies to**: `Lockfile` (YARN)

Yarn's custom YAML-like lockfile. Yarn v1 uses its own format; Yarn v2+ (Berry) uses a stricter YAML format with `__metadata` and `cacheKey`.

### pnpm-lock.yaml
**Spec**: https://pnpm.io/lockfile
**Applies to**: `Lockfile` (PNPM)

pnpm's YAML lockfile. Uses a content-addressable store. Key fields: `lockfileVersion`, `packages` (flat map of all packages by specifier), `importers` (per-workspace dependency declarations).

---

## Package Registries

### PyPI JSON API
**Spec**: https://warehouse.pypa.io/api-reference/json.html
**Applies to**: `Package`, `PackageVersion`, `ProjectPackagesRegistry.PYPI`

Endpoint: `https://pypi.org/pypi/{name}/json` and `https://pypi.org/pypi/{name}/{version}/json`.

Key response fields used:
- `info.name`, `info.version`, `info.author`, `info.summary`, `info.home_page`
- `info.requires_dist` — list of PEP 508 dependency strings
- `info.requires_python` — Python version constraint
- `releases` — map of version → list of distribution file objects (with `upload_time`, `yanked`)

`yanked` maps to `PackageVersion.is_yanked`. A yanked version still exists on PyPI but is excluded from normal resolution; pip will refuse to install it unless the version is pinned exactly.

### npm Registry API
**Spec**: https://github.com/npm/registry/blob/master/docs/REGISTRY.md
**Applies to**: `Package`, `PackageVersion`, `ProjectPackagesRegistry.NPM`

Endpoint: `https://registry.npmjs.org/{name}` (full packument) or `https://registry.npmjs.org/{name}/{version}`.

Key response fields used:
- `name`, `description`, `author`, `homepage`, `repository.url`
- `versions.{ver}.dependencies`, `versions.{ver}.devDependencies`, `versions.{ver}.peerDependencies`
- `versions.{ver}.deprecated` — non-empty string means this version is deprecated → `PackageVersion.is_deprecated`
- `dist-tags.latest` — current latest version; if `versions[latest].deprecated` is set → `Package.is_deprecated`
- `time.{ver}` — publish timestamp per version
- `time.unpublished` — present when the entire package was unpublished → `Package.is_unpublished`; every version also gets `PackageVersion.is_unpublished=True`
- `dist.integrity`, `dist.tarball` — download and verification

**Individually deleted versions**: a version key present in `time` but absent from `versions` was individually unpublished after release. These phantom entries are surfaced as `PackageVersion` objects with `is_unpublished=True` and `published_date_iso` from the `time` value. Non-semver keys (`created`, `modified`, and any registry metadata keys) are excluded.

---

## Further Reading — Versioning Practices

These articles expand on the motivation and trade-offs behind versioning strategies, which inform why OSS IQ tracks version lag as a risk signal.

### Against Upper-Bound Version Constraints in Libraries
**Article**: https://iscinumpy.dev/post/bound-version-constraints/

Argues that upper-bound caps (`package<2.0`) in library dependencies cause more harm than good in Python's flat dependency model. Key points:
- Users **cannot fix** an overly restrictive cap themselves — the library maintainer must release a patch — whereas a missing lower bound is trivially overridden.
- Caps force immediate maintenance releases whenever an upstream dependency cuts a new major, creating unsustainable pressure at scale.
- They hide real incompatibilities rather than surfacing them early when changesets are small.
- **Recommended practice**: set lower bounds to express what features are required; add upper bounds only when a known incompatibility exists and remove them as soon as possible. Never cap Python itself.
- Applications (not libraries) should use lock files for reproducibility instead of tightening manifest constraints.

### Version Pinning Debate (HN thread)
**Discussion**: https://news.ycombinator.com/item?id=16422916

A Hacker News thread that captures the core tension in dependency management:

- **Against pinning**: locked versions accumulate technical debt, making future upgrades progressively harder; they can bloat bundles with duplicate transitive versions; they reduce pressure on maintainers to preserve compatibility.
- **For pinning**: reproducible builds are "unquestionably superior" — code that built six months ago must build the same way today; developers should consciously choose when to update, not have it happen randomly.
- **Consensus**: the manifest/lockfile split (Cargo, Bundler, Composer pattern) is the right middle ground — express *intent* as version ranges in the manifest, express *reality* as exact versions in the lockfile. Pinning belongs in applications, not library manifests.

This tension — between flexibility for library consumers and reproducibility for application builders — is exactly what `Dependency.version_defined` (manifest constraint) vs. `Dependency.version_installed` (lockfile reality) models.

---

## Vulnerability Databases

The `CveDatabase` enum in `common.py` tracks which sources a CVE record came from. Not all sources are currently implemented.

### OSV (Open Source Vulnerabilities) — ✅ Implemented
**Spec**: https://ossf.github.io/osv-schema/
**Applies to**: `CVE`, `CveDatabase.OSV`

The primary vulnerability source used by ossiq. The OSV API (`https://api.osv.dev/v1/`) aggregates records from NVD, GHSA, and ecosystem-specific databases (PyPA, npm advisories, etc.) into a single unified schema. Key fields: `id`, `aliases` (cross-references to CVE, GHSA IDs), `affected[].package.name`, `affected[].package.ecosystem`, `affected[].ranges`, `severity`, `summary`, `published`, `modified`.

OSV covers both PyPI and npm ecosystems natively, making it well-suited as the single integration point — GHSA and CVE IDs appear as `aliases` on OSV records, so direct integration with those APIs is largely redundant.

### GitHub Security Advisories (GHSA) — 🔲 Not yet implemented
**Spec**: https://docs.github.com/en/rest/security-advisories
**Applies to**: `CVE`, `CveDatabase.GHSA`

GitHub's advisory database, accessible via REST (`GET /advisories`) and GraphQL APIs. IDs take the form `GHSA-xxxx-xxxx-xxxx`. Includes CVSS scores, CWE identifiers, affected version ranges, and patched versions. Most GHSA records are already surfaced through OSV aliases; a direct integration would be useful for accessing GitHub-specific metadata (e.g., `cvss_severities`, `credits`, `cwe_ids`) not always present in the OSV response.

### NVD (National Vulnerability Database) — 🔲 Not yet implemented
**Spec**: https://nvd.nist.gov/developers/vulnerabilities
**Applies to**: `CVE`, `CveDatabase.NVD`

NIST's authoritative CVE database. IDs take the form `CVE-YYYY-NNNNN`. The NVD API v2 provides CVSS v3.1/v4.0 scores, CPE applicability statements, and CWE classifications. NVD is the canonical source for CVE identifiers and CVSS scores; OSV records typically reference NVD for severity data, so direct integration would mainly be useful for richer CPE matching or accessing CVSS v4.0 scores before OSV propagates them.

### Snyk Vulnerability DB — 🔲 Not yet implemented
**Applies to**: `CVE`, `CveDatabase.SNYK`

Snyk maintains a proprietary database with additional vulnerability research not always present in OSV/NVD. Accessible via the Snyk API (requires API key). May surface earlier disclosures and more granular affected-version ranges for npm packages.

### CVSSv3 Severity Bands
**Spec**: https://www.first.org/cvss/specification-document
**Applies to**: `Severity`

| Score | `Severity` value |
|-------|----------------|
| 0.0 | _(informational)_ |
| 0.1 – 3.9 | `LOW` |
| 4.0 – 6.9 | `MEDIUM` |
| 7.0 – 8.9 | `HIGH` |
| 9.0 – 10.0 | `CRITICAL` |
