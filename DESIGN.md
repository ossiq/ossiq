# OSS IQ — Design Notes

Architectural decisions, known gaps, and deferred work.

---

## Gaps

Gaps identified during architectural review and deferred for separate implementation.

### GAP-2: `PackageVersion.declared_dev_dependencies` is NPM-only at the registry level

**Context:** `PackageVersion.declared_dev_dependencies` captures dev/optional dependencies
as declared in the package's registry metadata. For NPM, this maps directly from
`devDependencies` in the registry response. For PyPI, `devDependencies` is not a
registry-level concept — `requires_dist` only exposes runtime deps — so this field
will always be `None` for Python packages.

**Rationale for keeping the field:** Dev dependencies installed on a developer machine
represent a significant risk surface even if the signal is ecosystem-asymmetric. A
Bayesian approach is preferred: each available piece of information strengthens the
overall signal, and the absence of data for PyPI is not a reason to discard the data
that exists for NPM.

**Future work:** When PyPI expands its API or when a supplementary data source (e.g.
repository-level `pyproject.toml` analysis) becomes available, populate this field
for Python packages to close the asymmetry.

---

### GAP-4: `runtime_requirements` is not populated for NPM packages

**Context:** `PackageVersion.runtime_requirements` is intended to capture runtime
environment constraints — `python_requires` for PyPI and `engines` for NPM. The NPM
adapter currently maps `engines` from the registry response into `runtime_requirements`
correctly. However, downstream consumers (service layer, export renderers) do not yet
use this field for any analysis or reporting.

**Future work:** Incorporate `runtime_requirements` into the risk scoring model.
For example, a package requiring `node >= 18` when the project targets `node 16`
is an implicit compatibility risk.

---

### GAP-5: No `is_yanked` / `is_deprecated` distinction in `PackageVersion`

**Context:** `PackageVersion.is_published = False` covers the case where a version has
been fully unpublished (removed from the registry). However, registries also expose
softer deprecation states:

- **PyPI**: Individual releases can be *yanked* (still downloadable but flagged unsafe).
  The current adapter sets `is_published=False` for yanked versions, conflating yanked
  with unpublished.
- **NPM**: Packages can be `deprecated` with a free-text reason, distinct from
  being unpublished.

These are meaningfully different signals: a yanked/deprecated package still exists and
may be transitively pulled in, but carries an explicit maintainer warning.

**Future work:** Add `is_yanked: bool = False` and `deprecation_notice: str | None = None`
fields to `PackageVersion`. Update `api_pypi.py` to set `is_published=True, is_yanked=True`
for yanked releases, and update `api_npm.py` to capture the `deprecated` field from NPM
registry responses.

---

### GAP-6: No caching in `scan_record()` for transitive dependency scanning

**Context:** `scan_record()` issues 2–3 external API calls per package (registry info,
version history, CVE lookup). Transitive dependency scanning via `GraphExporter.walk_all_paths()`
follows all distinct paths without cross-path deduplication, which is intentional for
visualisation purposes. However, the same `package@version` reached via multiple parent
chains triggers redundant API requests for identical data.

For a typical project with 50 direct dependencies and 300+ transitive entries, this means
hundreds of duplicate network calls, sharply increasing scan latency.

**Future work:** Introduce a response cache keyed on `(package_name, installed_version)`
within the scan service (or at the UoW/adapter level). The cache should be request-scoped
(not persisted) to avoid stale CVE data across invocations. Evaluate whether lazy
evaluation of transitive metrics (on-demand rather than eagerly in `scan()`) is preferable
for interactive CLI use.
