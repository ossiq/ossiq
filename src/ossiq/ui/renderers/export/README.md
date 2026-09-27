# Export Format Versioning Guide

This directory owns the versioned JSON export format. Follow this guide when introducing a new schema version (e.g. v1.6).

---

## Profiles: standard and full

Every schema version has two profiles, each with its own schema file:

| Profile | Produced by | Carries | Schema |
|---------|-------------|---------|--------|
| `standard` | `ossiq export` (default) | Every direct dependency, the transitives `needs_attention` selects, decision fields only; optional nulls and empty lists omitted from per-package records | `export_schema_v<N>_standard.json` |
| `full` | `ossiq export --full`, `ossiq html` | Everything: every transitive, `dependency_tree`, provenance URLs, the raw upstream signals behind each verdict | `export_schema_v<N>.json` |

`standard` is a **projection** of `full`: the same field names and meanings, fewer fields and fewer
transitive entries, nothing renamed or added. `metadata.profile` says which one a document is.

- **Which fields are full-only** is decided on the field itself, in `models.py`:
  `Field(..., json_schema_extra=FULL_ONLY)`. `ProfiledExportModel` drops them at dump time, and
  `export_json()` is the one place a document becomes JSON.
- **Adding a field:** decide its profile where you declare it. An agent needs it to decide what to
  do → leave it untagged. Only dashboards, archives or recalibration need it → tag it `FULL_ONLY`.
  `test_standard_field_sets_are_a_deliberate_choice` fails until you make that call.
- **The two schemas are kept in sync by a test**, not by hand-diffing:
  `TestStandardSchemaIsAProjectionOfFull` requires the standard schema to equal the full one minus
  exactly the `FULL_ONLY` fields, property by property. The standard schema sets
  `additionalProperties: false`, so a leaked full-only field fails validation.


---

## Versioning policy

Two kinds of changes require a new version:

| Change type | Example | New version? |
|-------------|---------|--------------|
| Additive — new optional fields on existing models | Adding `maintainer_count` to `PackageMetrics` | Yes (minor) |
| Structural — changed field types, renamed fields, different array item shapes | v1.3's `transitive_packages` item type change | Yes (minor) |

Breaking changes (removing required fields, renaming) are **never** made to an existing version — always bump.

### The standing exception: v1.5 while it is unreleased

v1.5 has not shipped in a release (the package is still `0.1.10`), so it has no consumers outside
this repository and additive fields have been **amended into `export_schema_v1.5.json` in place**
rather than bumped. Amended this way so far: the version-ladder fields (`latest_in_range`,
`latest_in_major`, `latest_compatible_major`, `recommended_from_rung`), the module-system and
engine fields, `next_action` / `requires_constraint_widening`, the data-completeness
diagnostics (`data_completeness.sources[].failures` and `data_completeness.api_budgets`), and
`latest_preserving_module_system` / `module_system_note`, and the profile split
(`metadata.profile`, `summary.transitive_packages`, `runtime_context.runtime_mismatch`,
`CVEInfo.affected_ranges` / `fixed_in`, `TransitivePackageMetrics.recommended_version` /
`required_by`, and root `ignored_packages` / `upgrade_paths` / `manifest_lock_divergent`, plus the
new `export_schema_v1.5_standard.json`). Each addition to the full schema is optional, not in
`required`, and none of its `$defs` sets `additionalProperties: false`, so documents produced before
the amendment still validate. `runtime_context.engine_context_source` also gained the `provided`
value it was missing since the stated-runtime change.

One rename was also made in place: `triage_action` became `dependency_health_action`. Agents read
the old name as the answer to "should I update?". With no released consumer, a rename cost nothing
that a v1.6 bump would have saved. A pre-rename document still validates, since the old key is
simply an unknown extra property, but it no longer populates the field.

This exception ends the moment v1.5 ships. After that the policy above applies without
qualification: additive changes bump the minor version. Amending in place still means running the
rest of the checklist below — regenerate the TS types, type-check the frontend, rebuild the SPA.

---

## Step-by-step: introducing v1.6

### 1. Enum — `src/ossiq/domain/common.py`

Add the new version to `ExportJsonSchemaVersion`:

```python
class ExportJsonSchemaVersion(StrEnum):
    V1_5 = "1.5"
    V1_6 = "1.6"   # add
```

---

### 2. Python models — `src/ossiq/ui/renderers/export/models.py`

There is a single `ExportData` root (the former v1.3 shape: `constraint_type_map`,
`transitive_packages` as `TransitivePackageMetrics`, and `dependency_tree`).

**Additive-only change (new optional fields on `PackageMetrics` / `TransitivePackageMetrics`):**
add the field as optional with `default=None` and update the `from_domain` constructor. No new
subclass, no factory branch — existing serialization picks it up automatically.

**Structural change** (a package-array item shape changes): add a new `ExportData` subclass and
branch `build_export_data()` on `schema_version` to return it, keeping the old root for the
previous version.

---

### 3. JSON schema — `src/ossiq/ui/renderers/export/schemas/`

Copy the previous version as a starting point:

```
cp export_schema_v1.5.json export_schema_v1.6.json
```

Edit `export_schema_v1.6.json`:
- Update `$id` → `https://ossiq.org/schemas/export/v1.6.json`
- Update `title` and `description`
- Update `metadata.properties.schema_version.const` → `"1.6"`
- Apply the structural or additive changes to `$defs`

Do the same for the standard profile (`export_schema_v1.6_standard.json`): copy the previous
standard schema, bump its `$id` / `title`, and mirror every change that isn't `FULL_ONLY`. The
projection test tells you exactly which properties are missing or extra.

---

### 4. Schema registry — `src/ossiq/ui/renderers/export/json_schema_registry.py`

```python
SCHEMA_FILES = {
    (ExportJsonSchemaVersion.V1_5, ExportProfile.FULL): "export_schema_v1.5.json",
    (ExportJsonSchemaVersion.V1_5, ExportProfile.STANDARD): "export_schema_v1.5_standard.json",
    (ExportJsonSchemaVersion.V1_6, ExportProfile.FULL): "export_schema_v1.6.json",                   # add
    (ExportJsonSchemaVersion.V1_6, ExportProfile.STANDARD): "export_schema_v1.6_standard.json",      # add
}

def get_latest_version(self) -> ExportJsonSchemaVersion:
    return ExportJsonSchemaVersion.V1_6   # bump
```

Also widen the `--schema-version` `Literal` in `src/ossiq/cli.py` and update
`HELP_SCHEMA_VERSION` in `src/ossiq/messages.py`.

---

### 5. Frontend types — `frontend/package.json`

Update the `generate:types` script to point at the new JSON schema:

```json
"generate:types": "json2ts -i ../src/ossiq/ui/renderers/export/schemas/export_schema_v1.6.json -o src/types/report.ts"
```

Then regenerate:

```bash
cd frontend
npm run generate:types
```

This overwrites `frontend/src/types/report.ts`. TypeScript compiler errors after regeneration are the authoritative list of breaking changes to fix in Vue components.

---

### 6. Frontend alignment

Run `npm run type-check` in `frontend/` to surface all type errors introduced by the schema change.

Common patterns to check in Vue components and stores:
- New required fields need to be supplied in fixtures / mock data used in `vitest` tests
- Removed or renamed fields need updating at every access site
- Structural changes (like v1.3's `dependency_path → dependency_paths`) require updating iteration logic, filter callbacks, and any `d3` graph-building code that expands the transitive package list

After all type errors are resolved, rebuild the SPA and regenerate the embedded template:

```bash
cd frontend && npm run build
# then run whatever script bakes spa_app.html into the Python package
```

---

### 7. Tests

**New schema registry test file** — copy `tests/ui/renderers/export/test_json_schema_registry_v1_5.py` and update version strings and structural assertions.

**Update existing tests** — hardcoded version strings to update:
- `test_metadata_contains_schema_version_and_timestamp` in `test_json.py`
- `test_get_latest_version_returns_v1_X` and `included_versions` in the previous schema registry test file

**New renderer tests** — add a `TestJsonExportRendererV16` class in `test_json.py` covering:
- Output validates against the new JSON schema
- Any new structural invariants (e.g. deduplication counts, new field presence)
- Backward compat: v1.5 still produces v1.5-shaped output (if the previous version is kept registered)

---

## Checklist

```
[ ] ExportJsonSchemaVersion.V1_6 added to domain/common.py
[ ] New Pydantic fields / subclass added to models.py
[ ] build_export_data() factory branch added (only if structural)
[ ] export_schema_v1.6.json and export_schema_v1.6_standard.json created
[ ] json_schema_registry.py updated + get_latest_version() bumped
[ ] --schema-version Literal widened in cli.py + HELP_SCHEMA_VERSION updated
[ ] frontend/package.json generate:types script updated to v1.6
[ ] npm run generate:types run — src/types/report.ts regenerated
[ ] npm run type-check passes — all Vue component access sites updated
[ ] SPA rebuilt and spa_app.html regenerated
[ ] Schema registry tests added (full and standard), projection test pointed at v1.6
[ ] Renderer tests updated
```
