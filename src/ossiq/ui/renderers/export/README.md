# Export Format Versioning Guide

This directory owns the versioned JSON export format. Follow this guide when introducing a new schema version (e.g. v1.6).


---

## Versioning policy

Two kinds of changes require a new version:

| Change type | Example | New version? |
|-------------|---------|--------------|
| Additive — new optional fields on existing models | Adding `maintainer_count` to `PackageMetrics` | Yes (minor) |
| Structural — changed field types, renamed fields, different array item shapes | v1.3's `transitive_packages` item type change | Yes (minor) |

Breaking changes (removing required fields, renaming) are **never** made to an existing version — always bump.

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

---

### 4. Schema registry — `src/ossiq/ui/renderers/export/json_schema_registry.py`

```python
_SCHEMA_FILES = {
    ExportJsonSchemaVersion.V1_5: "export_schema_v1.5.json",
    ExportJsonSchemaVersion.V1_6: "export_schema_v1.6.json",   # add
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
[ ] export_schema_v1.6.json created
[ ] json_schema_registry.py updated + get_latest_version() bumped
[ ] --schema-version Literal widened in cli.py + HELP_SCHEMA_VERSION updated
[ ] frontend/package.json generate:types script updated to v1.6
[ ] npm run generate:types run — src/types/report.ts regenerated
[ ] npm run type-check passes — all Vue component access sites updated
[ ] SPA rebuilt and spa_app.html regenerated
[ ] Schema registry tests added
[ ] Renderer tests updated
```
