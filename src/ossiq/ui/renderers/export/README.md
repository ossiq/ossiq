# Export Format Versioning Guide

This directory owns the versioned JSON and CSV export formats. Follow this guide when introducing a new schema version (e.g. v1.4).

---

## Versioning policy

Two kinds of changes require a new version:

| Change type | Example | New version? |
|-------------|---------|--------------|
| Additive — new optional fields on existing models | Adding `maintainer_count` to `PackageMetrics` | Yes (minor) |
| Structural — changed field types, renamed fields, different array item shapes | v1.3's `transitive_packages` item type change | Yes (minor) |

Breaking changes (removing required fields, renaming) are **never** made to an existing version — always bump.

---

## Step-by-step: introducing v1.4

### 1. Enum — `src/ossiq/domain/common.py`

Add the new version to both enums:

```python
class ExportJsonSchemaVersion(StrEnum):
    ...
    V1_3 = "1.3"
    V1_4 = "1.4"   # add

class ExportCsvSchemaVersion(StrEnum):
    ...
    V1_3 = "1.3"
    V1_4 = "1.4"   # add (only if CSV also changes)
```

CSV and JSON versions move together unless one format is unchanged.

---

### 2. Python models — `src/ossiq/ui/renderers/export/models.py`

**Rule:** use a new `ExportData` subclass only when the _structure_ of one of the three package arrays changes (field type, required fields, or item shape changes). For additive-only changes (new optional fields on `PackageMetrics`), update the existing model in place and skip this step.

**Structural change → new subclass (Option A pattern):**

```python
class ExportDataV14(ExportDataBase):
    """Root export data structure for schema v1.4."""
    transitive_packages: list[NewTransitiveModel] = Field(default_factory=list)
```

Add any new Pydantic models above it (`NewTransitiveModel`, new nested types, etc.).

Update the factory in `build_export_data()`:

```python
def build_export_data(data: ScanResult, schema_version: ...) -> ...:
    if schema_version == ExportJsonSchemaVersion.V1_4:
        return ExportDataV14(...)
    if schema_version == ExportJsonSchemaVersion.V1_3:
        return ExportDataV13(...)
    return ExportData(...)   # v1.0–1.2 unchanged
```

**Additive-only → update `PackageMetrics` in place:**

Add the new field as optional with `default=None`. No new subclass, no factory branch — existing serialization picks it up automatically.

---

### 3. JSON schema — `src/ossiq/ui/renderers/export/schemas/`

Copy the previous version as a starting point:

```
cp export_schema_v1.3.json export_schema_v1.4.json
```

Edit `export_schema_v1.4.json`:
- Update `$id` → `https://ossiq.org/schemas/export/v1.4.json`
- Update `title` and `description`
- Update `metadata.properties.schema_version.const` → `"1.4"`
- Apply the structural or additive changes to `$defs`

---

### 4. CSV schemas — `src/ossiq/ui/renderers/export/schemas/csv/`

Three files per version (copy from previous and edit):

```
cp summary-schema-v1.2.json  summary-schema-v1.4.json
cp packages-schema-v1.2.json packages-schema-v1.4.json
cp cves-schema-v1.2.json     cves-schema-v1.4.json
```

If no CSV changes, these files are identical to the previous version — still create them so each version is self-contained.

---

### 5. Schema registries

**`src/ossiq/ui/renderers/export/json_schema_registry.py`:**

```python
_SCHEMA_FILES = {
    ...
    ExportJsonSchemaVersion.V1_3: "export_schema_v1.3.json",
    ExportJsonSchemaVersion.V1_4: "export_schema_v1.4.json",   # add
}

def get_latest_version(self) -> ExportJsonSchemaVersion:
    return ExportJsonSchemaVersion.V1_4   # bump
```

**`src/ossiq/ui/renderers/export/csv_schema_registry.py`:**

```python
_SCHEMA_FILES = {
    ...
    ExportCsvSchemaVersion.V1_3: {
        "summary":  "summary-schema-v1.3.json",
        "packages": "packages-schema-v1.3.json",
        "cves":     "cves-schema-v1.3.json",
    },
    ExportCsvSchemaVersion.V1_4: {   # add
        "summary":  "summary-schema-v1.4.json",
        "packages": "packages-schema-v1.4.json",
        "cves":     "cves-schema-v1.4.json",
    },
}

def get_latest_version(self) -> ExportCsvSchemaVersion:
    return ExportCsvSchemaVersion.V1_4   # bump
```

---

### 6. Frontend types — `frontend/package.json`

Update the `generate:types` script to point at the new JSON schema:

```json
"generate:types": "json2ts -i ../src/ossiq/ui/renderers/export/schemas/export_schema_v1.4.json -o src/types/report.ts"
```

Then regenerate:

```bash
cd frontend
npm run generate:types
```

This overwrites `frontend/src/types/report.ts`. TypeScript compiler errors after regeneration are the authoritative list of breaking changes to fix in Vue components.

---

### 7. Frontend alignment

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

### 8. Tests

**New schema registry test file** — copy `tests/ui/renderers/export/test_json_schema_registry_v1_3.py` and update version strings and structural assertions.

**Update existing tests** — two hardcoded version strings to update:
- `test_metadata_contains_schema_version_and_timestamp` in `test_json.py`
- `test_get_latest_version_returns_v1_X` in the previous schema registry test file

**New renderer tests** — add a `TestJsonExportRendererV14` class in `test_json.py` covering:
- Output validates against the new JSON schema
- Any new structural invariants (e.g. deduplication counts, new field presence)
- Backward compat: v1.3 still produces v1.3-shaped output

---

## Checklist

```
[ ] ExportJsonSchemaVersion.V1_4 added to domain/common.py
[ ] ExportCsvSchemaVersion.V1_4 added (if CSV changes)
[ ] New Pydantic models added to models.py (if structural change)
[ ] ExportDataV14 subclass added + build_export_data() factory updated (if structural)
[ ] export_schema_v1.4.json created
[ ] CSV schema files created (summary / packages / cves)
[ ] json_schema_registry.py updated + get_latest_version() bumped
[ ] csv_schema_registry.py updated + get_latest_version() bumped (if CSV changes)
[ ] frontend/package.json generate:types script updated to v1.4
[ ] npm run generate:types run — src/types/report.ts regenerated
[ ] npm run type-check passes — all Vue component access sites updated
[ ] SPA rebuilt and spa_app.html regenerated
[ ] Schema registry tests added
[ ] Renderer tests updated
```
