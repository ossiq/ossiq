# Export Format Versioning Guide

This directory owns the versioned JSON export format. Follow this guide when introducing a new schema version (e.g. v1.7).

The versions registered here are **1.5** and **1.6**; the next one is 1.7.

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

### Older versions stay selectable, and stay what they were

`ossiq export --schema-version 1.5` keeps producing a v1.5 document that validates against
`export_schema_v1.5.json` (and the standard one, which rejects any property it doesn't list). All
versions share one set of Pydantic models, so a field a later version added is tagged with its
version where it is declared:

```python
unresolved_peers: list[UnresolvedPeerExport] = Field(..., json_schema_extra=SINCE_V1_6)
```

`ProfiledExportModel` leaves such a field out of a document that declares an older version, in both
profiles, and `export_json()` passes the declared version to it. A field that is both full-only and
new carries both markers (`{**FULL_ONLY, **SINCE_V1_6}`). Anything that *selects* records by
version-dependent data (the standard profile's transitive filter) takes the version too, so the old
version selects exactly what it always did. `TestSchemaVersion15StaysAsReleased` pins all of this: a
v1.5 document is the v1.6 one minus the new fields, and `TestV16IsAdditiveOverV15` fails if a newer
schema removes, retypes or newly requires anything an older one had.

### The former exception: v1.5 while it was unreleased

v1.5 shipped in 0.1.12, so this no longer applies; it is kept as a record of what v1.5 contains.
Until then it had no consumers outside this repository and additive fields were **amended into
`export_schema_v1.5.json` in place** rather than bumped. Amended this way: the version-ladder fields (`latest_in_range`,
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
that a version bump would have saved. A pre-rename document still validates, since the old key is
simply an unknown extra property, but it no longer populates the field.

That exception ended when v1.5 shipped. For a released version the policy above applies without
qualification: additive changes bump the minor version, which is how v1.6 came about
(`unresolved_peers`, `peer_repairs`).

v1.6 itself has not shipped, so the exception applies to it in turn. Until it does, additive fields
are amended into `export_schema_v1.6.json` and `export_schema_v1.6_standard.json` in place, tagged
`SINCE_V1_6` so a `--schema-version 1.5` document stays as released. The next bump (1.7) waits for
the v1.6 release.

---

## Step-by-step: introducing v1.7

### 1. Enum — `src/ossiq/domain/common.py`

Add the new version to `ExportJsonSchemaVersion`:

```python
class ExportJsonSchemaVersion(StrEnum):
    V1_5 = "1.5"
    V1_6 = "1.6"
    V1_7 = "1.7"   # add
```

---

### 2. Python models — `src/ossiq/ui/renderers/export/models.py`

There is a single `ExportData` root (the former v1.3 shape: `constraint_type_map`,
`transitive_packages` as `TransitivePackageMetrics`, and `dependency_tree`).

**Additive-only change (new optional fields on `PackageMetrics` / `TransitivePackageMetrics`):**
add the field as optional with a default, tag it with the version that introduces it
(`json_schema_extra=SINCE_V1_7`, defined next to `SINCE_V1_6`; add the marker, then use it), decide its
profile (`FULL_ONLY` or not), and update the `from_domain` constructor. A field both
`PackageMetrics` and `TransitivePackageMetrics` carry belongs on a shared mixin (`PeerFields`,
`LadderFields`). No new subclass, no factory branch. Then update
`test_standard_field_sets_are_a_deliberate_choice` for the profile decision.

If a **record filter** depends on the new data (the standard profile's transitive selection does),
gate it on `schema_version.at_least(...)` the way `build_transitive_data` does, so the older version
keeps selecting what it always did.

**Structural change** (a package-array item shape changes): add a new `ExportData` subclass and
branch `build_export_data()` on `schema_version` to return it, keeping the old root for the
previous version.

---

### 3. JSON schema — `src/ossiq/ui/renderers/export/schemas/`

Copy the previous version as a starting point:

```
cp export_schema_v1.6.json export_schema_v1.7.json
```

Edit `export_schema_v1.7.json`:
- Update `$id` → `https://ossiq.org/schemas/export/v1.7.json`
- Update `title` and `description`
- Update `metadata.properties.schema_version.const` → `"1.7"`
- Apply the structural or additive changes to `$defs`

Take the new descriptions from the Pydantic `Field(description=...)` rather than retyping them, so the
two cannot drift. (`json.dumps(schema, indent=2, ensure_ascii=True) + "\n"` reproduces the existing
files byte for byte, which keeps a script-generated diff down to the real changes.)

Do the same for the standard profile (`export_schema_v1.7_standard.json`): copy the previous
standard schema, bump its `$id` / `title`, and mirror every change that isn't `FULL_ONLY`. The
projection test tells you exactly which properties are missing or extra.

**Check every enum you copied against the code that emits it.** They are hand-written and drift:
`next_action` lacked `Wait for cooldown` from 0.1.11 on, so any document with a package inside its
cooldown failed its own schema. `TestNextActionEnumMatchesTheEmitter` pins that one; export a real
project and validate it (`jsonschema.validate`) against both profiles before calling a schema done.

---

### 4. Schema registry — `src/ossiq/ui/renderers/export/json_schema_registry.py`

```python
SCHEMA_FILES = {
    (ExportJsonSchemaVersion.V1_5, ExportProfile.FULL): "export_schema_v1.5.json",
    (ExportJsonSchemaVersion.V1_5, ExportProfile.STANDARD): "export_schema_v1.5_standard.json",
    (ExportJsonSchemaVersion.V1_6, ExportProfile.FULL): "export_schema_v1.6.json",
    (ExportJsonSchemaVersion.V1_6, ExportProfile.STANDARD): "export_schema_v1.6_standard.json",
    (ExportJsonSchemaVersion.V1_7, ExportProfile.FULL): "export_schema_v1.7.json",                   # add
    (ExportJsonSchemaVersion.V1_7, ExportProfile.STANDARD): "export_schema_v1.7_standard.json",      # add
}

def get_latest_version(self) -> ExportJsonSchemaVersion:
    return ExportJsonSchemaVersion.V1_7   # bump
```

Also widen the `--schema-version` `Literal` in `src/ossiq/cli.py` and update
`HELP_SCHEMA_VERSION` in `src/ossiq/messages.py`, and add the new full schema to the two file lists in
`.github/workflows/test.yml` (the wheel and sdist checks), which name the latest schema by hand.

---

### 5. Frontend types — `frontend/package.json`

Update the `generate:types` script to point at the new full JSON schema:

```json
"generate:types": "json2ts -i ../src/ossiq/ui/renderers/export/schemas/export_schema_v1.7.json -o src/types/report.ts"
```

Then regenerate:

```bash
cd frontend
npm run generate:types
```

This overwrites `frontend/src/types/report.ts`. The root interface is named from the schema's title, so
it becomes `OSSIQExportSchemaV17`; rename the imports of the old name (`grep -rn OSSIQExportSchemaV16 src`).
TypeScript compiler errors after regeneration are the authoritative list of breaking changes to fix in
Vue components.

---

### 6. Frontend alignment

Run `npm run type-check` in `frontend/` to surface all type errors introduced by the schema change.

Common patterns to check in Vue components and stores:
- New required fields need to be supplied in fixtures / mock data used in `vitest` tests
- Removed or renamed fields need updating at every access site
- A new per-package field has to be carried down the whole chain: `explorer/registry.ts` →
  `types/registry.ts` → `explorer/transform.ts` → `composables/useD3Tree.ts` and, for the direct table,
  `views/ScanReportView.vue` → `types/dependency-tree.ts`. Miss a link and the detail panel silently
  shows nothing for that node type.
- If the new data can make a package worth reading on its own, add it to `isActionable` in
  `composables/useReportFilters.ts` (the table hides packages with nothing to do by default)
- Structural changes (like v1.3's `dependency_path → dependency_paths`) require updating iteration logic, filter callbacks, and any `d3` graph-building code that expands the transitive package list

After all type errors are resolved, rebuild the SPA and regenerate the embedded template:

```bash
uv run just frontend-build   # npm ci + type-check + vite build, then rewrites spa_app.html
```

The HTML report always embeds the **latest** version's full profile, so the SPA must read the newest schema.

---

### 7. Tests

**New schema registry test file** — copy `tests/ui/renderers/export/test_json_schema_registry_v1_6.py` and update version strings and structural assertions. Add the new version to `VERSIONS` in `test_json_schema_projection.py` (`test_every_registered_version_is_checked` fails until you do).

**Update existing tests** — hardcoded version strings to update:
- `test_metadata_contains_schema_version_and_timestamp` in `test_json.py`
- `included_versions` in the previous schema registry test files

**New renderer tests** — add a `TestSchemaVersion18` class in `test_json.py` covering:
- Output validates against the new JSON schema, in both profiles
- Any new structural invariants (e.g. deduplication counts, new field presence)
- Backward compat: every older registered version still produces its own shape
  (`TestSchemaVersion15StaysAsReleased` — extend it, or add the sibling for the version you just superseded)
- `TestV16IsAdditiveOverV15`-style check that the new schema removes, retypes and newly requires nothing

---

## Checklist

```
[ ] ExportJsonSchemaVersion.V1_7 added to domain/common.py
[ ] New Pydantic fields tagged SINCE_V1_7 and given a profile decision in models.py
[ ] Record filters that read the new data gated on the declared version
[ ] build_export_data() factory branch added (only if structural)
[ ] export_schema_v1.7.json and export_schema_v1.7_standard.json created
[ ] Every enum in them checked against its emitter; a real export validates against both profiles
[ ] json_schema_registry.py updated + get_latest_version() bumped
[ ] --schema-version Literal widened in cli.py + HELP_SCHEMA_VERSION updated
[ ] .github/workflows/test.yml file lists name the new schema
[ ] frontend/package.json generate:types script updated to v1.7
[ ] npm run generate:types run — src/types/report.ts regenerated, root type renamed at its imports
[ ] npm run type-check passes — all Vue component access sites updated
[ ] New fields carried through the registry/transform/selection chain; isActionable considered
[ ] uv run just frontend-build — SPA rebuilt and spa_app.html regenerated
[ ] Schema registry tests added (full and standard), projection test covers the new version
[ ] Renderer tests updated; older versions pinned by a compat test
```
