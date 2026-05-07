# 05 — Export: JSON and CSV

Run from repo root.

```bash
mkdir -p reports
```

---

## TC-E01: JSON export — default filename

```bash
uv run hatch run ossiq-cli export testdata/pypi/version-constraint
```

- [ ] File `ossiq_export_report_*.json` created in current directory
- [ ] File is valid JSON:
  ```bash
  python -m json.tool ossiq_export_report_*.json > /dev/null && echo OK
  ```

---

## TC-E02: JSON export — explicit output, field validation

```bash
uv run hatch run ossiq-cli export --output-format=json --output=reports/test_export.json testdata/pypi/version-constraint
```

- [ ] File `reports/test_export.json` created
- [ ] Top-level keys present: `schema_version`, `export_timestamp`, `project_name`, `registry`, `packages`
- [ ] `packages` is a non-empty array
- [ ] Each package object contains: `name`, `installed_version`, `latest_version`, `cve`, `is_yanked`, `is_prerelease`, `constraint_type`, `purl`

---

## TC-E03: CSV export

```bash
uv run hatch run ossiq-cli export --output-format=csv --output=reports/test_export.csv testdata/pypi/version-constraint
```

- [ ] File `reports/test_export.csv` created
- [ ] First row is a header row (column names, not data)
- [ ] Row count (excluding header) matches package count visible in console scan output
- [ ] Key columns present: package name, installed version, latest version, CVE count

---

## TC-E04: JSON export — npm project

```bash
uv run hatch run ossiq-cli export --output-format=json --output=reports/npm_export.json testdata/npm/project1
```

- [ ] `registry` field value is `"npm"`
- [ ] Package names and versions match what console scan shows

---

## TC-E05: Production flag in export

```bash
# Full export
uv run hatch run ossiq-cli export --output-format=json --output=reports/full_export.json testdata/pypi/version-constraint

# Production-only export
uv run hatch run ossiq-cli export --production --output-format=json --output=reports/prod_export.json testdata/pypi/version-constraint
```

- [ ] `prod_export.json` has fewer entries in `packages` than `full_export.json`
- [ ] Dev/optional packages absent from production export
