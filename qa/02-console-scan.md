# 02 — Console: scan + package Commands

Run from repo root.

**Precondition — verify testdata exists:**

```bash
ls testdata/pypi/version-constraint testdata/pypi/yanked testdata/npm/deprecated testdata/npm/project1 testdata/mixed
```

---

## TC-C01: Basic PyPI scan

```bash
uv run hatch run ossiq-cli scan testdata/pypi/version-constraint
```

- [ ] "Production Dependency Drift Report" table renders
- [ ] Columns present: Dependency, CVEs, Drift Status, Installed, Latest, Releases Distance, Time Lag, Version Age
- [ ] Drift Status has values (Major / Minor / Patch / Latest / N/A)
- [ ] No crash or traceback

---

## TC-C02: Basic npm scan

```bash
uv run hatch run ossiq-cli scan testdata/npm/project1
```

- [ ] npm packages appear in table
- [ ] No crash

---

## TC-C03: Production flag

```bash
uv run hatch run ossiq-cli scan --production testdata/pypi/version-constraint
```

- [ ] Settings shows `production: True`
- [ ] Dev/optional dependencies absent from output

---

## TC-C04: Yanked packages

```bash
uv run hatch run ossiq-cli scan testdata/pypi/yanked
```

- [ ] Package with yanked installed version shows `[YANKED]` annotation in Installed column
- [ ] Drift Status still renders (not blank)

---

## TC-C05: Deprecated packages (npm)

```bash
uv run hatch run ossiq-cli scan testdata/npm/deprecated
```

- [ ] Deprecated packages show `[DEPRECATED]` annotation in Installed column

---

## TC-C06: CVE display

> Use any project known to have packages with CVEs, or a real-world project (e.g. a project pinned to an old version of `requests` or `lodash`).

```bash
uv run hatch run ossiq-cli scan <project-with-cves>
```

- [ ] CVEs column shows a red count for affected packages
- [ ] Packages with 0 CVEs show an empty CVEs cell

---

## TC-C07: Prerelease installed version annotation

> Requires a testdata project where at least one installed version is a prerelease. Skip if none available.

```bash
uv run hatch run ossiq-cli scan <project-with-prerelease-dep>
```

- [ ] Prerelease version shows `[pre]` annotation in Installed column

---

## TC-C08: Allow-prerelease flag

```bash
# Without
uv run hatch run ossiq-cli scan testdata/pypi/version-constraint

# With
uv run hatch run ossiq-cli scan --allow-prerelease testdata/pypi/version-constraint
```

- [ ] Without: Latest column shows only stable versions (no `a`, `b`, `rc`, `.dev` suffixes)
- [ ] With: Latest may show a prerelease version; run completes without crash

---

## TC-C09: `package` command — known package

```bash
uv run hatch run ossiq-cli package testdata/pypi/version-constraint requests
```

- [ ] Package detail view renders (name, installed version, CVEs, drift info)
- [ ] Transitive CVE groups shown if any
- [ ] No crash

---

## TC-C10: `package` command — unknown package

```bash
uv run hatch run ossiq-cli package testdata/pypi/version-constraint this-package-does-not-exist
```

- [ ] Error message shown (not a raw Python traceback)
- [ ] Exit code non-zero
