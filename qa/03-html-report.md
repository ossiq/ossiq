# 03 — HTML Report

Run from repo root. Each test generates a file in `reports/`; open in browser to verify.

```bash
mkdir -p reports
```

---

## TC-H01: Generate PyPI HTML report

```bash
uv run hatch run ossiq-cli scan --presentation=html --output=reports/test_report.html testdata/pypi/version-constraint
```

- [ ] File `reports/test_report.html` created with size > 0
- [ ] No crash or traceback

---

## TC-H02: Main dependency table

Open `reports/test_report.html` in browser.

- [ ] Page loads without JS errors in browser console
- [ ] Main dependency table renders with all packages
- [ ] Columns visible: Dependency, CVEs, Drift Status, Installed, Latest, Releases Distance, Time Lag, Version Age
- [ ] Drift status cells are color-coded (red = major, yellow = minor, etc.)

---

## TC-H03: Dependencies explorer

*(If the HTML report has an interactive explorer/detail panel)*

- [ ] Explorer section is visible
- [ ] Clicking a package opens a detail panel
- [ ] CVE information renders if present

---

## TC-H04: npm HTML report

```bash
uv run hatch run ossiq-cli scan --presentation=html --output=reports/npm_report.html testdata/npm/project1
```

- [ ] File generated
- [ ] npm packages appear in the table (not an empty table)

---

## TC-H05: Report with yanked/deprecated packages

```bash
uv run hatch run ossiq-cli scan --presentation=html --output=reports/yanked_report.html testdata/pypi/yanked
uv run hatch run ossiq-cli scan --presentation=html --output=reports/deprecated_report.html testdata/npm/deprecated
```

- [ ] Yanked packages are visually indicated in the HTML table
- [ ] Deprecated packages are visually indicated in the HTML table
