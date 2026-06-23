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

---

## TC-H06: HTML report — transitive impact sub-rows

```bash
uv run hatch run ossiq-cli scan --presentation=html --output=reports/solver_report.html testdata/pypi/version-constraint
```

Open `reports/solver_report.html` in browser.

- [ ] Page loads without JS errors in browser console
- [ ] Direct dep rows that have a recommended version show an inline expandable control (chevron, button, or similar)
- [ ] Expanding a row reveals the transitive impact detail: package names and version arrows (e.g. `urllib3 1.26 → 2.2`)
- [ ] No `undefined` or blank cells in the expanded sub-rows
- [ ] `⚠` and `✗` markers visible on conflicting / non-actionable rows if any exist

---

## TC-H07: Explorer — D3 tree renders

Open `reports/solver_report.html` in browser and navigate to the Transitive Dependencies view/tab.

- [ ] SVG canvas is visible (not blank/white)
- [ ] At least one node circle is rendered
- [ ] No JS errors in the browser console

---

## TC-H08: Explorer — click node enters focus mode

Click any node in the D3 tree.

- [ ] Clicked node switches to solid fill (fill color equals its stroke color)
- [ ] Ancestor path to root is highlighted at full opacity
- [ ] Unrelated nodes and edges dim to ≤15% opacity
- [ ] Sidebar detail panel opens showing the package name and installed version
- [ ] Clicking the SVG background exits focus mode and restores all nodes

---

## TC-H09: Explorer — Alt+Click collapses and expands a subtree

Alt+Click a node that has visible children.

- [ ] Child nodes disappear; node grows to a larger solid-dark disc (collapsed indicator)
- [ ] Second Alt+Click restores the subtree with a brief animation

---

## TC-H10: Explorer — Super Node navigation and breadcrumb

Generate an npm report for a project with deep transitive deps if `solver_report.html` has no Super Nodes (circles with a `+N` badge):

```bash
uv run hatch run ossiq-cli scan --presentation=html --output=reports/npm_report.html testdata/npm/project1
```

Click a Super Node (`+N` badge circle).

- [ ] Tree re-renders rooted at that package's children
- [ ] Breadcrumb trail appears in the toolbar (e.g. `project → package`)
- [ ] Phantom root circle and dashed back-edge line are visible one column left of the current root

---

## TC-H11: Explorer — breadcrumb / back navigation

*(Precondition: navigated view from TC-H10)*

Click the back-edge dashed line, phantom root circle, or an ancestor in the breadcrumb.

- [ ] Tree returns to the parent level
- [ ] Breadcrumb shrinks by one entry
- [ ] Phantom root disappears

---

## TC-H12: Explorer — search and filter controls

In the Transitive Dependencies view:

1. Type at least 3 characters of a known package name in the search field.
   - [ ] Tree filters to show only matching branches and their ancestors; non-matching nodes are hidden
2. Click the **CVE** toggle (skip if no CVE-affected packages exist in the dataset).
   - [ ] Only red (CVE-affected) nodes remain visible
3. Click **Clear filters** (button appears when any filter is active).
   - [ ] Full tree is restored; search field is empty; toggles are inactive

---

## TC-H13: Explorer — zoom controls

- [ ] Clicking the `+` zoom button scales the tree visibly larger
- [ ] Clicking the `1:1` reset button returns to the original scale with the tree fully visible
