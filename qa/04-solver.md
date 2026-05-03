# 04 — HPDR Solver

Run from repo root. All cases require network (registry lookups).

**Precondition:**

```bash
uv run hatch run ossiq-cli scan --help | grep solver
```

- [ ] `--solver` flag listed in help output

---

## TC-S01: Solver activates — PyPI

```bash
uv run hatch run ossiq-cli scan --solver testdata/pypi/version-constraint
```

- [ ] Settings output shows `use_solver: True`
- [ ] "Production Dependency Drift Report" gains a **"Recommended"** column
- [ ] At least one package has a non-empty recommended version
- [ ] No crash

---

## TC-S02: No `--solver` = no Recommended column

```bash
uv run hatch run ossiq-cli scan testdata/pypi/version-constraint
```

- [ ] Settings shows `use_solver: False`
- [ ] No "Recommended" column in any table
- [ ] No "Transitive Safety Recommendations" section

---

## TC-S03: Version constraints respected

```bash
uv run hatch run ossiq-cli scan --solver testdata/pypi/version-constraint
```

Cross-check one constrained package against `testdata/pypi/version-constraint/pyproject.toml`:

- [ ] Recommended version falls within declared constraint range (e.g. `>=1.0,<2.0` → recommended is `1.x.x`)
- [ ] Pinned packages (`==X.Y.Z`) have an empty Recommended cell

---

## TC-S04: Yanked versions excluded

```bash
uv run hatch run ossiq-cli scan --solver testdata/pypi/yanked
```

- [ ] No recommended version has a `[YANKED]` annotation
- [ ] If a package has only yanked candidates, Recommended cell is empty

---

## TC-S05: Prerelease not recommended by default

```bash
# Run 1 — default (no prerelease)
uv run hatch run ossiq-cli scan --solver testdata/pypi/version-constraint

# Run 2 — prerelease allowed
uv run hatch run ossiq-cli scan --solver --allow-prerelease testdata/pypi/version-constraint
```

- [ ] Run 1: No recommended version contains `a`, `b`, `rc`, or `.dev` suffixes
- [ ] Run 2: May contain prerelease suffixes; completes without crash

---

## TC-S06: npm solver

```bash
uv run hatch run ossiq-cli scan --solver testdata/npm/version-constrained
```

- [ ] "Recommended" column appears
- [ ] Recommended versions are valid semver strings (e.g. `1.2.3`, `2.0.0`)
- [ ] No crash

---

## TC-S07: Deprecated packages get non-deprecated alternative

```bash
uv run hatch run ossiq-cli scan --solver testdata/npm/deprecated
```

- [ ] Deprecated packages show a Recommended version different from the installed `[DEPRECATED]` version

---

## TC-S08: Transitive Safety — CVE-driven

> Use a project with transitive deps known to have CVEs. If none in testdata, use a real-world project pinned to a vulnerable version (e.g. old `pip` or `semver`).

```bash
uv run hatch run ossiq-cli scan --solver <project-with-transitive-cves>
```

- [ ] "Transitive Safety Recommendations" section appears
- [ ] Each row has CVE count > 0 **or** a very fresh install date (< 7 days)
- [ ] Recommended version differs from installed
- [ ] Packages with no CVEs and not fresh are **absent** from the transitive table

---

## TC-S09: Graceful degradation — no crash on conflict

```bash
uv run hatch run ossiq-cli scan --solver testdata/pypi/yanked
uv run hatch run ossiq-cli scan --solver testdata/mixed
```

- [ ] Neither command produces a Python traceback
- [ ] When no recommendation is possible for a package, its Recommended cell is empty (no error message)

---

## TC-S10: Mixed project (PyPI + npm) with solver

```bash
uv run hatch run ossiq-cli scan --solver testdata/mixed
```

- [ ] PyPI recommended versions use PEP 440 format (e.g. `2.32.3`)
- [ ] npm recommended versions use semver format (e.g. `8.1.0`)
- [ ] No cross-ecosystem contamination (PyPI package not recommended for npm dep or vice versa)
