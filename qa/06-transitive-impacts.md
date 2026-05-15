# 06 — Transitive Impacts

New features: `--security` and `--full` flags, impact sub-rows in direct-dep recommendations,
conflict/non-actionable markers, new-transitive-deps section, and update-command transitive
impact display.

Run from repo root. All cases require network (registry lookups).

**Precondition:**

```bash
uv run hatch run ossiq-cli scan --help
uv run hatch run ossiq-cli update --help
```

- [ ] `--security` flag listed in `scan --help`
- [ ] `--full` flag listed in `scan --help`
- [ ] `--security` flag listed in `update --help`

---

## TC-T01: New flags in help

```bash
uv run hatch run ossiq-cli scan --help | grep -E "security|full"
uv run hatch run ossiq-cli update --help | grep security
```

- [ ] `--security` appears in scan help output
- [ ] `--full` appears in scan help output
- [ ] `--security` appears in update help output

---

## TC-T02: Impact sub-rows in default solver output

```bash
uv run hatch run ossiq-cli scan testdata/pypi/version-constraint
```

- [ ] "Recommended" column present when any package has a pending update or constraint conflict
- [ ] At least one recommendation row has an indented `↳ also updates:` sub-row listing transitive packages with version arrows (e.g. `urllib3 1.26→2.2`)
- [ ] All expected columns present: Dependency, CVEs, Status, Installed, Recommended, Latest, Distance, Time Lag, Version Age
- [ ] No crash or traceback

---

## TC-T03: `--full` flag — show all packages

```bash
# Run 1 — default (hides up-to-date packages with no CVEs)
uv run hatch run ossiq-cli scan testdata/pypi/version-constraint

# Run 2 — with --full (shows every package)
uv run hatch run ossiq-cli scan --full testdata/pypi/version-constraint
```

- [ ] Run 1: Packages with no pending update and no CVEs are absent from the table (or entire table section is absent if all packages are up-to-date)
- [ ] Run 2: All packages shown, including those with 0 CVEs and no pending updates
- [ ] Run 2: Row count ≥ Run 1 row count
- [ ] Run 2: If any package has peer constraints, Peer Constraint Status section shows `ok` and `override` rows (not just violations)
- [ ] No crash on either run

---

## TC-T04: `--security` flag — CVE-only transitive

```bash
# Run 1 — default (all transitive packages with recommendations)
uv run hatch run ossiq-cli scan .

# Run 2 — security filter (CVE-only transitive)
uv run hatch run ossiq-cli scan --security .
```

- [ ] Run 1: Transitive table may include packages with 0 CVEs
- [ ] Run 2: Every row in the transitive table has CVE count > 0
- [ ] Run 2: Row count ≤ Run 1 row count
- [ ] No crash on either run

---

## TC-T05: Conflict and non-actionable markers

```bash
uv run hatch run ossiq-cli scan .
```

Inspect direct-dep recommendation rows:

- [ ] If any package has a constraint conflict: Recommended column shows `[NO RESOLUTION]` and a `↳ no version satisfies: {specs}` sub-row appears below it
- [ ] If any package has no actionable update: its Recommended cell is empty (no error string, no `None`)
- [ ] If neither case applies: all Recommended cells are well-formed version strings or empty (no raw tracebacks)
- [ ] No crash

---

## TC-T06: "New transitive dependencies introduced" section

```bash
uv run hatch run ossiq-cli scan .
```

- [ ] If section "New transitive dependencies introduced by recommended updates" appears:
  - Columns present: Package, Constraint, Required By
  - At least one data row
  - No `None` or blank values in Package or Constraint columns
- [ ] If section is absent: at least one direct-dep recommendation was produced (feature ran; no new deps — valid outcome)
- [ ] No crash

---

## TC-T07: Update command — transitive impact rows

```bash
uv run hatch run ossiq-cli update testdata/pypi/version-constraint
```

```bash
uv run hatch run ossiq-cli update --security testdata/pypi/version-constraint
```

- [ ] `update` (no flags): renders an update plan without crash; at least one entry shows a `↳ also updates:` sub-row, or the new-transitive-deps section appears after the plan table
- [ ] `update` (no flags): "Update Script — review before running" section appears with a bash/pip/npm install block
- [ ] `update --security`: completes without crash; if transitive CVE packages exist they are included; if none, plan is empty or shows only direct deps
- [ ] Any non-actionable package row shows `✗ package_name` in the Package column with no recommended version
