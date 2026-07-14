# 07 — Plan Command: --pin-all, --rewrite-versions, --override, --ignore

`plan` shows solver recommendations read-only and never touches files. `apply` executes them
in-process (rewrites the manifest, runs `uv lock`/`uv sync` or `npm install`, rolls back on
failure). Both share the same option surface.

Run from repo root. UV/NPM specifier-rewrite tests require network (registry lookups).

**Precondition:**

```bash
uv run hatch run ossiq-cli plan --help
uv run hatch run ossiq-cli plan --help | grep -E "pin-all|rewrite-versions|override|ignore"
uv run hatch run ossiq-cli apply --help | grep -E "yes|pin-all|rewrite-versions|override"
```

- [ ] `plan --help` lists `--pin-all`, `--rewrite-versions`, `--override`, `--ignore` (NOT `--script`)
- [ ] `--pin-all` listed in `plan --help`
- [ ] `--rewrite-versions` listed in `plan --help`
- [ ] `--override` listed in `plan --help`
- [ ] `--yes` / `-y` listed in `apply --help`
- [ ] `--override` listed in `apply --help`
- [ ] `--ignore` / `-i` listed in both `plan` and `apply` help outputs

---

## TC-U01: `--ignore/-i` on status — recommendation excluded, package still visible

```bash
# Identify a package with a pending recommendation first
uv run hatch run ossiq-cli status testdata/pypi/version-constraint

# Now ignore it (substitute actual package name)
uv run hatch run ossiq-cli status --ignore requests testdata/pypi/version-constraint
```

- [ ] Ignored package row still appears in the table (not hidden)
- [ ] Recommended cell for the ignored package is empty (no recommendation generated)
- [ ] All other packages retain their recommendations
- [ ] No crash or traceback

---

## TC-U02: `--ignore/-i` on plan — package absent from plan

```bash
uv run hatch run ossiq-cli plan --ignore requests testdata/pypi/version-constraint
```

- [ ] `requests` does not appear in the plan table
- [ ] Other packages (if any) still appear in plan
- [ ] No crash

---

## TC-U03: `--ignore/-i` on export — flag accepted, no crash

```bash
uv run hatch run ossiq-cli export --ignore requests --output-format=json --output=reports/ignore_export.json testdata/pypi/version-constraint
```

- [ ] Export completes without crash
- [ ] Output file is valid JSON

---

## TC-U04: `--ignore/-i` on info — flag accepted, no crash

```bash
uv run hatch run ossiq-cli info pydantic testdata/pypi/version-constraint --ignore requests
```

- [ ] Command completes without crash
- [ ] Detail view renders for `pydantic`

---

## TC-U05: UV smart specifier — NARROWED (`~=`): `apply` rewrites in-place

> This test modifies `pyproject.toml`. Restore with `git checkout` afterwards (see cleanup below).

```bash
uv run hatch run ossiq-cli apply --yes testdata/pypi/version-constraint
grep 'requests' testdata/pypi/version-constraint/pyproject.toml
```

`requests` is declared as `~= 2.31.0` (NARROWED):

- [ ] `pyproject.toml` specifier rewritten to `requests~=<recommended_version>`, preserving the `~=` operator
- [ ] `uv.lock` resolves `requests` to the recommended version

```bash
# Cleanup
git checkout testdata/pypi/version-constraint/pyproject.toml testdata/pypi/version-constraint/uv.lock
```

---

## TC-U06: UV smart specifier — DECLARED (`>=`): lockfile-only update

> This test modifies `pyproject.toml`/`uv.lock`. Restore with `git checkout` afterwards.

```bash
uv run hatch run ossiq-cli apply --yes testdata/pypi/version-constraint
grep 'pydantic' testdata/pypi/version-constraint/pyproject.toml
```

`pydantic` is declared as `>= 2.0.0` (DECLARED):

- [ ] `pyproject.toml` specifier for `pydantic` is unchanged (no edit — lockfile-only update)
- [ ] `uv.lock` still resolves `pydantic` to the recommended version (applied via `uv lock --upgrade-package`)

```bash
# Cleanup
git checkout testdata/pypi/version-constraint/pyproject.toml testdata/pypi/version-constraint/uv.lock
```

---

## TC-U07: UV `--pin-all` flag — all direct deps pinned exactly with `==`

> This test modifies `pyproject.toml`/`uv.lock`. Restore with `git checkout` afterwards.

```bash
uv run hatch run ossiq-cli apply --pin-all --yes testdata/pypi/version-constraint
```

- [ ] Every direct dependency with a pending update is rewritten to `==<version>` (exact pin) in `pyproject.toml`, regardless of its original operator
- [ ] No crash

```bash
# Cleanup
git checkout testdata/pypi/version-constraint/pyproject.toml testdata/pypi/version-constraint/uv.lock
```

---

## TC-U08: NPM `apply` — manifest rewrite + `npm install --ignore-scripts`

> This test modifies `package.json`. Restore with `git checkout` afterwards.

```bash
uv run hatch run ossiq-cli apply --yes testdata/npm/version-constrained
git diff testdata/npm/version-constrained/package.json
```

- [ ] Direct dependency specifiers in `package.json` updated to their recommended versions
- [ ] Transitive-only changes are added to the `overrides` block in `package.json`
- [ ] `npm install --ignore-scripts` runs (visible in terminal output; `package-lock.json`/`node_modules` updated)
- [ ] If `npm install` fails, `package.json` is restored to its pre-run state
- [ ] No crash

```bash
# Cleanup
git checkout testdata/npm/version-constrained/package.json testdata/npm/version-constrained/package-lock.json
```

---

## TC-U12: NPM `--pin-all` — direct deps pinned to exact versions via `apply`

> This test modifies `package.json`. Restore with `git checkout` afterwards.

```bash
uv run hatch run ossiq-cli apply --pin-all --yes testdata/npm/version-constrained
```

- [ ] Updated direct dependency entries in `package.json` are rewritten to exact versions (no `^`, `~`, or range operators)
- [ ] Exact versions match the recommended versions from `plan`
- [ ] No crash

```bash
# Cleanup
git checkout testdata/npm/version-constrained/package.json testdata/npm/version-constrained/package-lock.json
```

---

## TC-U13: NPM caret spec — same major version stays resolvable after `apply`

> This test modifies `package.json`. Restore with `git checkout` afterwards.

```bash
uv run hatch run ossiq-cli apply --yes testdata/npm/version-constrained
```

Find a package in `testdata/npm/version-constrained/package.json` that uses `^major.x.x` and whose recommended version is within the same major:

- [ ] No crash
- [ ] `package-lock.json` reflects the recommended version for that package after `npm install`

```bash
# Cleanup
git checkout testdata/npm/version-constrained/package.json testdata/npm/version-constrained/package-lock.json
```

---

## TC-U14: Removed flag `--script` is rejected

`plan --script` and the entire script-generation / `ossiq helpers` surface were removed (GH-94);
`apply` is now the only way to execute updates, and it does so in-process.

```bash
uv run hatch run ossiq-cli plan --script testdata/pypi/version-constraint 2>&1 | head -5
```

- [ ] Command exits with a non-zero code
- [ ] Error output contains "No such option" or similar — the flag no longer exists
- [ ] No Python traceback

---

## TC-U15: `plan` shows a table only, never touches files

```bash
uv run hatch run ossiq-cli plan testdata/pypi/version-constraint
```

- [ ] Plan table is printed (Package / Current / Recommended columns visible)
- [ ] No bash script block printed (script generation was removed — `plan` is read-only)
- [ ] `pyproject.toml` unchanged (`git diff testdata/pypi/version-constraint/pyproject.toml` is empty)
- [ ] No crash

---

## TC-U17: `plan --help` shows plan options

```bash
uv run hatch run ossiq-cli plan --help
```

- [ ] Output shows plan help text listing `--pin-all`, `--rewrite-versions`, `--override`, `--ignore` (NOT `--script`)
- [ ] No Python traceback
- [ ] Exit code is zero

---

## TC-U18: `apply` shows plan, prompts, and runs (PyPI project)

> This test modifies `pyproject.toml`. Run on a copy or restore with `git checkout` afterwards.

```bash
# First preview
uv run hatch run ossiq-cli plan testdata/pypi/version-constraint

# Then execute (answer 'y' at prompt)
uv run hatch run ossiq-cli apply testdata/pypi/version-constraint
```

- [ ] Plan table appears before the confirmation prompt
- [ ] Prompt reads "Proceed with N updates?" (where N > 0)
- [ ] Answering `n` exits without modifying any files
- [ ] Answering `y` runs `uv lock` and `uv sync` (output visible in terminal)
- [ ] `pyproject.toml` updated after answering `y` (verify with `git diff`)
- [ ] `uv.lock` updated (verify with `git diff`)
- [ ] "Update complete." printed on success
- [ ] No crash

```bash
# Restore
git checkout testdata/pypi/version-constraint/pyproject.toml testdata/pypi/version-constraint/uv.lock
```

---

## TC-U19: `apply --yes` skips confirmation (CI mode)

> This test modifies `pyproject.toml`. Run on a copy or restore with `git checkout` afterwards.

```bash
uv run hatch run ossiq-cli apply --yes testdata/pypi/version-constraint
```

- [ ] No confirmation prompt appears
- [ ] Updates run directly
- [ ] "Update complete." printed on success
- [ ] No crash

```bash
# Restore
git checkout testdata/pypi/version-constraint/pyproject.toml testdata/pypi/version-constraint/uv.lock
```

---

## TC-U20: `--rewrite-versions` includes PINNED deps that are normally frozen

```bash
# Without --rewrite-versions: PINNED deps are frozen and absent from plan
uv run hatch run ossiq-cli plan testdata/pypi/version-constraint

# With --rewrite-versions: PINNED deps appear in plan
uv run hatch run ossiq-cli plan --rewrite-versions testdata/pypi/version-constraint
```

- [ ] Without `--rewrite-versions`: packages with `==x.y.z` specifiers do NOT appear in plan (frozen)
- [ ] With `--rewrite-versions`: packages with `==x.y.z` specifiers DO appear in plan (unfrozen)
- [ ] No crash in either case

---

## TC-U21: `apply` rollback — `pyproject.toml` restored if `uv lock` fails

> Simulate a failure by passing an invalid package path or registry-type mismatch.

```bash
# Make a backup
cp testdata/pypi/version-constraint/pyproject.toml /tmp/pyproject_backup.toml

# Force a failure by using an unreachable registry or an invalid flag combination
# (or temporarily corrupt pyproject.toml mid-test by using a debugger / test hook)

# Verify restoration
diff testdata/pypi/version-constraint/pyproject.toml /tmp/pyproject_backup.toml
```

- [ ] After a failed `apply`, `pyproject.toml` is identical to its pre-run state
- [ ] Error message printed to stderr explaining the failure
- [ ] Exit code non-zero
- [ ] No Python traceback beyond the error message
