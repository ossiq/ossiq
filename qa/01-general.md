# 01 — General: CLI Basics & Ecosystem Detection

Run from repo root. No network-sensitive operations.

---

## TC-G01: Version and help output

```bash
uv run hatch run ossiq-cli --version
uv run hatch run ossiq-cli --help
uv run hatch run ossiq-cli scan --help
```

- [ ] `--version` prints a semver string
- [ ] `--help` lists `scan`, `package`, `export`, `help` subcommands
- [ ] `scan --help` lists `--solver`, `--production`, `--allow-prerelease`, `--registry-type`, `--presentation`, `--output`

---

## TC-G02: Verbose output

```bash
uv run hatch run ossiq-cli --verbose scan testdata/pypi/version-constraint
```

- [ ] Settings panel is printed before the results table
- [ ] `verbose: True` visible in settings output
- [ ] Without `--verbose`: settings panel absent

---

## TC-G03: Auto-detection — PyPI

```bash
uv run hatch run ossiq-cli scan testdata/pypi/pip-classic
```

- [ ] Header shows `Packages Registry: pypi`
- [ ] No `--registry-type` flag needed

---

## TC-G04: Auto-detection — npm

```bash
uv run hatch run ossiq-cli scan testdata/npm/project1
```

- [ ] Header shows `Packages Registry: npm`

---

## TC-G05: Auto-detection — mixed (PyPI + npm)

```bash
uv run hatch run ossiq-cli scan testdata/mixed
```

- [ ] Both PyPI and npm packages appear in separate tables or clearly marked sections
- [ ] No crash

---

## TC-G06: Registry override

```bash
uv run hatch run ossiq-cli scan --registry-type=pypi testdata/mixed
```

- [ ] Only PyPI packages processed (npm packages absent from output)
- [ ] Settings shows `narrow_registry_type: pypi`

---

## TC-G07: Unit test suite

```bash
uv run just qa
```

- [ ] All tests pass (0 failures; any skips/xfails are expected and documented)
