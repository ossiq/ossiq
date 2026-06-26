# HPDR — High-Performance Dependency Resolver

Weighted MaxSAT solver that recommends the best version for each dependency: the highest version satisfying all hard constraints while maximising freshness and avoiding deprecated/unsafe packages.

---

## Module Map

```
solver/
├── driver.py              Types + AbstractSolverDriver ABC
├── driver_pysat.py        VarAllocator + PySATDriver (RC2 concrete impl)
├── kernel.py              HPDRKernel — thin delegating wrapper
├── problem.py             SolverProblem, CandidateVersion, PackageConstraint
├── universe.py            SolvablePool — builds SolverProblem from registry
├── version_matchers.py    npm semver + PEP 440 range matching — raw constraint → bool
├── encoder.py             ConstraintEncoder — produces EncodedProblem (WCNF)
├── weights.py             Constraint weight constants + age_weight()
└── dependencies_solver.py       Public API: solve_direct(), solve_transitive()
```

---

## Inputs

### `solve_direct(deps, registry, engine_context)`

| Argument | Type | Description |
|---|---|---|
| `deps` | `Sequence[_DepLike]` | Direct dependency descriptors from the scan pass |
| `registry` | `AbstractPackageRegistryApi` | Registry with warm in-memory cache (no extra HTTP) |
| `engine_context` | `dict[str, str]` | Project runtime versions, e.g. `{"python": "3.11.9"}` — currently `{}` (L2 inactive until Phase 6) |

`_DepLike` is a structural Protocol requiring: `canonical_name`, `version`, `version_constraint`, `constraint_info`.

### `solve_transitive(transitive_records, registry, engine_context)`

Same registry/engine_context contract. Input is `ScanRecord`-compatible objects exposing `package_name`, `installed_version`, `version_constraint`, `constraint_info`, `cve`, `version_age_days`.

Only **flagged** records are solved: those with ≥1 CVE or `version_age_days < 7`.

---

## Pipeline

```
deps / transitive_records
        │
        ▼
  SolvablePool.build()          universe.py
    – deduplicates by canonical_name (highest ConstraintType priority wins)
    – fetches candidates from warm registry cache
    – filters yanked, unpublished, prerelease (unless allowed)
    – sorts candidates descending (newest first)
    – stamps has_cve=True on affected versions from cve_affected map
        │
        ▼ SolverProblem
  ConstraintEncoder.encode()    encoder.py
    – allocates SAT variables via VarAllocator (1-based bijection)
    – emits hard + soft WCNF clauses (see Constraint Levels below)
        │
        ▼ EncodedProblem
  HPDRKernel.solve()            kernel.py → driver_pysat.py
    – builds pysat WCNF; runs RC2 (Weighted MaxSAT, minimises total penalty)
    – positive vars in model → selected (package, version) pairs
        │
        ▼ SolverResult | ConflictSet
  dict[canonical_name, version] — or {} on ConflictSet (logged DEBUG)
```

---

## Constraint Levels

RC2 **minimises** total cost of violated soft clauses. Hard clauses must be satisfied.

| Level | Kind | Weight | Trigger |
|---|---|---|---|
| L1 | Hard | — | Version outside declared `version_constraint` (PEP 440 or npm semver) |
| L2 | Soft-Hard | `W_ENGINE = 100_000` | Engine mismatch (`python`/`node` requirement vs `engine_context`) |
| L3 | Soft | `max(80_000 − rank × 5_000, 1_000)` | Semver-rank preference — rank 0 = latest eligible semver |
| L4 | Soft | `W_DEPRECATED = 10_000` | Deprecated flag — penalty on selection |
| L5 | Hard | — | CVE-affected version |
| L6 | Soft-Hard | `W_VERY_FRESH = 100_000` | Published < 7 days ago — both direct and transitive passes |
| L7 | — | *(reserved)* | Health score — not implemented |

Soft clause semantics (defined in `weights.py`, applied in `encoder.py`):
- `soft([+var], W)` — penalty W if this version is **not** selected (encourages selection; L3)
- `soft([-var], W)` — penalty W if this version **is** selected (discourages selection; L2, L4, L6)

**L3 — Semver-rank preference (not age-based)**  
Candidates are sorted newest-semver-first by `SolvablePool.build()`. The rank of each eligible
candidate in this sorted list determines its L3 weight: `semver_rank_weight(rank) = max(80_000 − rank × 5_000, 1_000)`.
Rank 0 (highest semver in the constraint) always has the highest preference. The step size (5 000)
is intentionally smaller than `W_DEPRECATED` (10 000), so a deprecated rank-0 version loses to a
clean rank-1 version. Engine mismatch (100 000) overrides any rank gap.

This design handles parallel major-version streams correctly: a freshly-released 7.x patch can
never beat an older 8.x release when both are eligible — semver order dominates calendar age.

**L6 — Very fresh penalty (< 7 days)**  
Applied in both `solve_direct` and `solve_transitive` (both use `penalize_fresh_days=VERY_FRESH_THRESHOLD_DAYS=7`).
A candidate published fewer than 7 days ago receives a 100 000 soft penalty. If an alternative with
the same or adjacent semver rank is ≥ 7 days old, it wins. If no older alternative exists, the fresh
version is still selected (soft penalty, not a hard ban).

Structural clauses per package (encoder):
- **AMO** (At-Most-One): pairwise `[-vi, -vj]` over eligible candidates — exactly one version selected
- **ALO** (At-Least-One): `[v1, v2, …]` over eligible candidates — solver must pick something; omitted when no eligible candidate exists (deliberate UNSAT → `ConflictSet`)

### Version constraint dispatch (encoder.py)

`version_satisfies_constraint(version, constraint, registry)` (in `version_matchers.py`) dispatches directly to PyPI (PEP 440) or npm (semver) based on the `ProjectPackagesRegistry` passed in — no exception-based fallback. Bare npm versions (e.g. `"14"`) are treated as caret ranges (`^14.0.0`). Unparseable constraints pass through (`True`) — unknown format is never a hard block.

---

## Outputs

| Scenario | Return value |
|---|---|
| Solution found | `dict[str, str]` — `{canonical_name: recommended_version}` |
| Hard constraint unsatisfiable (`ConflictSet`) | `{}` — DEBUG-logged; scan always completes |
| No input / no flagged records | `{}` |

`SolverResult.selected` is a list of `(package_name, version)` tuples emitted only for variables that were **true** in the RC2 model and present in `var_map`.

`SolverProblem.fingerprint()` returns a SHA-256 over canonical JSON — reserved as a cache key for future memoisation (Phase 6).

---

## Key Implementation Decisions

**Why Weighted MaxSAT / RC2?**  
The problem is naturally a Partial MaxSAT instance: some constraints are inviolable (declared ranges, CVEs) while others express preferences with quantified importance (age, engine, deprecation). RC2 from `python-sat==1.9.dev2` solves this directly without manual priority heuristics. Reference: [RC2 in the pysat handbook](https://pysathq.github.io/docs/html/api/examples/rc2.html).

**Why a Protocol (`_DepLike`) instead of importing `DependencyDescriptor`?**  
`service/` already imports `unit_of_work/`; importing back would create a cycle. The Protocol is duck-typed and zero-cost at runtime. A future refactor moving `DependencyDescriptor` to `domain/` would let us drop the Protocol (noted as TODO in `universe.py:28`).

**Why is `engine_context={}` in Phase 4/5?**  
L2 clauses only fire when both a candidate's `runtime_requirements` and `engine_context` are non-empty. Passing `{}` makes them structurally inactive without any conditional logic. Population from project metadata (`.python-version`, `.nvmrc`, `sys.version_info`) is deferred to Phase 6.

**Why deduplicate by highest `ConstraintType` priority?**  
The same package can appear as both a direct and transitive dependency with different constraint strengths. `OVERRIDE > ADDITIVE > PINNED > NARROWED > DECLARED` — the strongest constraint wins so the solver sees the binding restriction.

**Why candidates sorted descending (newest first)?**  
L3 assigns rank-based weights where rank 0 (index 0 in the sorted list) = highest semver = highest preference. Descending sort is therefore required for the L3 rank calculation to be meaningful, and also ensures `var_map` iteration and debug output are intuitively readable.

**On `ConflictSet` — silent `{}`?**  
Returning `{}` lets the scan pipeline always complete and show `Latest` even when the solver conflicts. Phase 6 will surface a user-facing warning identifying the conflicting package(s). Currently only DEBUG-logged.
