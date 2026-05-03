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
├── encoder.py             ConstraintEncoder — produces EncodedProblem (WCNF)
├── weights.py             Constraint weight constants + age_weight()
└── uow_dependencies_solver.py   Public API: solve_direct(), solve_transitive()
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
| L2 | Soft-Hard | `W_ENGINE = 1_000_000` | Engine mismatch (`python`/`node` requirement vs `engine_context`) |
| L3 | Soft | `max(1, 100_000 − age_days)` | Freshness bonus — every eligible candidate |
| L4 | Soft | `W_DEPRECATED = 10_000` | Deprecated flag — penalty on selection |
| L5 | Hard | — | CVE-affected version — transitive pass only |
| L6 | Soft-Hard | `W_VERY_FRESH = 1_000_000` | Published < 7 days ago — transitive pass only |
| L7 | — | *(reserved)* | Health score — not implemented |

Soft clause semantics (defined in `weights.py`, applied in `encoder.py`):
- `soft([+var], W)` — penalty W if this version is **not** selected (encourages selection; L3)
- `soft([-var], W)` — penalty W if this version **is** selected (discourages selection; L2, L4, L6)

Structural clauses per package (encoder):
- **AMO** (At-Most-One): pairwise `[-vi, -vj]` over eligible candidates — exactly one version selected
- **ALO** (At-Least-One): `[v1, v2, …]` over eligible candidates — solver must pick something; omitted when no eligible candidate exists (deliberate UNSAT → `ConflictSet`)

### Version constraint dispatch (encoder.py)

`version_matches()` tries PEP 440 `SpecifierSet` first; falls back to npm semver on `InvalidSpecifier`. Bare npm versions (e.g. `"14"`) are treated as caret ranges (`^14.0.0`). Unparseable constraints pass through (`True`) — unknown format is never a hard block.

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
L3 gives newer versions higher weights. RC2 is weight-sensitive, not order-sensitive, but descending order ensures `var_map` iteration and debug output are intuitively readable.

**On `ConflictSet` — silent `{}`?**  
Returning `{}` lets the scan pipeline always complete and show `Latest` even when the solver conflicts. Phase 6 will surface a user-facing warning identifying the conflicting package(s). Currently only DEBUG-logged.
