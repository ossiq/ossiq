(engines)=
# Engine constraints

Part of [Recommendations and Risk](../recommendations.md).

An "engine" is the runtime a release declares it needs: `engines.node` on npm, `requires-python` on
PyPI. A release that cannot run on your runtime is not a candidate, however new it is.

## Which runtime gets checked

Two things can speak for an engine, and an engine requirement has to hold for **both**:

- the **runtime**: the version the caller states (MCP `runtime`, which is required there, or
  `--engine node=<version>` on the CLI), or else, on the CLI only, the **probe**: the project's
  virtualenv Python, or `node --version` and `npm --version` from `PATH`;
- the **declared floor** — the lowest version the project's own manifest claims to support
  (`requires-python`, `engines.node`), reduced to a concrete version per engine key.

Each engine is held to whichever of the two is **lower**, because that is the one a requirement
fails against first. A project declaring `requires-python = ">=3.11"` on a machine running 3.13 is
held to 3.11: a release needing 3.12 breaks that project's own 3.11 users, and `uv` — which
resolves every Python version in the declared range — will refuse it at `apply` time even though
it runs fine here.

`engine_context_source` then says which side is binding:

| Source | Meaning |
|---|---|
| `provided` | the caller-stated runtime binds for every engine — no declared floor is lower |
| `detected` | the probe binds for every engine — no declared floor is lower |
| `declared` | the manifest floor binds for at least one engine |
| `none` | neither was available; no engine checking happens at all |

Probes are gated by registry: a pure-PyPI scan never spawns `node --version`. A stated runtime
replaces the probe entirely. The MCP server never probes, because its `PATH` belongs to whatever
process launched it, not to the shell the project's tests run in. That difference alone made two
identical requests disagree.

A stated or probed runtime is also checked against the version pins the project keeps for its
own tooling (`.nvmrc`, `.node-version`, `.tool-versions`, `mise.toml`, `volta.node`,
`.python-version`, `.venv/pyvenv.cfg`). A disagreement is reported as `runtime_mismatch`, never
silently resolved: a pin says what developers run, not what the project supports.

Both sides carry `npm` as well as `node`, so a release declaring `engines.npm` is checked too —
the two share one semver grammar and one matcher. `pnpm` and `yarn` are deliberately **not**
evaluated: OSS IQ has no adapter for either, so nothing probes them, and a floor checked on the
declared path but not the detected one would be worse than no check at all. They pass through as
satisfied like any other engine key OSS IQ cannot evaluate.

## One definition, three consumers

`engine_mismatch_reason` is the single engine check. The solver's ranking clauses, the record's
`engine_compatible` flag, and the candidate gate in the strategy pipeline all derive from it, so a
candidate the gate rejects can never disagree with the verdict written onto the record. The reason
string it returns is the one you read:

```
↳ requires node >=22.0.0, checked against 18.0.0 (detected)
```

## `engine_compatible` is tri-state

`False` = a conflict was found. `True` = checked and clear. `None` = **the question was never
answerable** — the release declares no requirement, or there was no runtime to check against.
`None` never means compatible.

## The escape hatch

If the engine gate would reject *every* installable release, OSS IQ drops the gate for that pass
rather than blanking the recommendation — the same rule it applies when every reachable version
carries a CVE. You get the newest version, with `engine_compatible: false` on the record and a red
`↳` row naming the mismatch. **A recommendation can be incompatible with your runtime and still be
the best available answer**; OSS IQ's obligation is to say so, not to hide it.

## What engine handling risks

| Risk | Detail |
|---|---|
| **The runtime may not be the deployed one** | A stated runtime is whatever the caller read. A probed one is whatever is on the `PATH` of the shell running `ossiq`: a developer laptop, not CI or production. Recommendations are gated against that. The pin cross-check catches the wrong shell, not the wrong environment. |
| **The declared floor is a floor, not your runtime** | Whenever the floor is the lower of the two, checks run against the *lowest* version the manifest supports. A package requiring `node >=22` is reported incompatible for a project declaring `>=18`, even if every real deployment runs 24. Raising the floor is the fix; OSS IQ will not quietly assume you meant it. |
| **The check fails open** | An engine key nothing can evaluate (`bun`, say) and an unparseable range both return "satisfied". A malformed `engines` field reads as compatible, not as unknown. |
| **An engine absent from the context is never checked** | The check iterates the runtime versions it has, not the requirements a release declares. A `pnpm` requirement on a project that declares no `pnpm` floor is passed over in silence, exactly as an `npm` requirement was everywhere before it was probed. |
| **`None` is easy to misread** | An absent requirement and a verified pass are different states and look similar in JSON. |
