---
title: Set a supply-chain policy
description: "Commit a .ossiq.yaml with your cooldown, build and source rules and per-package exceptions, so plan, status, add and the MCP tools refuse versions that lack the evidence you require."
---

# Set a supply-chain policy

Commit a `.ossiq.yaml` to your project. Then `plan`, `status`, `add` and the MCP tools stop
recommending versions that are too new, or that lack the build or source evidence you require.
This holds on every machine and in CI.

A stolen registry token is a known way to publish a malicious version. The attacker can publish,
but cannot reproduce the build pipeline the project normally uses. A version with less evidence
than its predecessors is the sign.

## Add a policy to your project

Create `.ossiq.yaml` in the project root and commit it. CI reads it from the checkout, and so does
everyone who scans the project.

```yaml
# .ossiq.yaml
version: 1

policy:
  cooldown:
    days: 7                       # hold back releases younger than 7 days
  build:
    minimum: provenance           # refuse a version with no signed build attestation
    no-downgrade: true            # refuse a version with less build evidence than an earlier one
  source:
    minimum: protected-history    # refuse a package whose repository lets history be rewritten
```

A rule is off unless its block is present. OSS IQ looks for the file in the project directory,
then in each parent directory, and stops at the first directory that holds a `.git`. A monorepo's
root file therefore covers `ossiq status packages/web`.

OSS IQ rejects a file it can't read: an unknown key, a value a rule can't take, or a missing
`version`. The command stops with an "Invalid policy file" message that names each entry
(`policy.build.minimum`) and what is wrong with it. A mistyped key never switches a rule off
unnoticed.

## Choose the rules

| Key | Values | A version or package breaks it when |
|---|---|---|
| `policy.cooldown.days` | A whole number; `0` is no cooldown | The version is younger than that many days. A flag, `OSSIQ_COOLDOWN_PERIOD` or the config file beats this value, so a developer can still pass `--cooldown-period`. |
| `policy.build.no-downgrade` | `true`, `false` | A version has less [build evidence](#build-evidence) than an earlier version in the same major line. Order is publish date. A stable version is compared with earlier stable versions only; a prerelease with everything earlier. |
| `policy.build.minimum` | `none` (default), `provenance`, `trusted-publisher` | A version has less build evidence than the value. |
| `policy.source.minimum` | `version-controlled`, `protected-history`, `reviewed` | The package's GitHub repository protects its default branch less than the value ([source levels](#source-levels)). Direct dependencies only. |
| `policy.exceptions` | A list of [exceptions](#allow-a-known-exception) | Never. Each one lifts the rules it names. |

Turn on `policy.build.no-downgrade` first. It asks nothing of packages that never had build
evidence, so it flags only the ones that lost it.

### Build evidence

OSS IQ reads the evidence from the registry's own record of each version.

| Tier | npm | PyPI |
|---|---|---|
| `none` | No provenance attestation | No attestation on one or more of the version's files |
| `provenance` | A signed provenance attestation | Not used: PyPI accepts attestations only from trusted publishing |
| `trusted-publisher` | An attestation, and the publish went through npm's trusted-publisher flow (OIDC) | An attestation on every file of the version |

The *Bld* column of `status --full` shows the tier of the installed version as a level: `L2` for
`trusted-publisher`, `L1` for `provenance` and `L0` for `none`. The
[HTML report](../reference/reports.md#html-report) shows the words `trusted`, `attested` and `none`.

### Source levels

OSS IQ reads how GitHub protects the default branch of each direct dependency's repository, as it
is now.

| Level | The default branch |
|---|---|
| `version-controlled` | Is on GitHub, but a force-push or deletion is allowed |
| `protected-history` | Blocks force-pushes and deletion |
| `reviewed` | Blocks force-pushes and deletion, and requires a pull request with at least one approval |

The *Src* column of `status --full` shows `L1` for `version-controlled`, `L2` for `protected-history` and `L3` for
`reviewed`. The HTML report shows `vcs`, `protected` and `reviewed`.

Reading it costs two GitHub requests per direct dependency, cached for 168 hours
(`OSSIQ_STABILITY_CACHE_TTL`). With `--no-stability` and no `policy.source` block, OSS IQ skips
those requests and the column shows `—`.

## See what the policy does

A version that breaks a rule is never recommended. What you see depends on the command.

| Where | What changes |
|---|---|
| `plan` | The version is left out, and the plan lists it under *Held by your supply-chain policy* with the reason. |
| `status` | When the installed version breaks a rule, a `↳ policy:` line gives the reason and *What's Next* reads **Review provenance**. With `--full`, the column for the rule that failed also turns red: `✗L0` in *Bld* for a build rule, `✗L1` in *Src* for the source rule. The HTML report flags the same two columns. |
| `add`, `info` for a package you haven't installed, and the MCP `ossiq_evaluate_dependency` tool | The `POLICY_VIOLATION` warning is critical. `add` stops unless you pass `--force`, and the MCP tool answers `do not install`. If an older version passes, OSS IQ recommends that one instead. |
| JSON export (schema `1.7`) and agent format | `policy_violations` lists the reasons, and `next_action` reads `Review provenance`. The full export also carries `build_provenance` and `source_level`. |

For example, requiring `reviewed` repositories holds back four updates in the `project1` test
project:

```text
Held by your supply-chain policy — newer versions exist, but the policy in .ossiq.yaml rules them out:
  Package        Refused    Why
  @types/node    26.6.6     source repository is protected-history, below the required reviewed
  i18n           0.15.4     source repository is version-controlled, below the required reviewed
  mustache       4.2.0      source repository is version-controlled, below the required reviewed
  vue            3.5.44     source repository is protected-history, below the required reviewed
```

Adding a package that has no provenance, under `policy.build.minimum: trusted-publisher`, stops
like this:

```text
╭──────────────────────────────── Blocked ─────────────────────────────────╮
│ Package 'left-pad' has critical warnings. Use --force to proceed anyway. │
╰──────────────────────────────────────────────────────────────────────────╯
```

## Allow a known exception

List an exception for a package that you have reviewed and accept. Each one lifts the rules it
names for the releases it matches:

```yaml
# .ossiq.yaml
policy:
  build:
    minimum: provenance
  exceptions:
    - package: chokidar
      versions: ["4.0.3"]       # omit for every version
      rules: [build]            # omit for every rule: cooldown, build, source
      reason: Published from a laptop during the CI migration; diffed against 4.0.2 by hand.
      expires: 2027-01-31       # optional; the last day the exception holds

    - package: "@myorg/*"       # a glob over registry names
      rules: [cooldown]
      reason: Our own packages; we release and consume them the same day.

    - package: legacy-package
      reason: Archived upstream, so there is no repository to protect.
```

| Key | Required | Meaning |
|---|---|---|
| `package` | yes | A registry name, or a glob such as `@myorg/*`. Write npm names as the registry lists them, scoped names included. For PyPI, `Typing_Extensions` and `typing-extensions` are the same entry. |
| `reason` | yes | Why the exception exists. A reviewer reads this in the pull request that adds it. |
| `versions` | no | Exact versions, quoted so YAML keeps them as strings. Without it, every version. |
| `rules` | no | `cooldown`, `build` or `source`. Without it, all three. |
| `expires` | no | A date, `YYYY-MM-DD`. After that day the rules apply again, and each scan warns that the exception expired. |

An exception for `build` leaves the same release's `source` and `cooldown` rules in force. A
release that an exception covers still counts as history for `no-downgrade`, so it can't hide a
downgrade in the releases after it.

## What a policy does not do

- **It does not verify signatures.** OSS IQ reads the evidence npm and PyPI report. Both
  registries check the Sigstore signature at upload, and OSS IQ doesn't repeat that check.
- **It treats missing data as a pass.** When the registry or GitHub can't say, the *Build* or
  *Source* cell shows `—`, and no rule fires. Not knowing is not a finding. The scan's data
  completeness warning still names the gap.
- **It reports the repository as it is now.** The source level is how the default branch is
  protected today, not how it was when a version was built. OSS IQ counts classic branch
  protection as blocking force-pushes, because GitHub shows that setting only to repository
  admins. It reads rulesets exactly.
- **The solver still prefers older transitive releases.** A cooldown exception stops `plan` from
  holding a release. It doesn't change which transitive release the solver picks.
- **It governs OSS IQ, not your package manager.** `npm install` and `uv add` still install
  whatever you tell them to. The policy changes what OSS IQ recommends and writes.
- **It judges transitive dependencies by build evidence only.** The source rule needs a GitHub
  lookup per repository, so it covers direct dependencies. OSS IQ skips a transitive version the
  policy rules out, but `plan` doesn't name it.
- **It can't see a dependency an update would add.** A new transitive package that the update
  introduces is not checked before you apply it.

## Related

- [Configuration](../reference/configuration.md#project-policy-file) lists every key in `.ossiq.yaml` and how the cooldown ranks against flags and environment variables.
- [Status report](../reference/reports.md#dependency-table) describes the *Build* and *Source* columns.
- [Verifying a release](verifying-a-release.md) checks a specific artifact's signed provenance yourself.
