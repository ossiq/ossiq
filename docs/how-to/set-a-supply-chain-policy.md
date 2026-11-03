---
title: Set a supply-chain policy
description: "Add policy lines to the OSS IQ config file so plan, status, add and the MCP tools refuse versions published without the build evidence you require."
---

# Set a supply-chain policy

Add a few lines to the OSS IQ config file. Then `plan`, `status`, `add` and the MCP tools stop
recommending versions that lack the build or source evidence you require.

A stolen registry token is a known way to publish a malicious version. The attacker can publish,
but cannot reproduce the build pipeline the project normally uses. A version with less evidence
than its predecessors is the sign.

## Add a policy to the config file

Policies have no command-line flags. Set them in the [config file](../reference/configuration.md#config-file),
or as environment variables in CI. An environment variable beats the file.

```bash
# ~/.config/ossiq/config
OSSIQ_POLICY_TRUST=no-downgrade           # refuse a version that has less build evidence than an earlier one
OSSIQ_POLICY_MIN_BUILD=provenance         # refuse a version with no signed build attestation
OSSIQ_POLICY_MIN_SOURCE=protected-history # refuse a package whose repository lets history be rewritten
```

Values are case-insensitive, and a blank value turns the rule off. If a value isn't one of the
allowed ones, the command stops with an "Invalid Configuration" message. It names the variable and
lists the allowed values.

## Choose the rules

| Setting | Values | A version or package breaks it when |
|---|---|---|
| `OSSIQ_POLICY_TRUST` | `no-downgrade` | A version has less [build evidence](#build-evidence) than an earlier version in the same major line. Order is publish date. A stable version is compared with earlier stable versions only; a prerelease with everything earlier. |
| `OSSIQ_POLICY_MIN_BUILD` | `none` (default), `provenance`, `trusted-publisher` | A version has less build evidence than the value. |
| `OSSIQ_POLICY_MIN_SOURCE` | `version-controlled`, `protected-history`, `reviewed` | The package's GitHub repository protects its default branch less than the value ([source levels](#source-levels)). Direct dependencies only. |
| `OSSIQ_POLICY_EXCLUDE` | Comma-separated `name` or `name@version` | Never. These are exempt from every rule. |

Turn on `OSSIQ_POLICY_TRUST` first. It asks nothing of packages that never had build evidence, so
it flags only the ones that lost it.

### Build evidence

OSS IQ reads the evidence from the registry's own record of each version.

| Tier | npm | PyPI |
|---|---|---|
| `none` | No provenance attestation | No attestation on one or more of the version's files |
| `provenance` | A signed provenance attestation | Not used: PyPI accepts attestations only from trusted publishing |
| `trusted-publisher` | An attestation, and the publish went through npm's trusted-publisher flow (OIDC) | An attestation on every file of the version |

The *Build* column in the [status report](../reference/reports.md#dependency-table) shows the tier of the installed
version: `trusted`, `attested` or `none`.

### Source levels

OSS IQ reads how GitHub protects the default branch of each direct dependency's repository, as it
is now.

| Level | The default branch |
|---|---|
| `version-controlled` | Is on GitHub, but a force-push or deletion is allowed |
| `protected-history` | Blocks force-pushes and deletion |
| `reviewed` | Blocks force-pushes and deletion, and requires a pull request with at least one approval |

The *Source* column shows `vcs`, `protected` or `reviewed`.

Reading it costs two GitHub requests per direct dependency, cached for 168 hours
(`OSSIQ_STABILITY_CACHE_TTL`). With `--no-stability` and no `OSSIQ_POLICY_MIN_SOURCE`, OSS IQ skips
those requests and the column shows `—`.

## See what the policy does

A version that breaks a rule is never recommended. What you see depends on the command.

| Where | What changes |
|---|---|
| `plan` | The version is left out, and the plan lists it under *Held by your supply-chain policy* with the reason. |
| `status` | When the installed version breaks a rule, a `↳ policy:` line gives the reason and *What's Next* reads **Review provenance**. With `--full`, the field for the rule that failed also turns red: `build ✗ none` for a build rule, `source ✗ vcs` for the source rule. The HTML report shows the same in its *Build* and *Source* columns. |
| `add`, `info` for a package you haven't installed, and the MCP `ossiq_evaluate_dependency` tool | The `POLICY_VIOLATION` warning is critical. `add` stops unless you pass `--force`, and the MCP tool answers `do not install`. If an older version passes, OSS IQ recommends that one instead. |
| JSON export (schema `1.7`) and agent format | `policy_violations` lists the reasons, and `next_action` reads `Review provenance`. The full export also carries `build_provenance` and `source_level`. |

For example, requiring `reviewed` repositories holds back four updates in the `project1` test
project:

```text
Held by your supply-chain policy — newer versions exist, but the policy in the config file rules them out:
  Package        Refused    Why
  @types/node    26.6.6     source repository is protected-history, below the required reviewed
  i18n           0.15.4     source repository is version-controlled, below the required reviewed
  mustache       4.2.0      source repository is version-controlled, below the required reviewed
  vue            3.5.44     source repository is protected-history, below the required reviewed
```

Adding a package that has no provenance, under `OSSIQ_POLICY_MIN_BUILD=trusted-publisher`, stops
like this:

```text
╭──────────────────────────────── Blocked ─────────────────────────────────╮
│ Package 'left-pad' has critical warnings. Use --force to proceed anyway. │
╰──────────────────────────────────────────────────────────────────────────╯
```

## Allow a known exception

List the package, or one version of it, in `OSSIQ_POLICY_EXCLUDE`:

```bash
# ~/.config/ossiq/config
OSSIQ_POLICY_EXCLUDE=chokidar@4.0.3,legacy-package,@types/node@18.0.0
```

A bare name exempts every version. A `name@version` entry exempts that version only. Write npm
names as the registry lists them, scoped names included. For PyPI, `Typing_Extensions` and
`typing-extensions` are the same entry.

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
- **It governs OSS IQ, not your package manager.** `npm install` and `uv add` still install
  whatever you tell them to. The policy changes what OSS IQ recommends and writes.
- **It judges transitive dependencies by build evidence only.** The source rule needs a GitHub
  lookup per repository, so it covers direct dependencies. OSS IQ skips a transitive version the
  policy rules out, but `plan` doesn't name it.
- **It can't see a dependency an update would add.** A new transitive package that the update
  introduces is not checked before you apply it.

## Related

- [Configuration](../reference/configuration.md) lists every setting and where the config file lives.
- [Status report](../reference/reports.md#dependency-table) describes the *Build* and *Source* columns.
- [Verifying a release](verifying-a-release.md) checks a specific artifact's signed provenance yourself.
