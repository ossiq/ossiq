---
title: Cooldown
description: Why OSS IQ waits 7 days before it recommends a new release, and why a CVE or an end-of-life package skips the wait.
---

(cooldown)=
# Cooldown

Part of [Explanation](index.md).

**OSS IQ treats the age of a release as a quarantine. It recommends no release younger than the
cooldown period, unless the installed version has a CVE or the package is end-of-life.**

The cooldown period is `--cooldown-period`, 7 days by default.

## Why fresh releases wait

A supply-chain attack can ride on a freshly published release. An attacker compromises a
maintainer account and pushes a malicious version, and automated update tooling distributes it
before anyone notices. The cooldown withholds a release until it has survived in public for a
while.

The wait applies to both kinds of dependency:

- **Direct.** OSS IQ recommends the newest release that is at least as old as the cooldown. When
  every newer release is younger, OSS IQ recommends none, and `plan` lists the package under
  *Held for cooldown*.
- **Transitive.** The solver penalizes fresh releases, and `plan` withholds any pick that is still
  younger than the cooldown.

## A CVE or end-of-life outranks the wait

The quarantine creates one tension: what if the quarantined release fixes a CVE? OSS IQ resolves
it in favor of the known risk, because a concrete vulnerability outweighs the statistical risk of
a fresh release.

A direct dependency skips the wait when the tier you run admits an `exploitable_cve` or
`end_of_life` motive for it. [Motives](../recommendations/motives.md) defines both. A transitive
package skips the wait when its installed version carries a CVE.

The plan shows every skipped wait. A package whose installed version carries a CVE gets a `CVE`
tag, and a pick younger than the cooldown gets this note:

```text
↳ cooldown bypassed — installed version has a known CVE or is end-of-life
```

To decide by hand, you have two options:

- `--update-strategy security` limits the run to the nearest release that clears the CVE.
- `--override <package>==<version>` forces a release you have vetted. It bypasses the solver and
  the cooldown.

## New transitive dependencies sit outside the cooldown

The native package manager resolves a package that enters the tree for the first time, so OSS IQ
can't hold it. The plan shows the age of each new package and flags the ones younger than the
cooldown with `⚠`. pnpm is the exception, as the next section explains.

## pnpm holds new dependencies to the cooldown

`apply` and `add` run pnpm with the cooldown period as its `minimumReleaseAge`. For each new
package, pnpm then picks a release at least that old, where the version range allows one. The plan
says so in a note after the new-dependencies table, in place of the warning that the package sits
outside the cooldown. `--cooldown-period 0` turns this off.

How pnpm treats a package with no old-enough release depends on your own settings:

- **No `minimumReleaseAge` of your own, or `minimumReleaseAgeStrict: false`.** pnpm 11 and later
  fall back to the younger release. pnpm 10 has no `minimumReleaseAgeStrict` and refuses.
- **A strict `minimumReleaseAge` of your own.** It stays strict. OSS IQ raises the age to the
  cooldown if yours is shorter, and pnpm refuses a package with no old-enough release.
- **A longer `minimumReleaseAge` of your own.** Yours applies.

When pnpm refuses, `apply` or `add` stops and restores `package.json`, `pnpm-lock.yaml` and
`pnpm-workspace.yaml`. The error points at `--cooldown-period 0`.

The releases the plan installs are exempt from the cooldown age, and so are the releases already
in your lockfile. OSS IQ adds a `name@version` entry to `minimumReleaseAgeExclude` in
`pnpm-workspace.yaml` for each one that a later plain `pnpm install` refuses without it, keeping
your comments:

- a release the plan installs that is younger than the cooldown;
- a locked release younger than your `minimumReleaseAge`, or younger than a day if you set none.

Without these entries, a plain `pnpm install` fails on pnpm 11 and later. Those versions check every
locked release against the age. pnpm 10 reads the exclude list only from this file.

A strict `minimumReleaseAge` of your own still applies to all of these, because OSS IQ only lifts
the age it added. The one exception is an `--override` version: OSS IQ exempts it even when your
rule refuses it, including under `--cooldown-period 0`, and `plan` says so when you pass it.
