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
cooldown with `⚠`.
