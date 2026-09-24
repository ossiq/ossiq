# Security Policy

## Supported versions

OSS IQ is pre-1.0 and ships fixes on the latest release only. Please reproduce an issue
against the most recent version before reporting it.

| Version | Supported |
|---|---|
| Latest release | Yes |
| Anything older | No — upgrade first |

## Reporting a vulnerability

Please report security issues **privately**, via
[GitHub's private vulnerability reporting](https://github.com/ossiq/ossiq/security/advisories/new).
Do not open a public issue for anything exploitable.

Include the OSS IQ version, how it was installed (PyPI, npm, standalone binary, Docker),
and the smallest reproduction you can manage. If OSS IQ misreports risk for a package —
a missed CVE, a wrong deprecation verdict — that is a correctness bug, not a
vulnerability; a normal issue is the right place for it.

Expect an acknowledgement within a week. OSS IQ is maintained by a very small number of
people, so please allow reasonable time for a fix before disclosing publicly.

## Supply chain

OSS IQ forecasts supply-chain risk in other people's dependencies, so its own build is
held to the standard it measures against.

**Every distributed artifact carries [SLSA v1.2](https://slsa.dev/spec/v1.2/build-track-basics)
Build Level 3 provenance.** Artifacts are built inside reusable GitHub Actions workflows
that sign provenance under their own identity, isolated from the workflows that publish
them — so provenance cannot be forged by anyone able to edit only the release plumbing.
The signing key is held by GitHub and Sigstore and is never reachable from a build step.

| Channel | Signer identity |
|---|---|
| PyPI (`ossiq`) | `.github/workflows/reusable-build-dist.yml` |
| GitHub Release binaries | `.github/workflows/reusable-build-binaries.yml` |
| npm (`@ossiq/cli` and platform packages) | `.github/workflows/reusable-build-npm.yml` |

**[How to verify a release →](https://ossiq.github.io/ossiq/how-to/verifying-a-release.html)**
gives the exact `gh attestation verify` commands per channel, plus an honest account of
what each attestation does and does not prove.

Other controls:

- **No long-lived registry credentials** for PyPI or npm — both publish through OIDC
  Trusted Publishing.
- **Pinned, hashed dependencies.** `uv.lock` carries a SHA-256 for every artifact and CI
  installs with `uv sync --locked`. The build backend comes from that lockfile via
  `uv build --no-build-isolation`, because PEP 517 build requirements have no hash
  mechanism of their own.
- **Every GitHub Action pinned to a full commit SHA**, kept current by Dependabot.
- **A CycloneDX 1.5 SBOM** generated from `uv.lock` and attested alongside each artifact.
- **No network access during packaging.** The HTML report's compiled frontend is a
  committed, reviewed source artifact rather than something fetched and rebuilt at
  package time.

The Docker image (`ossiq/ossiq-cli`) installs `ossiq` from PyPI and is outside the
provenance chain above; verify the wheel instead.
