# Verifying a release

Every OSS IQ artifact is built by a reusable GitHub Actions workflow that signs
[SLSA](https://slsa.dev/spec/v1.2/build-track-basics) build provenance over the bytes it
produced. This page shows how to check that what you installed is what those workflows
built.

You need [`gh`](https://cli.github.com/) 2.49 or newer. Replace `X.Y.Z` with the version
you are verifying.

## Why `--signer-workflow` matters

`--signer-workflow` is the part that makes this a Build L3 check rather than a Build L2
one. OSS IQ builds artifacts inside reusable workflows (`reusable-build-*.yml`) and
publishes them from separate top-level workflows. The signing identity in the certificate
is the *reusable* workflow, which the publishing workflow cannot impersonate — so
provenance cannot be forged by anyone who can only edit the release plumbing.

Verifying without `--signer-workflow` still proves the artifact came from this repository,
but not that it came from the isolated builder. Always pass it.

```{warning}
These workflow filenames are part of OSS IQ's public interface. If a verification command
here ever fails with an identity mismatch after an upgrade, check this page for the
release you are verifying rather than assuming the artifact is bad.
```

## PyPI (wheel and sdist)

```bash
pip download --no-deps --only-binary :all: ossiq==X.Y.Z    # wheel
pip download --no-deps --no-binary :all: ossiq==X.Y.Z      # sdist

gh attestation verify ossiq-X.Y.Z-py3-none-any.whl \
  --repo ossiq/ossiq \
  --signer-workflow ossiq/ossiq/.github/workflows/reusable-build-dist.yml

gh attestation verify ossiq-X.Y.Z.tar.gz \
  --repo ossiq/ossiq \
  --signer-workflow ossiq/ossiq/.github/workflows/reusable-build-dist.yml
```

PyPI also stores its own [PEP 740](https://peps.python.org/pep-0740/) attestations, shown
per file on the release page at `https://pypi.org/project/ossiq/X.Y.Z/#files`. Those are a
weaker claim — see [what each attestation proves](#what-each-attestation-proves).

## Standalone binaries

```bash
gh release download vX.Y.Z --repo ossiq/ossiq \
  --pattern 'ossiq-*.tar.gz' --pattern SHA256SUMS

sha256sum -c SHA256SUMS

gh attestation verify ossiq-linux-x64.tar.gz \
  --repo ossiq/ossiq \
  --signer-workflow ossiq/ossiq/.github/workflows/reusable-build-binaries.yml
```

Repeat for whichever of `darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64` or
`win32-x64` you downloaded.

## npm

```bash
# npm's own registry provenance, for everything in the install tree
npm audit signatures

# Re-download the published tarball and check OSS IQ's build provenance over it
npm pack @ossiq/cli@X.Y.Z
gh attestation verify ossiq-cli-X.Y.Z.tgz \
  --repo ossiq/ossiq \
  --signer-workflow ossiq/ossiq/.github/workflows/reusable-build-npm.yml
```

`npm pack` re-downloads the registry tarball byte for byte, which is why the attestation
made at build time still matches. The platform packages verify the same way — for example
`npm pack @ossiq/cli-linux-x64@X.Y.Z` giving `ossiq-cli-linux-x64-X.Y.Z.tgz`.

## SBOM

Each Python artifact also carries a CycloneDX 1.5 SBOM, generated from `uv.lock` and so
describing exactly the hash-pinned dependency set the artifact was built against.

```bash
gh attestation verify ossiq-X.Y.Z-py3-none-any.whl \
  --repo ossiq/ossiq \
  --predicate-type https://cyclonedx.org/bom

# Read it
gh attestation download ossiq-X.Y.Z-py3-none-any.whl \
  --repo ossiq/ossiq --predicate-type https://cyclonedx.org/bom
```

## What each attestation proves

| Claim | Signed by | Covers | Level |
|---|---|---|---|
| `reusable-build-dist.yml` provenance | GitHub / Sigstore, identity = the reusable workflow | The exact sdist and wheel bytes | Build L3 |
| `reusable-build-binaries.yml` provenance | GitHub / Sigstore, identity = the reusable workflow | Each platform's `.tar.gz` | Build L3 |
| `reusable-build-npm.yml` provenance | GitHub / Sigstore, identity = the reusable workflow | Each published `.tgz` | Build L3 |
| CycloneDX SBOM attestation | GitHub / Sigstore | The dependency set, from `uv.lock` | — |
| PyPI PEP 740 attestation | Sigstore, identity = `release.yml` | The uploaded files | Build L2 |
| npm registry provenance | Sigstore, via npm's infrastructure, identity = `binaries.yml` | The published tarball | Build L2 |

The last two are signed by workflows OSS IQ's maintainers edit directly, which is what
makes them L2: the signing identity is not isolated from the people who control the build
definition. They are kept because they are what registry tooling checks natively
(`npm audit signatures`, PyPI's file listing), and because they are useful corroboration.
The L3 claim rests on the `reusable-build-*.yml` attestations.

### Not covered

- **The Docker image** (`ossiq/ossiq-cli`) is built by installing `ossiq==X.Y.Z` from PyPI,
  so it is outside this chain. Verify the wheel instead: the image contains it, but the
  image's own build does not attest it.
- **Reproducibility.** These attestations say who built an artifact and from what source,
  not that rebuilding reproduces identical bytes. The build is deterministic in the inputs
  that matter — `uv.lock` is hash-pinned, the SPA template is committed rather than rebuilt,
  and `SOURCE_DATE_EPOCH` is the commit time — but bit-for-bit reproducibility is not a
  claim OSS IQ currently makes.

## If verification fails

`gh attestation verify` failing is not automatically evidence of tampering. In order of
likelihood:

1. **Wrong version.** The attestation is over specific bytes; a different version fails.
2. **Wrong `--signer-workflow` for that release.** Check this page as of the version you
   are verifying.
3. **A repackaged artifact.** A wheel rebuilt by a mirror or a corporate proxy is a
   different file and will not match.
4. **No attestation exists.** Releases before the SLSA L3 work have none. Verify with
   `gh attestation list --repo ossiq/ossiq` before concluding a check failed.

If none of those explain it, please report it — see [SECURITY.md](https://github.com/ossiq/ossiq/blob/main/SECURITY.md).
