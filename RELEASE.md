## How to cut new release

This document outlines the process for cutting a new release of the `ossiq` project.
It covers both the standard release procedure and steps for reverting a release if issues arise.

**Important Warning**: Do not reuse the same release version twice. While local operations might appear successful, you will be unable to push a tag with an identical version to the remote repository, even if the previous remote tag has been deleted. Each release must have a unique version number.

### One version, one tag, three registries

You control the version manually with `release.py`. Everything else derives from it:

```
   pyproject.toml  version = "X.Y.Z"      <- you set this, via release.py
          │
          ▼
     git tag vX.Y.Z
          │
          ▼
     GitHub Release "Release vX.Y.Z"
          │
          ├───────────────┬───────────────────────┐
          ▼               ▼                       ╎ (manual, once PyPI is live)
     release.yml     binaries.yml                 ▼
          │               │                  docker.yml
          ▼               ▼                       │
      PyPI ossiq     5 binaries as                ▼
        X.Y.Z        Release assets           Docker Hub
                     + npm packages         ossiq/ossiq-cli
                     @ossiq/cli                  X.Y.Z
                        X.Y.Z
```

There is **one** GitHub Release per version, not one per package. Publishing it triggers
PyPI and npm automatically; **Docker stays a deliberate manual step**, because the image
installs `ossiq==X.Y.Z` *from PyPI* and so cannot be built until that upload has landed.

All three publish the identical version string: PyPI and npm read it from the tagged
commit's `pyproject.toml`, and you pass the same version to the Docker workflow by hand.

You never bump an npm version by hand. `packaging/npm/build_npm_packages.py` reads
`pyproject.toml`, and `binaries.yml` refuses to publish if that file and the release tag
disagree.

### First release after the distribution rework

The next release renames the console script from `ossiq-cli` to `ossiq` and lights up the
npm channel. It needs a one-time bootstrap — see
[Bootstrapping the npm channel](#bootstrapping-the-npm-channel-first-time-only), which is
the full ordered runbook. Every release after it follows the standard procedure below.

One extra caution during that window: **do not build the Docker image against a pre-rename
version.** `docker-entrypoint.sh` now execs `ossiq`, which only exists from this release
onward, so `TAG_VERSION=0.1.10` or earlier produces an image that fails at startup.

### Standard Release Procedure

Follow these steps to create and publish a new release:

1.  **Ensure `production` branch is up-to-date**:
    ```bash    
    git checkout production
    git merge --ff-only main
    ```

2.  **Run the release script (dry-run first)**:
    Use the `release.py` script to manage version bumping and tagging.
    It's highly recommended to perform a dry-run first to preview the changes without actually applying them.
    You can specify the version bump type (`--major`, `--minor`, `--patch`) or explicitly set the version with `--override-version`.
    
    *   **Make sure github token is exported to the environment:
        ```bash
        export OSSIQ_GITHUB_TOKEN=$(gh auth token)
        ```
        
    *   **Dry-run (recommended)**:
        ```bash
        uv run release.py --dry-run --override-version 0.1.3 # or --major/--minor/--patch
        ```
    *   **Execute the release**:
        ```bash
        uv run release.py --override-version 0.1.3 # or --major/--minor/--patch
        ```

    This performs 11 steps locally and remotely: bumps `pyproject.toml`, regenerates
    `CHANGELOG.md`, commits `uv.lock` + `pyproject.toml` + `CHANGELOG.md` as
    `chore(release): X.Y.Z`, creates and pushes tag `vX.Y.Z`, then creates the GitHub
    Release — which is what starts the PyPI and npm workflows.

    Note that only the *tag* is pushed at this point, not the `production` branch. That is
    enough for CI: both workflows check out the tag.

3.  **Watch PyPI and npm publish** (see [Release timeline](#release-timeline) below):
    ```bash
    gh run list --limit 5
    gh run watch
    ```

4.  **Publish the Docker image** — manual, and only once PyPI has the version:
    ```bash
    gh workflow run docker.yml -f tag=vX.Y.Z
    ```
    `latest` defaults to on; untick it (`-f latest=false`) when rebuilding an older
    version. The workflow refuses to start if `ossiq==X.Y.Z` is not yet on PyPI.

5.  **Synchronize `main` with `production`**:
    After a successful release, ensure your `main` branch reflects the changes from `production`.
    ```bash
    git push origin production
    git checkout main
    git merge production
    git push origin main
    ```

6.  **Verify all three channels landed** ([details](#post-release-verification)):
    ```bash
    uvx ossiq@X.Y.Z --version
    npx --yes @ossiq/cli@X.Y.Z --version
    docker run --rm ossiq/ossiq-cli:X.Y.Z --version
    ```

### Release timeline

| Workflow | Trigger | Duration | Depends on |
| --- | --- | --- | --- |
| `release.yml` → PyPI | `release: published` | ~2 min | nothing |
| `binaries.yml` → binaries, then npm | `release: published` | ~15 min | nothing (builds from source) |
| `docker.yml` → Docker Hub | **manual** `workflow_dispatch` | ~20 min | the version being live on PyPI |

The first two start together and run concurrently; neither needs the other.

`docker.yml` is manual on purpose. Its image does `uv pip install ossiq==X.Y.Z` *from
PyPI*, so triggering it off the release event would race the PyPI upload. Releases are
infrequent and deliberate, so you run it yourself once `release.yml` is green — it
fails fast (one API call) if the version is not on PyPI yet.

`binaries.yml` runs in two stages: a 5-way build matrix, then — only after all five
succeed — the npm publish. A single platform failing means **no** npm packages are
published, which is deliberate: publishing a launcher whose `optionalDependencies` point
at a missing platform package would leave that platform permanently broken.

### Post-release verification

```bash
# 1. PyPI
uvx ossiq@X.Y.Z --version

# 2. npm - resolves the platform package and runs the bundled binary
npx --yes @ossiq/cli@X.Y.Z --version

# 3. Docker
docker run --rm ossiq/ossiq-cli:X.Y.Z --version

# 4. The GitHub Release should carry five .tar.gz assets
gh release view vX.Y.Z --json assets --jq '.assets[].name'
```

### If one channel fails

Each channel is recoverable on its own; you do **not** re-cut the release.

| Failed | Recovery |
| --- | --- |
| PyPI (`release.yml`) | Re-run the failed job: `gh run rerun <id> --failed`. A version already on PyPI cannot be replaced — if the artifact itself is wrong, cut a new patch version. |
| Binaries (`binaries.yml`) | Re-run the failed job. Re-running is safe: assets upload with `--clobber`. |
| npm only (binaries built, publish failed) | Download the artifacts and publish by hand — see [Publishing npm manually](#publishing-npm-manually). |
| Docker (`docker.yml`) | Just run it again: `gh workflow run docker.yml -f tag=vX.Y.Z`. Nothing depends on it, so it can be published hours or days later. |

A version that is live on one registry but not another is not an emergency — the channels
are independent. Fix the failed one and the release is complete.

### How to Revert a Release (If Something Goes Wrong)

If an issue is discovered immediately after a release, you can revert the changes using these steps.
**Note**: This should be done with caution, as it rewrites history.

1.  **Revert the version bump commit**:
    This command will undo the last commit, which typically contains the version bump.
    ```bash
    git reset --hard HEAD~1
    ```

2.  **Delete the local tag**:
    Remove the tag associated with the problematic release from your local repository.
    ```bash
    git tag -d vX.Y.Z # Replace vX.Y.Z with the actual version tag, e.g., v0.1.3
    ```

3.  **Delete the remote tag (if already pushed)**:
    If the tag was already pushed to the remote, you must delete it there as well.
    ```bash
    git push origin :refs/tags/vX.Y.Z # Replace vX.Y.Z with the actual version tag
    ```

---

## Channel reference

| Workflow | Publishes | Trigger | Auth |
| --- | --- | --- | --- |
| `release.yml` | PyPI (`ossiq`) | on release | Trusted Publishing (OIDC) |
| `binaries.yml` | Standalone binaries → GitHub Release assets, then npm (`@ossiq/cli` + 5 platform packages) | on release | npm Trusted Publishing (OIDC) |
| `docker.yml` | Docker Hub (`ossiq/ossiq-cli`) | manual | `DOCKER_USERNAME` / `DOCKER_PASSWORD` |

## npm Channel

`@ossiq/cli` ships prebuilt, self-contained binaries so Node users need no Python. The
launcher package depends *optionally* on five platform packages
(`@ossiq/cli-{darwin-arm64,darwin-x64,linux-arm64,linux-x64,win32-x64}`); npm installs
exactly the one matching the host.

Platform coverage gaps, by design: musl-based Linux (Alpine) is not covered — the binaries
link against glibc, and `common-expression-language` publishes no musllinux wheels — and
neither is Windows on ARM. On those platforms the launcher prints instructions to install
from PyPI instead.

### How the npm version stays aligned with PyPI

There is no separate npm version to maintain. On a release, `binaries.yml`:

1. Checks out the tagged commit, so `pyproject.toml` holds the released version.
2. **Fails the publish** if `pyproject.toml` and the release tag disagree.
3. Runs `packaging/npm/build_npm_packages.py`, which reads the version from
   `pyproject.toml` and stamps it into all six generated `package.json` files, pinning the
   launcher's `optionalDependencies` to that exact version.
4. Publishes the five platform packages **first**, then the launcher — in that order,
   because the launcher pins exact versions of packages that must already exist.

So `ossiq X.Y.Z` on PyPI and `@ossiq/cli X.Y.Z` on npm are always the same commit.

**Keep versions to plain `X.Y.Z`.** Python (PEP 440) and npm (semver) agree on that form
but not on prereleases: PyPI normalises `0.2.0-rc.1` to `0.2.0rc1`, while npm keeps
`0.2.0-rc.1`, so the two registries would show different strings for one release. Forms
like `0.2.0rc1` or `0.1.10.post1` are not valid semver at all and npm will reject them
outright.

### Bootstrapping the npm channel (first time only)

Do these in order. Steps 0–1 publish nothing and can be done at any time.

#### Why the Python release comes first

`build_npm_packages.py` reads the version from `pyproject.toml`, which today says
`0.1.10` — and `ossiq==0.1.10` is **already on PyPI, shipping the old `ossiq-cli`
command**. Publishing npm now would put a *different* CLI behind the same version number
on two registries, permanently.

So the first npm publish must carry a version that does not exist yet, which means cutting
the Python release first. Nothing about that release is special — it is the normal
`release.py` flow.

#### Step 0 — Prove the binaries build (publishes nothing)

Only `darwin-arm64` has been verified. Run the matrix and fix anything that fails before
going further; this is the largest unknown in the whole channel.

```bash
gh workflow run binaries.yml
gh run watch
```

The npm publish and release-asset steps are gated on the release event, so a
`workflow_dispatch` run just builds and uploads the five artifacts for inspection.

#### Step 1 — Confirm your npm access (publishes nothing)

```bash
npm whoami                    # must be a member of the `ossiq` org
npm org ls ossiq              # confirm your publish rights
```

All six package names were unclaimed at the time of writing; claiming them happens in
step 3.

#### Step 2 — Cut the Python release as usual

Follow the [Standard Release Procedure](#standard-release-procedure) — e.g.
`uv run release.py --minor`. That publishes `ossiq X.Y.Z` to PyPI with the renamed `ossiq`
command, and `binaries.yml` builds the five binaries and attaches them to the release.

**The `publish-npm` job will fail on this release, and that is expected** — the packages do
not exist yet and no trusted publisher is configured. It is a separate job from
`attach-to-release`, so the binaries still land on the GitHub Release regardless.

#### Step 3 — Publish the six npm packages by hand, once

```bash
npm login                     # supply the 2FA OTP if your org enforces it

gh run download <binaries-run-id> --dir artifacts
python packaging/npm/build_npm_packages.py --artifacts artifacts --output build/npm

# Platform packages FIRST - the launcher pins their exact versions
for dir in build/npm/cli-*; do
  npm publish "$dir" --access public
done

# Launcher LAST
npm publish build/npm/cli --access public
```

Do **not** pass `--provenance` here — provenance requires CI OIDC and will fail locally.
Then verify:

```bash
npx --yes @ossiq/cli@X.Y.Z --version
```

#### Step 4 — Attach trusted publishers

The packages now exist, so their settings pages are available. Publishing uses **npm
Trusted Publishing**, so there is no `NPM_TOKEN` secret to create.

1. Sign in to npmjs.com as an owner of the `ossiq` organization.
2. For **each of the six packages**, open *Settings → Trusted Publisher* and add:
   - Provider: GitHub Actions
   - Repository: `ossiq/ossiq`
   - Workflow: `binaries.yml`
   - Environment: `release`

#### Step 5 — Publish the Docker image

```bash
gh workflow run docker.yml -f tag=vX.Y.Z
```

#### Step 6 — Confirm the automation on the next release

The following release should publish npm with no manual step: `publish-npm` goes green and
`npx @ossiq/cli@<next version>` works. If it does, the bootstrap is complete and this
section never applies again.

### Rehearsing without publishing

`binaries.yml` can be run at any time without cutting a release; only the npm publish and
release-asset steps are gated on the release event.

```bash
gh workflow run binaries.yml
gh run watch

# then, locally:
gh run download <run-id> --dir artifacts
python packaging/npm/build_npm_packages.py --artifacts artifacts --output build/npm
npm publish build/npm/cli-darwin-arm64 --dry-run
npm publish build/npm/cli --dry-run
```

### Publishing npm manually

For recovering when the build matrix succeeded but the publish step failed. (The
first-ever publish uses the same commands — see
[Bootstrapping the npm channel](#bootstrapping-the-npm-channel-first-time-only) for the
surrounding order.)

```bash
# 1. Grab the binaries built for the release
gh run download <run-id> --dir artifacts

# 2. Generate all six packages at the released version
python packaging/npm/build_npm_packages.py --artifacts artifacts --output build/npm

# 3. Platform packages FIRST - the launcher pins their exact versions
for dir in build/npm/cli-*; do
  npm publish "$dir" --access public
done

# 4. Launcher LAST
npm publish build/npm/cli --access public
```

The generator refuses to run unless all five binaries are present, so a partial set cannot
produce a launcher pointing at packages that were never published.

---

## Docker Image

The Docker image is published by triggering `.github/workflows/docker.yml` **by hand**,
after the release's PyPI publish has succeeded. See
[Specifying OSS IQ Version in Docker](#specifying-oss-iq-version-in-docker) for the exact
tags produced.

This is deliberate. The image installs `ossiq==<version>` *from PyPI* rather than building
from the working tree, so it can only be built once that version exists. Wiring it to the
release event would mean racing the PyPI upload and adding retry machinery to save a
single command on an infrequent, deliberate operation.

```bash
# Normal case: publish the version you just released and make it `latest`
gh workflow run docker.yml -f tag=vX.Y.Z

# Rebuild an older version without disturbing `latest`
gh workflow run docker.yml -f tag=vX.Y.Z -f latest=false
```

The workflow verifies the version is on PyPI before building, so a typo or a premature run
fails in seconds rather than part-way through a ~20 minute multi-arch build.

### Building and Testing Locally

Before releasing, test the Docker build locally:

```bash
# Build the image against an already-published version
docker build -t ossiq/ossiq-cli:test --build-arg TAG_VERSION=0.1.10 .

# Test help commands
docker run --rm ossiq/ossiq-cli:test --help
docker run --rm ossiq/ossiq-cli:test status --help

# Test token validation (should fail gracefully with helpful message)
docker run --rm ossiq/ossiq-cli:test status /project

# Test an actual scan against a project
docker run -t --rm \
  -e OSSIQ_GITHUB_TOKEN=$(gh auth token) \
  -v ./testdata/npm/project1:/project:ro \
  ossiq/ossiq-cli:test status /project

# Test HTML report generation
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN=$(gh auth token) \
  -v ./testdata/npm/project1:/project:ro \
  -v $(pwd)/reports:/output \
  ossiq/ossiq-cli:test html -o /output/report.html /project
```

`TAG_VERSION` must be a version that already exists on PyPI — the build installs
`ossiq==$TAG_VERSION` from there, it does not build from your working tree.

### Multi-Architecture Build Test

The CI builds for both `linux/amd64` and `linux/arm64`. To test multi-arch locally:

```bash
# Create a builder (one-time setup)
docker buildx create --name multiarch --use

# Build for multiple platforms (without pushing)
docker buildx build --platform linux/amd64,linux/arm64 -t ossiq/ossiq-cli:test .
```

### Updating Python Version

The Dockerfile uses a specific Python version. Update it when:
- A new Python version becomes stable and is tested with OSS IQ
- The minimum Python version in `pyproject.toml` changes
- Security updates require a newer version

**Files to update:**
1. `Dockerfile` - Update both stages:
   ```dockerfile
   FROM python:3.14-slim-bookworm AS builder
   ...
   ENV UV_PYTHON=python3.14
   ...
   FROM python:3.14-slim-bookworm AS runtime
   ```

2. `pyproject.toml` - Ensure classifiers include the version:
   ```toml
   "Programming Language :: Python :: 3.14",
   ```

3. `.github/workflows/test.yml` - Add the version to the test matrix

### Updating uv Version

The Dockerfile pins a specific uv version for reproducibility. Update it when:
- A new uv version has features or fixes you need
- Security updates are released
- Breaking changes require testing

**File to update:** `Dockerfile`
```dockerfile
COPY --from=ghcr.io/astral-sh/uv:0.9.26 /uv /uvx /bin/
```

Check for new versions at: https://github.com/astral-sh/uv/releases

### Specifying OSS IQ Version in Docker

The version comes from the `tag` input you pass, which `docker.yml` also forwards to the
build as `TAG_VERSION` so the image installs exactly `ossiq==<version>` from PyPI. A
leading `v` is optional — `v0.1.3` and `0.1.3` behave identically.

| `tag` input | `latest` input | Docker tags created |
|---------|---------|---------------------|
| `v0.1.3` | on (default) | `0.1.3`, `0.1`, `latest` |
| `v0.1.3` | off | `0.1.3`, `0.1` |
| `v2.0.0-beta.1` | either | `2.0.0-beta.1` only |

A version with a prerelease suffix never claims the rolling minor tag or `latest`, whatever
the `latest` input says — those tags are reserved for exact `X.Y.Z` versions.

There is no `major`-only tag (`1`): with the project pre-1.0, a rolling major tag would be
misleading.

### Docker Hub Setup (One-Time)

1. Create Docker Hub repository at https://hub.docker.com
   - Organization/Username: `ossiq`
   - Repository: `ossiq-cli`
   - Short description: "Dependency risk analysis by linking version lag, CVEs, and maintainer activity"

2. Add GitHub repository secrets:
   - `DOCKER_USERNAME` - Docker Hub username
   - `DOCKER_PASSWORD` - Docker Hub access token (create at https://hub.docker.com/settings/security)

3. Update Docker Hub README:
   - Copy content from `DOCKER_README.md` to the Docker Hub repository description

### Common Issues

#### How to include additional assets
One of the typical packaging issue is to make sure that all necessary
assets are included alongside source code. The practical use case
is **HTML templates** (see `[tool.hatch.build.targets.wheel.force-include]` section
of `pyproject.toml`).

To validate that specific files are present in the build, use bash command:

```bash
unzip -l dist/ossiq-0.1.3-py3-none-any.whl | grep ".html"
```

#### No duplicate assets

Similarly to previous problem, another risk is to include twice the same asset.

PyPI would report during release proces something like:

```
Uploading ossiq-0.1.4-py3-none-any.whl
WARNING  Error during upload. Retry with the --verbose option for more details. 
ERROR    HTTPError: 400 Bad Request from https://upload.pypi.org/legacy/        
         Invalid distribution file. ZIP archive not accepted: Duplicate filename
         in local headers. See https://docs.pypi.org/archives for more          
         information  
```

And to identify what is wrong follow similar command:

```bash
python3 -m zipfile -l dist/ossiq-0.1.4-py3-none-any.whl
```