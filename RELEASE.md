## How to cut new release

This document outlines the process for cutting a new release of the `ossiq` project: the
release branches it runs on, the standard procedure, what to do when a channel or a release
fails, and how releases are attested: SLSA Build L3 for the artifacts, and SLSA Source for the
code they are built from (Level 1 today, Level 3 once the source policy lists the release
branch).

**Versions only go up, and every tag is permanent.** `release.py` refuses a version that is
not newer than the newest one on PyPI, and the tag ruleset blocks moving or deleting a tag. A
mistaken release is fixed by the next patch, never by reusing its number.

### One version, one tag, three registries

You control the version manually with `release.py`. Everything else derives from it:

```
   pyproject.toml  version = "X.Y.Z"      <- you set this, via release.py
          │
          ▼
     git tag vX.Y.Z  +  draft GitHub Release "Release vX.Y.Z"
          │
          ├───────────────┬───────────────────────┐
          ▼               ▼                       ╎ (manual, once PyPI is live)
     release.yml     binaries.yml                 ▼
          │               │                  docker.yml
          ▼               ▼                       │
      PyPI ossiq     5 binaries attached,         ▼
        X.Y.Z        then draft published     Docker Hub
                     + 6 npm packages        ossiq/ossiq-cli
                       STAGED                    X.Y.Z
                          │
                          ╎ (manual: you approve each package with 2FA)
                          ▼
                     npm @ossiq/cli
                        X.Y.Z
```

There is **one** GitHub Release per version, not one per package. Pushing the tag publishes
PyPI and the binaries on its own. **Two steps are deliberately manual:**

- **npm.** CI only *stages* the six packages; nothing is installable until you approve each
  one with 2FA. See [Approving a staged npm release](#approving-a-staged-npm-release).
- **Docker**, because the image installs `ossiq==X.Y.Z` *from PyPI* and so cannot be built
  until that upload has landed.

The repository has **release immutability** on: once a GitHub Release is published, no
asset can be added, replaced or removed, and its tag is locked. So `release.py` creates
the release as a *draft*, `binaries.yml` attaches the binaries to it, and only then
publishes it. The workflows therefore trigger on the tag push, not on
`release: published` — a draft never fires that event, and a publish made with
`GITHUB_TOKEN` starts no other workflow. v0.1.11 was cut before this flow existed and its
release carries no binaries.

All three publish the identical version string: PyPI and npm read it from the tagged
commit's `pyproject.toml`, and you pass the same version to the Docker workflow by hand.

You never bump an npm version by hand. `packaging/npm/build_npm_packages.py` reads
`pyproject.toml`, and `binaries.yml` refuses to publish if that file and the release tag
disagree.

### npm channel status

| Version | PyPI | Binaries | npm |
| --- | --- | --- | --- |
| 0.1.12 | ✅ | ✅ | ✅ published **by hand** (the bootstrap) |
| 0.1.13 | ✅ | ✅ | ✅ published by CI, with provenance, on the third attempt |
| 0.1.14 | ✅ | ✅ | ✅ staged by CI, approved by hand: the first release through the normal flow |

0.1.13's two failed attempts are worth remembering, because both were registry-side
settings that nothing in this repo can see:

- **`E404` on the first `PUT`** — the Trusted Publisher did not match.
- **`403 OIDC permission denied`** — the publisher granted `npm stage publish` only, which
  is how publishers created after 2026-09-03 default. The workflow was running a direct
  `npm publish`.

**0.1.13 is what fixed npm on macOS.** `@ossiq/cli@0.1.12` could not load libpython on any
Mac: `npm pack` silently dropped the symlinks the binary needs, fixed in #154. Verified on
darwin-arm64 — `npx --yes @ossiq/cli@0.1.13 --version` runs, and the tarball carries
`_internal/Python` again at 136 files rather than 131. Deprecate 0.1.12 when convenient
(see [If one channel fails](#if-one-channel-fails)).

**Docker Hub is still at 0.1.10.** `docker.yml` was never run for 0.1.11–0.1.13, and 0.1.14's
run was started from `main`, which the `release` environment rejects (see step 7 below).

From 0.1.14 the flow is **stage, then approve**: `binaries.yml` runs `npm stage publish`,
and nothing is installable until you approve each package with 2FA.

**Do not build the Docker image against a pre-rename version.** `docker-entrypoint.sh`
execs `ossiq`, which only exists from 0.1.11 onward, so `TAG_VERSION=0.1.10` or earlier
produces an image that fails at startup.

### Branches

Releases ship from **release branches**: one short-lived branch per release, so `main` stays
open for anything while a release is being tested.

```
main             A──B──C──D──E──F'──R1'──G──►
                       │                 │
release/0.1.14         └──F──R1          │        v0.1.14 tags R1
                                         │
release/0.1.15                           └──R2    v0.1.15 tags R2
```

`F` is a fix made while testing 0.1.14, and `R1` is the `chore(release): 0.1.14` commit that
`release.py` makes. Both go back to `main` through a back-port pull request (step 8 below), and
the next release branch is cut from `main` again. The diagram shows the case where `main` has
moved on (`D`, `E`), so they go back as cherry-picks (`F'`, `R1'`). If `main` hasn't moved,
they land unchanged.

A release branch:

1. is cut from `main` when you start testing a release, or from the last release tag when an
   urgent fix can't wait for what is on `main`;
2. is named `release/X.Y.Z` after the one version it ships, and `release.py` refuses any other
   version on it;
3. takes fixes only, as pull requests, landed as
   [CONTRIBUTING.md](CONTRIBUTING.md#merge-a-pull-request-maintainers) describes;
4. is frozen once tagged: never reused, never deleted;
5. has its fixes and its `chore(release)` commit back-ported to `main` before the next release
   branch is cut.

The `chore(release)` commit has to go back too. `release.py` finds the previous release from the
version in `pyproject.toml`, so if `main` still says the old version, the next changelog repeats
the whole previous release.

**Why not one long-running release branch.** After its first release it holds commits that
`main` only has as cherry-picked copies. Catching it up with `main` would take a merge commit
or a force-push, and the rulesets forbid both: linear history, and the no-force-push rule that
SLSA continuity depends on.

`production`, the branch the old process released from, is retired. It stays protected and is
no longer used.

### Standard Release Procedure

`X.Y.Z` is the version being released. A fix to something already released ships as the next
patch, from a new release branch.

1.  **Cut the release branch** from `main`:
    ```bash
    git fetch origin
    git switch -c release/X.Y.Z origin/main    # urgent fix: start from the last tag instead
    git push -u origin release/X.Y.Z
    ```
    `compute_slsa_source.yml` skips this push, because sourcetool can't attest a branch
    creation. The commit is already attested on the branch it was cut from, and the branch's
    first fix or release commit starts its own provenance.

2.  **Check the SLSA source policy** (needed for Source Level 3 only). A release reaches Level 3
    only if `release/X.Y.Z` is in the *merged* policy before step 4. Otherwise it still ships,
    at Level 1, and stays at Level 1:
    ```bash
    sourcetool policy view ossiq/ossiq     # release/X.Y.Z listed at SLSA_SOURCE_LEVEL_3?
    ```
    `release.py` can't check this for you. It waits for a green attestation run, and a run is
    green at Level 1 too. Upstream takes about a month to merge a policy PR, so list release
    branches well ahead. See [SLSA Source track](#slsa-source-track).

3.  **Test, and fix through pull requests.** Run `uv run just qa-integration` and the manual
    cases in `qa/manual/release-checklist.md` against the release branch. Each fix:
    ```bash
    git switch -c fix/GH-<n>--<slug> origin/release/X.Y.Z
    gh pr create --base release/X.Y.Z
    ```
    Land it as [CONTRIBUTING.md](CONTRIBUTING.md#merge-a-pull-request-maintainers) describes,
    with `release/X.Y.Z` in place of `main`.

4.  **Run the release script**, dry run first:
    ```bash
    git switch release/X.Y.Z && git pull --ff-only
    export OSSIQ_GITHUB_TOKEN=$(gh auth token)
    uv run release.py --override-version X.Y.Z --dry-run
    uv run release.py --override-version X.Y.Z
    ```
    Before changing anything, both runs refuse unless the branch is `release/X.Y.Z` and `X.Y.Z`
    is newer than the newest version on PyPI. The real run then:

    - bumps `pyproject.toml` and `uv.lock`, regenerates `CHANGELOG.md`, and commits them as a
      signed `chore(release): X.Y.Z`. The rulesets require signed commits, so git signing must
      be set up ([CONTRIBUTING.md](CONTRIBUTING.md#get-started), step 5).
    - tags that commit `vX.Y.Z` locally and pushes the release branch.
    - waits for `compute_slsa_source.yml` to attest the commit. A tag's attestation takes its
      level from its commit's, so the tag must not go first.
    - pushes the tag, which starts `release.yml` (PyPI), `binaries.yml` and the tag's own
      attestation.
    - creates the GitHub Release as a draft. `binaries.yml` publishes it once the binaries are
      attached; don't publish it by hand, or it becomes immutable without them.

    If something fails, see [If a release goes wrong](#if-a-release-goes-wrong).

5.  **Watch the workflows** (see [Release timeline](#release-timeline) below):
    ```bash
    gh run list --limit 5
    gh run watch
    ```
    `release.yml` and the tag's `compute_slsa_source.yml` must be green, and so must every job
    in `binaries.yml`, including **Stage npm packages for approval**. That job's summary page
    prints the approval commands for this release.

6.  **Approve the staged npm packages** — manual, and nothing is installable until you do.
    Full runbook: [Approving a staged npm release](#approving-a-staged-npm-release).
    ```bash
    just npm-approve <binaries.yml run id>            # verify, approve nothing
    just npm-approve <binaries.yml run id> --approve  # approve, in order, 2FA each
    ```

7.  **Publish the Docker image** — manual, and only once PyPI has the version:
    ```bash
    gh workflow run docker.yml --ref vX.Y.Z -f tag=vX.Y.Z
    ```
    Run it from the tag. The `release` environment accepts only `v*` tags, so a run started
    from `main` (the default `--ref`) is rejected before it starts. `latest` defaults to on;
    untick it (`-f latest=false`) when rebuilding an older version. The workflow refuses to
    start if `ossiq==X.Y.Z` is not yet on PyPI.

8.  **Back-port to `main`** through a pull request, before the next release branch is cut.
    `main` needs the release branch's fixes and its `chore(release): X.Y.Z` commit. Without
    the bump, `main` still says the old version, and the next changelog repeats this release.

    1. **Create the back-port branch.** How depends on whether `main` has moved since the cut:
       ```bash
       git fetch origin
       git log --oneline origin/release/X.Y.Z..origin/main     # commits on main since the cut
       ```
       If that prints nothing, branch from the release branch itself. Its commits then land
       on `main` unchanged, so the `vX.Y.Z` tag is in `main`'s history:
       ```bash
       git switch -c chore/backport-X.Y.Z origin/release/X.Y.Z
       ```
       If it prints commits, branch from `main` and cherry-pick the release branch's commits:
       ```bash
       git switch -c chore/backport-X.Y.Z origin/main
       git cherry -v origin/main origin/release/X.Y.Z          # "+" lines: not on main yet
       git cherry-pick -x <each "+" sha, top to bottom>
       ```
    2. **Check, push and open the pull request:**
       ```bash
       git log --format='%G? %h %s' origin/main..HEAD          # every line starts with G
       git push -u origin chore/backport-X.Y.Z
       gh pr create --base main --title "chore(release): back-port X.Y.Z" \
         --body "Back-ports release/X.Y.Z to main: its fixes and the chore(release) commit."
       gh pr checks --watch
       ```
    3. **Land it** as [CONTRIBUTING.md](CONTRIBUTING.md#merge-a-pull-request-maintainers)
       describes:
       ```bash
       git fetch origin
       git rebase origin/main                    # a no-op unless main moved since step 1
       git push origin HEAD:main                 # GitHub marks the pull request as merged
       git push origin --delete chore/backport-X.Y.Z
       git switch main && git pull --ff-only
       grep '^version' pyproject.toml            # X.Y.Z
       ```
       If the rebase changed anything, push the branch with `--force-with-lease` and wait for
       the checks again before you push to `main`.

    The release branch is now frozen.

    When the commits reach `main` as copies (cherry-picked, or rebased because `main` moved),
    the next release's changelog lists them again. `release.py` collects every commit since the
    previous tag, the tag is on the release branch, and the copies on `main` have new hashes.
    Branching from the release branch avoids this.

9.  **Verify all three channels and the source attestation**
    ([details](#post-release-verification)):
    ```bash
    uvx ossiq@X.Y.Z --version
    npx --yes @ossiq/cli@X.Y.Z --version
    docker run --rm ossiq/ossiq-cli:X.Y.Z --version
    sourcetool verify ossiq/ossiq --tag vX.Y.Z     # Level 1 unless step 2's check passed
    ```

### Release timeline

| Step | Trigger | Duration | Depends on |
| --- | --- | --- | --- |
| `compute_slsa_source.yml` → source attestation in git notes | push to `main`, a `release/*` branch, or any tag | ~1 min | nothing; `release.py` waits for the release commit's run before pushing the tag |
| `release.yml` → PyPI | push of tag `vX.Y.Z` | ~2 min | nothing |
| `binaries.yml` → binaries, publish the draft release, then **stage** npm | push of tag `vX.Y.Z` | ~15 min | the draft release existing (created seconds after the tag push) |
| **npm approval** → npm | **manual**, `just npm-approve … --approve` | ~2 min + 2FA | `binaries.yml` having staged |
| `docker.yml` → Docker Hub | **manual** `workflow_dispatch` | ~20 min | the version being live on PyPI |

The two workflows start together and run concurrently; neither needs the other. The two
manual steps are independent of each other, so the order between them does not matter.

`docker.yml` is manual on purpose. Its image does `uv pip install ossiq==X.Y.Z` *from
PyPI*, so triggering it off the release event would race the PyPI upload. Releases are
infrequent and deliberate, so you run it yourself once `release.yml` is green — it
fails fast (one API call) if the version is not on PyPI yet.

`binaries.yml` runs in two stages: a 5-way build matrix, then — only after all five
succeed — the npm packing and staging. A single platform failing means **no** npm packages
are staged, which is deliberate: a launcher whose `optionalDependencies` point at a missing
platform package would leave that platform permanently broken.

### Post-release verification

```bash
# 1. PyPI
uvx ossiq@X.Y.Z --version

# 2. npm - only works once you have approved the staged packages. It resolves the
#    platform package and runs the bundled binary, so it exercises just this machine's
#    platform: run it on a Mac, since the darwin trees are the only ones with symlinks
#    and npm pack dropping them is what broke 0.1.12.
npx --yes @ossiq/cli@X.Y.Z --version

# 3. Docker
docker run --rm ossiq/ossiq-cli:X.Y.Z --version

# 4. The GitHub Release should carry five .tar.gz assets
gh release view vX.Y.Z --json assets --jq '.assets[].name'

# 5. The tag's source attestation: SLSA_SOURCE_LEVEL_3 if the release branch was in the
#    merged policy before release.py ran (step 2), SLSA_SOURCE_LEVEL_1 otherwise
sourcetool verify ossiq/ossiq --tag vX.Y.Z
```

### If one channel fails

Each channel is recoverable on its own; you do **not** re-cut the release.

| Failed | Recovery |
| --- | --- |
| PyPI (`release.yml`) | Re-run the failed job: `gh run rerun <id> --failed`. A version already on PyPI cannot be replaced — if the artifact itself is wrong, cut a new patch version. |
| Binaries (`binaries.yml`) | Re-run the failed job. The release stays a draft until the binaries are attached, so re-running is safe (assets upload with `--clobber`). Once it is published it is immutable — missing binaries then mean a new patch version. |
| npm staging (`binaries.yml`) | `403 OIDC permission denied` means a direct `npm publish` was attempted against a stage-only publisher — the workflow must use `npm stage publish`. `E404` on the first `PUT` means the trusted publisher does not match: fix it on npmjs.com, then `gh run rerun <id> --failed`. Nothing has landed in either case, so a rerun is safe. |
| npm approval | Staged-but-unapproved is **not** a failed release — the packages simply wait. Re-run `just npm-approve <run-id>`; it reports what is already live and what is still pending. If an approval failed part-way, the launcher may be live before its platform packages: the tool says so, and the fix is to approve the rest immediately. |
| Docker (`docker.yml`) | Just run it again: `gh workflow run docker.yml --ref vX.Y.Z -f tag=vX.Y.Z`. Nothing depends on it, so it can be published hours or days later. "Branch "main" is not allowed to deploy to release" means the run started from `main` instead of the tag. |
| Source attestation (`compute_slsa_source.yml`) | Re-run the failed job: `gh run rerun <id> --failed`. A re-run keeps the original push event, which the attestation action requires. |

A version that is live on one registry but not another is not an emergency — the channels
are independent. Fix the failed one and the release is complete.

A version that was published but is **broken** gets fixed by the next patch release. Then
deprecate the bad one; never unpublish it. The version number can't be reused anyway, and
unpublishing every version of a package frees the name and drops its trusted-publisher
config:

```bash
npm deprecate "@ossiq/cli@X.Y.Z" "<what is broken>; use X.Y.Z+1 or later"
```

### If a release goes wrong

Nothing a release pushes can be taken back: the tag ruleset makes every tag permanent, and a
release branch can't be force-pushed or deleted. So you fix forward.

- **`release.py` stopped before pushing anything.** Nothing left your machine. Discard the
  local bump with `git reset --hard origin/release/X.Y.Z` (and `git tag -d vX.Y.Z` if it got
  as far as tagging), then run it again.
- **It stopped after pushing the branch**, most likely while waiting for the attestation. The
  `chore(release)` commit is on the release branch, and it is the commit to tag. Don't run
  `release.py` again, because it would bump and commit a second time. Once that commit's
  `compute_slsa_source.yml` run is green, finish with the two commands it printed: push the
  tag, then create the draft release.
- **A published version is broken.** Release the fix as the next patch: cut its release branch
  from the broken version's tag if `main` isn't ready, and deprecate the bad version (see
  above).

---

## Channel reference

| Workflow | Publishes | Trigger | Auth |
| --- | --- | --- | --- |
| `release.yml` | PyPI (`ossiq`) | tag push `vX.Y.Z` | Trusted Publishing (OIDC) |
| `binaries.yml` | Standalone binaries → GitHub Release assets (then publishes the draft), then **stages** npm (`@ossiq/cli` + 5 platform packages) | tag push `vX.Y.Z` | npm Trusted Publishing (OIDC), stage-only |
| *you* | approving the staged npm packages, which is what makes them installable | manual | your npm login + 2FA |
| `docker.yml` | Docker Hub (`ossiq/ossiq-cli`) | manual | `DOCKER_USERNAME` / `DOCKER_PASSWORD` |

Each top-level workflow above is a thin caller. The builds happen in reusable workflows
that sign [SLSA Build L3](https://slsa.dev/spec/v1.2/build-track-basics) provenance:

| Reusable workflow | Builds and attests |
| --- | --- |
| `reusable-build-dist.yml` | sdist + wheel, plus the CycloneDX SBOM |
| `reusable-build-binaries.yml` | the five platform `.tar.gz` binaries |
| `reusable-build-npm.yml` | the six npm `.tgz` tarballs |

## Provenance and verification

### Two filenames must never change

**`release.yml` and `binaries.yml` are registry-bound.** PyPI and npm match a Trusted
Publisher on `(repository, workflow filename, environment)`. Renaming either file, or
removing `environment: release` from a publish job, breaks publishing until the publisher
is reconfigured registry-side — and the failure only surfaces mid-release, after the tag
is already pushed.

Two further constraints follow from how the registries validate OIDC:

- **The PyPI publish step cannot move into a reusable workflow.** PyPI matches the
  `job_workflow_ref` claim, which for a `workflow_call` job names the callee:
  *"Reusable workflows cannot currently be used as the workflow in a Trusted Publisher."*
  So `release.yml` keeps a `steps` job that downloads the attested artifact and uploads it.
- **npm validates the *calling* workflow's filename**, which is why moving
  `npm stage publish` into a reusable workflow would not have helped, and why
  `--provenance` alone does not reach L3.

`tests/test_workflow_supply_chain.py` asserts all of this, so a well-meaning tidy-up fails
in CI rather than during a release.

One part of the contract has **no representation in this repo**: each package's *Allowed
actions* on npmjs.com, which permit `npm stage publish` and not direct publishing. A test
asserts that `binaries.yml` stages rather than publishes, but nothing here can see the
registry side — so if a release fails with `403 OIDC permission denied`, that setting is
where to look.

### The reusable workflow filenames are public API

Consumers verify with
`gh attestation verify ... --signer-workflow ossiq/ossiq/.github/workflows/reusable-build-*.yml`.
Renaming one silently breaks every published verification command. If you must rename,
update `docs/how-to/verifying-a-release.md` in the same change — a test asserts the two
agree — and note the change in the release notes.

### After publishing

Run the consumer-facing commands from
[docs/how-to/verifying-a-release.md](docs/how-to/verifying-a-release.md) against the
*published registries*, not against CI artifacts. That is the only check of what is
actually being claimed:

```bash
# PyPI
pip download --no-deps --only-binary :all: ossiq==X.Y.Z
gh attestation verify ossiq-X.Y.Z-py3-none-any.whl --repo ossiq/ossiq \
  --signer-workflow ossiq/ossiq/.github/workflows/reusable-build-dist.yml

# Binaries
gh release download vX.Y.Z --repo ossiq/ossiq --pattern 'ossiq-*.tar.gz' --pattern SHA256SUMS
sha256sum -c SHA256SUMS
gh attestation verify ossiq-linux-x64.tar.gz --repo ossiq/ossiq \
  --signer-workflow ossiq/ossiq/.github/workflows/reusable-build-binaries.yml

# npm
npm audit signatures
npm pack @ossiq/cli@X.Y.Z
gh attestation verify ossiq-cli-X.Y.Z.tgz --repo ossiq/ossiq \
  --signer-workflow ossiq/ossiq/.github/workflows/reusable-build-npm.yml
```

### SLSA Source track

The workflows above make the *artifacts* SLSA Build L3. The *code* they are built from
targets [SLSA Source L3](https://slsa.dev/spec/v1.2/source-requirements). Every revision a
release is built from sits on a protected branch and is attested when it lands there, and
every tag is permanent.

**Status:** the controls are in place, and `main` and the release branches are eligible for
Level 3. Releases still ship at **Level 1**, because the source policy isn't merged yet (see
**Policy** below). v0.1.14 verifies at Level 1.

**Protected references**, set up as repository rulesets:

| Ruleset | Covers | Rules |
| --- | --- | --- |
| SLSA Source Level 3 Ruleset | `main`, `release/*`, `production` | no deletion, no force-push, signed commits, linear history |
| SLSA Source Level 3 Tags Ruleset | every tag | no deletion, no update, no force-push |
| Main Branch Protection | `main` | changes through pull requests, squash-merged; org admins can bypass |

The two SLSA rulesets have **no bypass actors**, admins included. A bypass would break the
continuity that the attestations claim. Tag *creation* is deliberately not restricted: SLSA
asks only that tags never move or disappear, and `release.py` has to be able to create them.

Main Branch Protection keeps its org-admin bypass. That is how a maintainer lands a pull
request: by pushing its signed commits straight to `main`, as
[CONTRIBUTING.md](CONTRIBUTING.md#merge-a-pull-request-maintainers) describes. The SLSA rules
still apply to that push. GitHub's **Rebase and merge** would re-create the commits without
signatures, so it is never used.

**Attestations.** `compute_slsa_source.yml` runs on every push to a protected branch or tag,
except the push that creates a branch: sourcetool only finds pushes, force-pushes and pull
request merges in GitHub's activity log, and GitHub logs a new branch as a branch creation.
It calls the SLSA framework's reusable workflow, which records source provenance and a
Verification Summary Attestation (VSA) for the pushed commit in git notes (`refs/notes/*`). A
tag's VSA takes its level from its commit's. That is why `release.py` waits for the release
commit's run before it pushes the tag.

**Policy.** The level each branch is held to is declared in
`policy/github.com/ossiq/ossiq/source-policy.json` in `slsa-framework/source-policies`, a
repository this project doesn't control. A branch that isn't listed in the *merged* file is
held to sourcetool's default policy, which is Level 1.

- **Pending:** the file is proposed in
  [slsa-framework/source-policies#26](https://github.com/slsa-framework/source-policies/pull/26)
  with `main` and `release/0.1.14`. Upstream takes about a month to merge a policy PR.
- **Exact names.** sourcetool matches branch names exactly, with no wildcards, so every release
  branch needs its own entry. Add upcoming names ahead of time.
- **The `since` date.** A branch reaches Level 3 only if its entry's `since` is no earlier than
  the newest date among its required controls, and no later than the attested push. For
  `release/*`, that date is the later `updated_at` of the two SLSA rulesets, in UTC:
  `2026-10-22T20:31:35.469Z` today. Don't copy `main`'s date. `main` is also covered by the
  older Main Branch Protection ruleset, so its date is earlier, and a release branch given
  that date drops to Level 1.
- **Editing either SLSA ruleset moves that date** for every branch that has no attestation yet,
  which breaks entries written ahead of time. Update their `since` after any edit. Branches
  that already have an attestation keep their earlier date.

```bash
sourcetool policy view ossiq/ossiq                                    # the merged policy
sourcetool status --owner ossiq --repo ossiq --branch release/X.Y.Z   # one branch's controls
sourcetool verify ossiq/ossiq --tag vX.Y.Z                            # what a consumer checks
```

Pass a branch to `status` with `--branch`. The `ossiq/ossiq@release/X.Y.Z` form silently
reports `main` instead.

**Safe expunging.** SLSA requires the process for removing content from protected history to
be documented, and this is it:

- It is allowed only to meet a legal or privacy obligation.
- An org admin disables the affected ruleset, rewrites or deletes the ref, and re-enables the
  ruleset. GitHub's audit log records each ruleset change.
- The reason, the refs and the revisions removed are recorded in a GitHub issue.
- That ref's continuity restarts afterwards, so update its `Since` date in the source policy.

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
4. **Stages** all six. Nothing is installable yet: you approve each one with 2FA, the five
   platform packages first and the launcher last, because the launcher pins exact versions
   of packages that must already exist.

So `ossiq X.Y.Z` on PyPI and `@ossiq/cli X.Y.Z` on npm are always the same commit.

**Keep versions to plain `X.Y.Z`.** Python (PEP 440) and npm (semver) agree on that form
but not on prereleases: PyPI normalises `0.2.0-rc.1` to `0.2.0rc1`, while npm keeps
`0.2.0-rc.1`, so the two registries would show different strings for one release. Forms
like `0.2.0rc1` or `0.1.10.post1` are not valid semver at all and npm will reject them
outright.

### Approving a staged npm release

CI stages, you approve. Until you do, `npm install @ossiq/cli@X.Y.Z` cannot see the version
at all. The trusted publisher grants `npm stage publish` only, so the gate cannot be
skipped — which is the point: a compromised workflow can stage a version but never ship
one.

**Order is the whole risk.** The launcher's `optionalDependencies` pin the five platform
packages at that exact version, and npm *silently skips* an optional dependency it cannot
resolve. Approve the launcher first and `npm install @ossiq/cli` still succeeds — with no
binary inside, printing the PyPI fallback hint instead of running. So: the five platform
packages, then `@ossiq/cli`.

```bash
npm login                                          # 2FA is required to approve
just npm-approve <binaries.yml run id>             # verify; approves nothing
just npm-approve <binaries.yml run id> --approve   # approve, in order
```

The run id is on `binaries.yml`'s summary page, which prints these commands for you.

What the first command checks before you commit to anything:

- all six are staged, at this release's version, exactly once;
- each tarball CI attested still verifies against `reusable-build-npm.yml`;
- what npm holds staged matches the bytes CI attested — where npm's CLI allows that
  comparison; it reports "staged bytes not compared" rather than quietly assuming;
- nothing else is staged that would be swept up in the approval.

It refuses to approve if a check fails, and `--approve` re-runs every check first, so the
two commands differ only in what happens at the end. Re-running after a half-finished
approval is safe: it reports what is already live and approves only what is left.

To discard a staged version rather than approve it, `npm stage reject <stage-id>`. Do
either reasonably promptly — npm does not document how long a staged version lives.

npmjs.com → **Staged Packages** does the same by hand and is the fallback if the CLI
misbehaves. The order still applies.

### Bootstrapping the npm channel (first time only)

**Done at 0.1.12.** Kept for reference: adding a platform package later means a new package
name, and repeating steps 3–4 for that one package.

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

The npm staging and release-asset steps are gated on the tag push, so a
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

**The npm job fails on this release, and that is expected** — the packages do not exist yet
and no trusted publisher is configured. It is a separate job from `attach-to-release`, so
the binaries still land on the GitHub Release, and the release is still published,
regardless.

#### Step 3 — Publish the six npm packages by hand, once

```bash
npm login                     # supply the 2FA OTP if your org enforces it
```

Then follow [Publishing npm manually](#publishing-npm-manually) with this release's
`binaries.yml` run id. Do **not** pass `--provenance` — provenance requires CI OIDC and
will fail locally. Then verify:

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
   - Allowed actions: **leave direct `npm publish` unchecked** (the default). CI stages and
     a human approves; ticking it would remove the 2FA gate, and `binaries.yml` does not
     use it.

#### Step 5 — Publish the Docker image

```bash
gh workflow run docker.yml --ref vX.Y.Z -f tag=vX.Y.Z
```

#### Step 6 — Confirm the automation on the next release

**Done at 0.1.14.** `Stage npm packages for approval` went green with no manual step, and
`npx @ossiq/cli@0.1.14` runs once approved. The bootstrap is complete. 0.1.13 was meant to
be this release and didn't reach npm at all (see [npm channel status](#npm-channel-status)).

### Rehearsing without publishing

`binaries.yml` can be run at any time without cutting a release; only the npm staging and
release-asset steps are gated on the tag push.

```bash
gh workflow run binaries.yml --ref <branch>
gh run watch

# then, locally, from the repo root. `gh run download` puts each artifact in its own
# directory, and the packer wants the five tarballs side by side.
W="$(mktemp -d)"
gh run download <run-id> --repo ossiq/ossiq --pattern 'ossiq-*' --dir "$W/runs"
mkdir "$W/artifacts" && mv "$W"/runs/*/ossiq-*.tar.gz "$W/artifacts/"
uv run python packaging/npm/build_npm_packages.py --artifacts "$W/artifacts" --output "$W/build/npm"
# `npm publish --dry-run` is deliberate here, not a leftover from before staging: it only
# packs and prints, never contacts the registry, so it needs no publisher and no approval.
npm publish "$W/build/npm/cli-darwin-arm64" --dry-run
npm publish "$W/build/npm/cli" --dry-run

# On a Mac, run the binary out of the *packed* tarball. CI's smoke test runs before
# packing, so this is the only check that npm pack kept everything the binary needs.
npm pack "$W/build/npm/cli-darwin-arm64" --pack-destination "$W"
mkdir "$W/x" && tar xzf "$W"/ossiq-cli-darwin-arm64-*.tgz -C "$W/x"
"$W/x/package/bin/ossiq/ossiq" --version
```

To test a packaging change without a CI run, pass the last release's binaries instead:
`gh release download vX.Y.Z --repo ossiq/ossiq --pattern 'ossiq-*.tar.gz' --dir "$W/artifacts"`.

### Publishing npm manually

Break-glass only. The normal path is
[Approving a staged npm release](#approving-a-staged-npm-release); reach for this when
staging itself cannot be made to work and a version has to get to npm anyway. It is also
what the 0.1.12 bootstrap used.

This publishes under **your** npm credentials and your own 2FA. The stage-only setting
governs CI's OIDC identity, not yours, so it does not block you here.

```bash
# 1. The six tarballs CI packed and attested for this release
cd "$(mktemp -d)"               # outside the repo, so nothing lands in the work tree
gh run download <binaries-run-id> --repo ossiq/ossiq -n npm-tarballs

# 2. Prove they are the bytes reusable-build-npm.yml signed; the manual path skips
#    the staging job's own verify step, so this is the only check there is
for f in npm/*.tgz; do
  gh attestation verify "$f" --repo ossiq/ossiq \
    --signer-workflow ossiq/ossiq/.github/workflows/reusable-build-npm.yml
done

# 3. Platform packages FIRST - the launcher pins their exact versions. The `./` matters:
#    npm reads a bare `npm/<file>.tgz` as a GitHub shorthand and refuses it.
python3 -c 'import json; print(*(e["tarball"] for e in json.load(open("build/npm/manifest.json"))["platform_packages"]), sep="\n")' |
  while read -r tarball; do npm publish "./npm/$tarball" --access public; done

# 4. Launcher LAST
npm publish "./npm/$(python3 -c 'import json; print(json.load(open("build/npm/manifest.json"))["launcher"]["tarball"])')" --access public
```

Publishing CI's tarballs rather than regenerating them locally puts on npm exactly the
bytes that were attested. `package-npm` only runs once all five binaries have built, so the
set is never partial.

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
gh workflow run docker.yml --ref vX.Y.Z -f tag=vX.Y.Z

# Rebuild an older version without disturbing `latest`
gh workflow run docker.yml --ref vX.Y.Z -f tag=vX.Y.Z -f latest=false
```

`--ref vX.Y.Z` is required: the job deploys to the `release` environment, which accepts only
`v*` tags.

The workflow verifies the version is on PyPI before building, so a typo or a premature run
fails in seconds rather than part-way through a ~20 minute multi-arch build.

### Building and Testing Locally

Before releasing, test the Docker build locally:

```bash
# Build the image against an already-published version
docker build -t ossiq/ossiq-cli:test --build-arg TAG_VERSION=0.1.13 .

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
