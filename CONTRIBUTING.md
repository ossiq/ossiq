# Contributing

Contributions are welcome, and they are greatly appreciated! Every little bit helps, and credit will always be given.

You can contribute in many ways:

## Types of Contributions

### Report Bugs

Report bugs at [https://github.com/ossiq/ossiq/issues](https://github.com/ossiq/ossiq/issues).

If you are reporting a bug, please include:

- Your operating system name and version.
- Any details about your local setup that might be helpful in troubleshooting.
- Detailed steps to reproduce the bug.

### Fix Bugs

Look through the GitHub issues for bugs. Anything tagged with "bug" and "help wanted" is open to whoever wants to implement it.

### Implement Features

Look through the GitHub issues for features. Anything tagged with "enhancement" and "help wanted" is open to whoever wants to implement it.

### Write Documentation

ossiq could always use more documentation, whether as part of the official docs, in docstrings, or even on the web in blog posts, articles, and such.

### Submit Feedback

The best way to send feedback is to file an issue at [https://github.com/ossiq/ossiq/issues](https://github.com/ossiq/ossiq/issues).

If you are proposing a feature:

- Explain in detail how it would work.
- Keep the scope as narrow as possible, to make it easier to implement.
- Remember that this is a volunteer-driven project, and that contributions are welcome :)

## Get Started!

Ready to contribute? Here's how to set up `ossiq` for local development.

1. Fork the `ossiq` repo on GitHub.

2. Clone your fork locally, and add the main repository as the `upstream` remote:

   ```sh
   git clone git@github.com:your_name_here/ossiq.git
   cd ossiq/
   git remote add upstream git@github.com:ossiq/ossiq.git
   ```

   Maintainers who clone `ossiq/ossiq` itself don't need a fork: use `origin` wherever this
   guide says `upstream`.

3. Install dependencies using `uv`:

   ```sh
   uv sync
   ```

4. Set up required environment variables:

   ```sh
   export OSSIQ_GITHUB_TOKEN=$(gh auth token)
   ```

5. Turn on commit signing. `main` accepts only commits that GitHub shows as **Verified**. Add a
   GPG or SSH signing key to your GitHub account by following
   [GitHub's guide on signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).
   Then make git sign every commit, including the ones a rebase rewrites:

   ```sh
   git config commit.gpgsign true
   ```

## Make your changes

1. Fetch the latest `main` and create a branch from it, named
   `<type>/GH-<ISSUE_ID>--<meaningful-branch-name>`:

   ```sh
   git fetch upstream
   git switch -c fix/GH-42--lockfile-parsing-error upstream/main
   ```

   Where `<type>` is one of:
   - `feature` - New functionality
   - `fix` - Bug fixes
   - `chore` - Maintenance tasks (dependencies, CI, etc.)
   - `docs` - Documentation updates

   More examples: `feature/GH-11--release-process`, `chore/GH-15--update-dependencies`,
   `docs/GH-8--api-documentation`.

2. When you're done making changes, run the full QA suite:

   ```sh
   just qa
   ```

   This runs formatting, linting, type checking, and tests. You can also run individual steps:

   ```sh
   just lint           # Run linter only
   just test           # Run tests only
   just test tests/adapters/test_api_npm.py  # Run specific test file
   just coverage       # Generate coverage report
   ```

3. Commit your changes using conventional commit format with sign-off:

   ```
   <type>[(<scope>)][!]: <description>
   ```

   **Valid types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`

   **Important:**
   - All commits must be **signed** (step 5 of "Get Started!").
   - All commits must include a **Signed-off-by** line using `git commit -s` or `git commit --signoff`.

   Examples:
   ```sh
   git commit -s -m "feat(parser): add support for poetry lockfiles"
   git commit -s -m "fix(npm): handle missing optional dependencies"
   git commit -s -m "chore(deps): update ruff to 0.5.0"
   git commit -s -m "docs: update contributing guidelines"
   git commit -s -m "feat!: breaking change to API"
   ```

   To reference a GitHub issue in the commit body:
   ```sh
   git commit -s -m "feat(parser): add poetry support" -m "GH-42"
   ```

4. Push your branch to your fork:

   ```sh
   git push -u origin fix/GH-42--lockfile-parsing-error
   ```

## Rearrange commits or catch up with `main`

Rebase your branch on your machine, never on GitHub. Your machine has your signing key, so a
local rebase re-signs every commit it rewrites. Don't merge `main` into your branch either:
`main` accepts only linear history.

To pick up new commits from `main`:

```sh
git fetch upstream
git rebase upstream/main
```

To reorder, squash, reword or drop commits, start an interactive rebase. Git opens the list of
your commits: move lines to reorder them, and change `pick` to `reword`, `squash`, `fixup` or
`drop`:

```sh
git rebase -i upstream/main
```

To fold a small fix into an earlier commit, commit it as a fixup, and let `--autosquash` move it
into place:

```sh
git commit -s --fixup=<sha-of-the-earlier-commit>
git rebase -i --autosquash upstream/main
```

After any rebase, check that every commit on your branch is signed. `N` in the first column
marks an unsigned commit:

```sh
git log --format='%G? %h %s' upstream/main..HEAD
```

To sign commits that show `N`, rewrite the whole branch with signing on:

```sh
git rebase --force-rebase --gpg-sign upstream/main
```

A rebase gives your commits new SHAs, so the branch on GitHub needs a forced push.
`--force-with-lease` refuses to overwrite commits on GitHub that you haven't fetched:

```sh
git push --force-with-lease
```

## Open a pull request

Open the pull request against `main` of `ossiq/ossiq`, on the GitHub website or with the GitHub
CLI:

```sh
gh pr create --base main
```

Title it like a commit, for example `fix(npm): handle missing optional dependencies`. Every push
to the branch reruns the checks. To change the pull request, add commits or rebase, then push
again.

## Merge a pull request (maintainers)

Land a pull request by pushing its commits to `main` yourself. Then `main` gets exactly the
commits the author made, with their signatures. GitHub's merge buttons work differently:

| Button | What happens |
|---|---|
| Rebase and merge | Don't use it. GitHub re-creates every commit without a signature, and `main` requires signed commits. |
| Squash and merge | Works. GitHub combines the branch into one new commit and signs it with its own key. Use it for a pull request you can't push to. |
| Create a merge commit | Turned off. `main` accepts only linear history. |

To land a pull request from a clone of `ossiq/ossiq`:

1. Check out the pull request and rebase it onto the latest `main`:

   ```sh
   gh pr checkout <number>
   git fetch origin
   git rebase origin/main
   ```

2. Check that every commit is signed (no `N` in the first column):

   ```sh
   git log --format='%G? %h %s' origin/main..HEAD
   ```

3. If the rebase changed anything, push the branch, so the pull request shows exactly the
   commits that will land. Then wait for the checks:

   ```sh
   git push --force-with-lease
   gh pr checks --watch
   ```

4. Fast-forward `main` to the branch:

   ```sh
   git push origin HEAD:main
   ```

   GitHub marks the pull request as merged, because its last commit is now on `main`. If GitHub
   rejects the push because `main` has moved, start again from step 1.

5. If the branch lives in `ossiq/ossiq`, delete it:

   ```sh
   git push origin --delete <branch>
   ```

Pushing to `main` directly skips the "changes through a pull request" rule of the Main Branch
Protection ruleset, so only organization admins can do it. Nobody can skip the other rules:
commits must be signed, history must stay linear, and `main` can't be force-pushed.

To land a fix on a release branch, follow the same steps with `release/X.Y.Z` in place of `main`.
[RELEASE.md](RELEASE.md) covers the rest of the release process.

## Pull Request Guidelines

Before you submit a pull request, check that it meets these guidelines:

1. The pull request should include tests.
2. If the pull request adds functionality, the docs should be updated. Put your new functionality into a function with a docstring.
3. The pull request should work for Python 3.11, 3.12, 3.13, and 3.14 (the range declared by `requires-python` in `pyproject.toml`). You can test multiple versions locally:

   ```sh
   just testall
   ```

## Tips

To run a subset of tests:

```sh
just test tests/adapters/test_api_npm.py::TestClass::test_method
```

To debug failing tests with IPython debugger:

```sh
just pdb tests/path/to/test.py
```

## Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.
