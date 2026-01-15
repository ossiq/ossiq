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

ossiq-cli could always use more documentation, whether as part of the official docs, in docstrings, or even on the web in blog posts, articles, and such.

### Submit Feedback

The best way to send feedback is to file an issue at [https://github.com/ossiq/ossiq/issues](https://github.com/ossiq/ossiq/issues).

If you are proposing a feature:

- Explain in detail how it would work.
- Keep the scope as narrow as possible, to make it easier to implement.
- Remember that this is a volunteer-driven project, and that contributions are welcome :)

## Get Started!

Ready to contribute? Here's how to set up `ossiq-cli` for local development.

1. Fork the `ossiq-cli` repo on GitHub.

2. Clone your fork locally:

   ```sh
   git clone git@github.com:your_name_here/ossiq-cli.git
   ```

3. Install dependencies using `uv`:

   ```sh
   cd ossiq-cli/
   uv sync
   ```

4. Set up required environment variables:

   ```sh
   export OSSIQ_GITHUB_TOKEN=$(gh auth token)
   ```

5. Create a branch for local development using the naming convention:

   ```
   <type>/GH-<ISSUE_ID>--<meaningful-branch-name>
   ```

   Where `<type>` is one of:
   - `feature` - New functionality
   - `fix` - Bug fixes
   - `chore` - Maintenance tasks (dependencies, CI, etc.)
   - `docs` - Documentation updates

   Examples:
   ```sh
   git checkout -b feature/GH-11--release-process
   git checkout -b fix/GH-42--lockfile-parsing-error
   git checkout -b chore/GH-15--update-dependencies
   git checkout -b docs/GH-8--api-documentation
   ```

   Now you can make your changes locally.

6. When you're done making changes, run the full QA suite:

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

7. Commit your changes using conventional commit format with sign-off:

   ```
   <type>[(<scope>)][!]: <description>
   ```

   **Valid types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`

   **Important:**
   - All commits must be **GPG signed**. Set up commit signing with `git config commit.gpgsign true`. See [GitHub's guide on signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).
   - All commits must include a **Signed-off-by** line using `git commit -s` or `git commit --signoff`.

   A commit-msg hook (`.git/hooks/commit-msg`) validates:
   1. Commit title follows Conventional Commits format
   2. `Signed-off-by` line is present

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

8. Push your branch to GitHub:

   ```sh
   git push origin feature/GH-11--release-process
   ```

9. Submit a pull request through the GitHub website.

## Pull Request Guidelines

Before you submit a pull request, check that it meets these guidelines:

1. The pull request should include tests.
2. If the pull request adds functionality, the docs should be updated. Put your new functionality into a function with a docstring.
3. The pull request should work for Python 3.10, 3.11, 3.12, and 3.13. You can test multiple versions locally:

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
