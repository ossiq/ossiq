---
title: Version Lag and CVE Quality Gate with GitHub Actions
description: Learn how to set up a GitHub Actions quality gate that scans dependencies with OSS IQ and blocks pull requests introducing critical vulnerabilities or excessive version lag. This tutorial shows how to enforce dependency and supply-chain standards using deterministic analysis—without relying on noisy, alert-driven security tools.

weight: 2
---

# Version Lag and CVE Quality Gate with GitHub Actions

In this tutorial, you will create a GitHub Actions workflow that automatically scans your project's dependencies with OSS IQ and blocks pull requests that introduce security vulnerabilities or severely outdated packages. By the end, you'll have a working quality gate that protects your main branch from risky dependency changes.

**What you'll build:**

A CI workflow that:

- Runs OSS IQ on every pull request
- Exports dependency metrics to JSON
- Fails the build if any CVEs are detected or if dependencies are too far behind

**Prerequisites:**

- A GitHub repository with a JavaScript (npm) or Python (uv/pip) project
- Basic familiarity with GitHub Actions
- A GitHub personal access token (for the OSS IQ API calls)

**Time to complete:** 15-20 minutes

---

## Step 1: Prepare Your Repository

First, let's ensure your repository has the files OSS IQ needs to analyze.

OSS IQ auto-detects dependency files. Make sure your repository contains one of these:

| Ecosystem  | Required Files                                     |
|------------|----------------------------------------------------|
| JavaScript | `package.json` and `package-lock.json`             |
| Python     | `pyproject.toml` and `uv.lock` (or `requirements.txt`) |

If you're starting fresh or want to follow along exactly, create a simple `package.json`:

```json
{
  "name": "quality-gate-demo",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "^4.18.2"
  }
}
```

Run `npm install` to generate the lockfile.

---

## Step 2: Add a GitHub Token as a Repository Secret

OSS IQ queries the GitHub API to gather repository health data for each dependency. Without authentication, GitHub limits requests to 60 per hour—not enough for most projects.

1. Go to your repository on GitHub
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Name it `OSSIQ_GITHUB_TOKEN`
5. Paste your GitHub personal access token as the value

!!! tip "Creating a token"

    If you don't have a token, create one at [github.com/settings/tokens](https://github.com/settings/tokens).
    The token needs **no special scopes**—public repository access is sufficient.

---

## Step 3: Create the Workflow File

Now let's create the GitHub Actions workflow that will run OSS IQ on every pull request.

Create the file `.github/workflows/dependency-quality-gate.yml`:

```yaml
name: Dependency Quality Gate

on:
  pull_request:
    branches: [main]

jobs:
  ossiq-scan:
    name: OSS IQ Dependency Scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install OSS IQ
        run: pip install ossiq

      - name: Run OSS IQ scan
        env:
          OSSIQ_GITHUB_TOKEN: ${{ github.token }}
        run: |
          ossiq-cli export \
            --output-format=json \
            --output=ossiq-report.json \
            .

      - name: Upload scan results
        uses: actions/upload-artifact@v4
        with:
          name: ossiq-report
          path: ossiq-report.json

      - name: Check for critical issues
        run: |
          echo "Checking OSS IQ results..."

          # Extract metrics from JSON report
          TOTAL_CVES=$(jq '.summary.total_cves' ossiq-report.json)
          PACKAGES_OUTDATED=$(jq '.summary.packages_outdated' ossiq-report.json)
          TOTAL_PACKAGES=$(jq '.summary.total_packages' ossiq-report.json)

          echo "📊 Scan Summary:"
          echo "   Total packages: $TOTAL_PACKAGES"
          echo "   Packages with CVEs: $TOTAL_CVES"
          echo "   Outdated packages: $PACKAGES_OUTDATED"

          # Fail if any CVEs are found
          if [ "$TOTAL_CVES" -gt 0 ]; then
            echo ""
            echo "❌ FAILED: Found $TOTAL_CVES CVE(s) in dependencies"
            echo ""
            echo "Packages with vulnerabilities:"
            jq -r '(.production_packages + .development_packages) | .[] | select(.cve | length > 0) | "  - \(.package_name)@\(.installed_version): \(.cve | length) CVE(s)"' ossiq-report.json
            exit 1
          fi

          # Check for severely outdated packages (default: 365 days)
          MAX_LAG_DAYS=${MAX_LAG_DAYS:-365}
          SEVERELY_OUTDATED_COUNT=$(jq "(.production_packages + .development_packages) | map(select(.time_lag_days != null and .time_lag_days > $MAX_LAG_DAYS)) | length" ossiq-report.json)

          if [ "$SEVERELY_OUTDATED_COUNT" -gt 0 ]; then
            echo ""
            echo "❌ FAILED: Found $SEVERELY_OUTDATED_COUNT package(s) more than $MAX_LAG_DAYS days behind latest"
            echo ""
            echo "Severely outdated packages:"
            jq -r "(.production_packages + .development_packages) | .[] | select(.time_lag_days != null and .time_lag_days > $MAX_LAG_DAYS) | \"  - \(.package_name): \(.time_lag_days) days behind\"" ossiq-report.json
            exit 1
          fi

          echo ""
          echo "✅ PASSED: No critical issues detected"
```

This workflow:

1. **Triggers on pull requests** to the main branch
2. **Installs OSS IQ** using pip
3. **Exports a JSON report** containing all dependency metrics
4. **Uploads the report** as a build artifact for later review
5. **Checks for CVEs** and fails the build if any are found
6. **Blocks severely outdated packages** that are more than a year old

---

## Step 4: Test Your Quality Gate

Commit and push the workflow file:

```bash
git add .github/workflows/dependency-quality-gate.yml
git commit -m "Add OSS IQ dependency quality gate"
git push origin main
```

Now create a test pull request to see the workflow in action:

```bash
git checkout -b test-quality-gate
# Make any small change to trigger the workflow
echo "# Test" >> README.md
git add README.md
git commit -m "Test quality gate"
git push origin test-quality-gate
```

Open a pull request on GitHub. You should see the "Dependency Quality Gate" check running. If your dependencies have no CVEs and are not severely outdated, the check will pass with a green checkmark.

---

## Step 5: See It Fail

Let's intentionally add a vulnerable or outdated dependency to verify the quality gate blocks it.

### Testing CVEs

Update your `package.json` to include an old version of `lodash` with known vulnerabilities:

```json
{
  "name": "quality-gate-demo",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.4",
    "express": "^4.18.2"
  }
}
```

!!! note "Why this version?"

    `lodash@4.17.4` has several known CVEs including prototype pollution vulnerabilities.
    This is a safe way to test your quality gate.

Run `npm install` to update the lockfile, then commit and push:

```bash
npm install
git add package.json package-lock.json
git commit -m "Downgrade lodash (testing quality gate)"
git push origin test-quality-gate
```

The workflow will now fail with output similar to:

```
📊 Scan Summary:
   Total packages: 2
   Packages with CVEs: 1
   Outdated packages: 1

❌ FAILED: Found 3 CVE(s) in dependencies

Packages with vulnerabilities:
  - lodash@4.17.4: 3 CVE(s)
```

The pull request will be blocked from merging until the vulnerability is resolved.

### Testing Outdated Packages

Now, let's revert the vulnerable `lodash` and instead add a very old, but not insecure, package like `moment@2.0.0` (released over a decade ago).

```json
{
  "name": "quality-gate-demo",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "^4.18.2",
    "moment": "2.0.0"
  }
}
```

Commit this change and push it. The workflow will fail again, but this time with a message about the package being outdated:

```
📊 Scan Summary:
   Total packages: 3
   Packages with CVEs: 0
   Outdated packages: 1

❌ FAILED: Found 1 package(s) more than 365 days behind latest

Severely outdated packages:
  - moment: 3500+ days behind
```

---

## What You've Learned

Congratulations! You've successfully created a dependency quality gate that:

<span class="material-symbols-outlined marker-check">check</span> Automatically scans dependencies on every pull request

<span class="material-symbols-outlined marker-check">check</span> Exports structured metrics in JSON format

<span class="material-symbols-outlined marker-check">check</span> Blocks PRs that introduce security vulnerabilities

<span class="material-symbols-outlined marker-check">check</span> Blocks PRs with severely outdated packages

<span class="material-symbols-outlined marker-check">check</span> Provides clear feedback about what needs to be fixed

## Next Steps

Now that you have a basic quality gate working, you might want to:

- **Adjust thresholds**: Modify `MAX_LAG_DAYS` or add checks for `releases_lag` to match your team's standards
- **Add notifications**: Send Slack or email alerts when scans fail
- **Generate reports**: Use `ossiq-cli scan --presentation=html` for detailed HTML reports
- **Scan on schedule**: Add a `schedule` trigger to catch new CVEs in existing dependencies

For more details on OSS IQ's metrics and what they mean, see the [Explanation](/explanation/) documentation.
