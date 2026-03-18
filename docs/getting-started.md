---
title: Getting Started
description: OSS IQ solves the problem of unmanaged dependency drift and invisible transitive supply-chain risk by replacing alert-driven, CVE-centric tooling with calm, longitudinal, and deterministic analysis that enables planned, context-aware remediation at scale.
---

# Getting Started

## What is OSS IQ?

**OSS IQ** is a tool that maps out open-source packages that your project relies on so you can keep them secure and up to date. It helps move from "CVE panic-fixing", reactive mode to "planned maintenance" of your entire software supply chain.

Most security tools only alert you when a specific vulnerability (CVE) is found, forcing you to scramble for a "reactive" fix. OSS IQ is different: it looks at your project structure to give you a clear, long-term view of your project dependencies state.

This allows you to build a predictable update rhythm, so you can focus your efforts where they matter most instead of just chasing the latest fire.

## How it works

The tool scans your project files to identify Direct Dependencies, Dependencies of your direct dpeendencies (Transitive Dependencies), how far behind you are from the latest, safest versions, signs that a library has been abandoned by its creators.

## Built for Your Workflow

**OSS IQ** is designed for Platform and Infrastructure teams who need to set standards across many different projects.

You get the data in the format that fits your task:
 
 - **Terminal (CLI)** "on-the-spot" analysis while you work.
 - **interactive HTML report** For a "bird's-eye view" of your project's overall health.
 - **JSON** or **CSV** Exports to plug data into your automated pipelines or custom spreadsheets.

## Quick Start

Get **OSS IQ** up and running in your terminal to analyze your first project.

:::{note}

GitHub limits unauthenticated API requests to 60 per hour, 
which is typically insufficient for a full scan. Because OSS IQ employs 
Mining Software Repository (MSR) techniques to analyze differences across 
many versions (e.g., high-velocity projects like TypeScript), 
it may perform hundreds of requests per run.

To ensure a complete analysis, please provide a GitHub Personal Access Token (PAT):

```bash
export OSSIQ_GITHUB_TOKEN=$(gh auth token);
```
:::

 1. **Run your first dependencies analysis**

    OSS IQ works best with the popular ecosystem dependency formats e.g. for **NPM** its [package.json](https://docs.npmjs.com/cli/v7/configuring-npm/package-json) or [package-lock.json](https://docs.npmjs.com/cli/v8/configuring-npm/package-lock-json),
    and for **PyPI** its [pylock.toml](https://packaging.python.org/en/latest/specifications/pylock-toml/#pylock-toml-spec),  [uv.lock](https://docs.astral.sh/uv/concepts/projects/layout/#the-lockfile), or classic [requirements.txt](https://pip.pypa.io/en/stable/reference/requirements-file-format/).

    Point `ossiq-cli` at an existing python or javascript project and OSS IQ will **detect proejct dependencies**.

    ```bash
    uvx --from ossiq ossiq-cli scan testdata/npm/project1/ 
    ```

    You always can install [ossiq](https://pypi.org/project/ossiq/) package with respective python tools `uv add ossiq` or `pip install ossiq`.

 3. **Understand the Output**

    OSS IQ provides a high-level risk score and breaks down specific signals for both security (vulnerabilities) and maintenance (activity, overhead, and health).

    ![OSS IQ Terminal/CLI Report](/img/ossiq-cli-report-2026-03-14.png)


## Package Details

Get a specific package details:
```bash
uvx --from ossiq ossiq-cli package . sphinx
```

![OSS IQ Terminal/CLI Package Details](/img/ossiq-cli-package-2026-03-14.png)


## HTML Report

 1. Generate HTML report:
    ```bash
    uvx --from ossiq ossiq-cli scan --presentation=html --output report.html .
    ```

 2. Open `report.html` and you'll get table view of your dependencies:
    ![OSS IQ HTML Report](/img/ossiq-html-report-2026-03-14.png)

 3. Click on the **Transitive Dependencies** tab on the top:
    ![OSS IQ Transitive Dependencies Report](/img/ossiq-html-transitive-dependencies-2026-03-14.png)

 4. Click on a dependency node (blue circle):
    ![OSS IQ Transitive Dependencies Package Details](/img/ossiq-html-transitive-dependencies-package-2026-03-14.png)

   From the report you could conclude that [eslint-plugin-vue](https://www.npmjs.com/package/eslint-plugin-vue) with
   version `10.8.0` has pretty old [semver](https://www.npmjs.com/package/semver) dependency - the latest version is `7.7.4` while dependend version is `6.3.1`.



## Export to JSON or CSV

 1. Export to JSON:
    ```bash
    uvx --from ossiq ossiq-cli export --output-format=json --output=./scan_export.json .
    ```

   you also could specify schema version via `--schema-version` argument.
   **We commited** to make sure that versions are **backward compatible**.

 2. Export to CSV:
    ```bash
    uvx --from ossiq ossiq-cli export --output-format=csv --output=./scan_export_csv .
    ```    
   **Note** that folder `scan_report_csv` will be created automatically
   if it doesn't exist.