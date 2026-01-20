---
title: Getting Started
description: A First Tutorial on Something Important
weight: 2
---

# Getting Started

**OSS IQ** provides deep visibility into the risk profile of your open-source ecosystem. By analyzing both direct and transitive dependencies, it identifies security vulnerabilities and maintenance "red flags" before they reach production.

Built for Platform Teams OSS IQ bridges the gap between raw dependency data and actionable intelligence. It supports flexible output formats—ranging from **interactive HTML reports** and **rich console output** for human review, to **JSON** and **CSV** for automated workflows. This versatility allows teams to enforce security standards across diverse CI pipelines and repositories without the friction of a heavy, proprietary security toolchain.

## Quick Start

!!! note "GitHub Token Required"

    GitHub limits unauthenticated requests to 60/hour—insufficient for full scans.
    Set a token before running:

    ```bash
    export OSSIQ_GITHUB_TOKEN=$(gh auth token)
    ```

1. **Install**

    ```bash
    pip install ossiq
    ```

2. **Scan a project**

    Point OSS IQ at any project—it auto-detects `package.json`, `uv.lock`, `requirements.txt`, and other dependency files.

    ```bash
    ossiq-cli scan ./
    ```

3. **Review output**

    OSS IQ shows a risk summary with CVEs, version lag, and maintenance signals:


    ```bash

    ╭─────────────────────────────────────────╮
    │ 📦 Project: example                     │
    │ 🔗 Packages Registry: NPM               │
    │ 📍 Project Path: testdata/npm/project1/ │
    ╰─────────────────────────────────────────╯


                            Production Packages Version Status                           
    ┏━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━┓
    ┃ Dependency        ┃ CVEs ┃ Lag Status ┃ Installed ┃ Latest ┃ Release Lag ┃ Time Lag ┃
    ┡━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━┩
    │ react-hook-form-5 │  1   │    N/A     │ 90.9.0    │ N/A    │           2 │       0d │
    │ mustache          │  1   │   Major    │ 2.2.0     │ 4.2.0  │          18 │       5y │
    │ vue               │      │   Major    │ 1.0.23    │ 3.5.25 │         413 │      10y │
    │ i18n              │      │   Minor    │ 0.9.1     │ 0.15.3 │          16 │       5y │
    │ luxon             │      │   Patch    │ 3.7.0     │ 3.7.2  │           3 │       2m │
    │ bootstrap         │      │   Latest   │ 5.3.8     │ 5.3.8  │           0 │       0d │
    └───────────────────┴──────┴────────────┴───────────┴────────┴─────────────┴──────────┘
    ```

4. **Generate HTML report**

    ```bash
    ossiq-cli scan --presentation=html --output=./ossiq_report.html ./
    ```

    ![OSS IQ HTML report](/img/ossiq-report-html-light.png){ align=left }


## Export

### Export to JSON

```bash
export OSSIQ_GITHUB_TOKEN=$(gh auth token)
ossiq-cli export --output-format=json --output=./ossiq_metrics.json ./
```

This creates an `ossiq_metrics.json` file containing a structured representation of your project's dependency metrics. This format is ideal for CI/CD pipelines, custom dashboards, or programmatic access. The format follows the [JSON schema](https://github.com/ossiq/ossiq-cli/blob/main/src/ossiq/ui/renderers/export/schemas/export_schema_v1.0.json).

### Export to CSV

```bash
export OSSIQ_GITHUB_TOKEN=$(gh auth token)
ossiq-cli export --output-format=csv --output=./ossiq_metrics ./
```

This generates a [Tabular Data Package](https://specs.frictionlessdata.io/tabular-data-package/) following [the schema](https://github.com/ossiq/ossiq/tree/main/src/ossiq/ui/renderers/export/schemas/csv) with CSV files in the `ossiq_metrics` directory.


## Docker

Run OSS IQ without installing Python dependencies using the [official Docker image](https://hub.docker.com/r/ossiq/ossiq-cli).

1. **Scan a project**

    ```bash
    docker run --rm \
      -e OSSIQ_GITHUB_TOKEN=$(gh auth token) \
      -v /path/to/your/project:/project:ro \
      ossiq/ossiq-cli scan /project
    ```

2. **Generate HTML report**

    ```bash
    docker run --rm \
      -e OSSIQ_GITHUB_TOKEN=$(gh auth token) \
      -v /path/to/project:/project:ro \
      -v $(pwd)/reports:/output \
      ossiq/ossiq-cli scan --presentation=html --output=/output/report.html /project
    ```

3. **Export to JSON**

    ```bash
    docker run --rm \
      -e OSSIQ_GITHUB_TOKEN=$(gh auth token) \
      -v /path/to/project:/project:ro \
      -v $(pwd)/reports:/output \
      ossiq/ossiq-cli export --output-format=json --output=/output/metrics.json /project
    ```
