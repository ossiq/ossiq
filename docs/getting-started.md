---
title: Getting Started
description: OSS IQ solves the problem of unmanaged dependency drift and invisible transitive supply-chain risk by replacing alert-driven, CVE-centric tooling with calm, longitudinal, and deterministic analysis that enables planned, context-aware remediation at scale.

weight: 2
---

# Getting Started

**OSS IQ** helps software teams understand and remediate dependency drift and transitive supply-chain risk before it turns into an emergency. Instead of alert-driven, CVE-centric tooling that forces *reactive upgrades*, OSS IQ uses static analysis of dependency files and project structure to provide calm, longitudinal insight into dependency health. It makes version drift, systemic risk, and maintenance red flags explicit—so remediation can be planned, contextual, and safe.

Built for **Platform and Infrastructure teams**, OSS IQ bridges the gap between raw dependency data and actionable engineering decisions. It analyzes both direct and transitive dependencies and produces outputs designed for real workflows: **interactive HTML reports** and **rich CLI output** for human review, alongside **JSON** and **CSV** for automation and policy enforcement. This lets teams apply consistent dependency and supply-chain standards across repositories and CI pipelines without adopting a heavy, proprietary security toolchain.


## Quick Start

Get **OSS IQ** up and running in your terminal to analyze your first project.

!!! note

    GitHub Token Required for Full Analysis > GitHub limits unauthenticated API requests to 60 per hour, 
    which is typically insufficient for a full scan. Because OSS IQ employs 
    Mining Software Repository (MSR) techniques to analyze differences across 
    many versions (e.g., high-velocity projects like TypeScript), 
    it may perform hundreds of requests per run.

    To ensure a complete analysis, please provide a GitHub Personal Access Token (PAT):

    ```bash
    export OSSIQ_GITHUB_TOKEN=$(gh auth token)
    oss-iq scan ./your-project
    ```

 1. Install and run OSS IQ in **dev mode**

    ```bash
    git clone https://github.com/ossiq/ossiq.git
    cd ossiq
    uv sync

    OSSIQ_GITHUB_TOKEN=$(gh auth token) \
    uv run hatch run ossiq-cli scan testdata/npm/project1/
    ```

 2. Run your first analysis

    OSS IQ works best with the popular ecosystem dependency formats e.g. for **NPM** its [package.json](https://docs.npmjs.com/cli/v7/configuring-npm/package-json) or [package-lock.json](https://docs.npmjs.com/cli/v8/configuring-npm/package-lock-json),
    and for **PyPI** its [pylock.toml](https://packaging.python.org/en/latest/specifications/pylock-toml/#pylock-toml-spec),  [uv.lock](https://docs.astral.sh/uv/concepts/projects/layout/#the-lockfile), or classic [requirements.txt](https://pip.pypa.io/en/stable/reference/requirements-file-format/).

    You can point it at an existing project and OSS IQ will **detect dependencies automatically**.

    ```bash
    OSSIQ_GITHUB_TOKEN=$(gh auth token) \
    uv run hatch run ossiq-cli scan testdata/npm/project1/ 
    ```

 3. Understand the Output
    OSS IQ provides a high-level risk score and breaks down specific signals for both security (vulnerabilities) and maintenance (activity, overhead, and health).

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
   