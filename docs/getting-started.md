---
title: Getting Started
description: A First Tutorial on Something Important
weight: 2
---

# Getting Started

**OSS IQ** provides deep visibility into the risk profile of your open-source ecosystem. By analyzing both direct and transitive dependencies, it identifies security vulnerabilities and maintenance "red flags" before they reach production.

Built for Platform Teams OSS IQ bridges the gap between raw dependency data and actionable intelligence. It supports flexible output formats—ranging from **interactive HTML reports** and **rich console output** for human review, to **JSON** and **CycloneDX SBOMs** for automated workflows. This versatility allows teams to enforce security standards across diverse CI pipelines and repositories without the friction of a heavy, proprietary security toolchain.

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
    oss-iq overview ./your-project
    ```

 1. Install and run OSS IQ in **dev mode**

    ```bash
    git clone https://github.com/ossiq/ossiq.git
    cd ossiq
    uv sync

    OSSIQ_GITHUB_TOKEN=$(gh auth token) \
    uv run hatch run ossiq-cli overview testdata/npm/project1/
    ```

 2. Run your first analysis

    OSS IQ works best with the popular ecosystem dependency formats e.g. for **NPM** its [package.json](https://docs.npmjs.com/cli/v7/configuring-npm/package-json) or [package-lock.json](https://docs.npmjs.com/cli/v8/configuring-npm/package-lock-json),
    and for **PyPI** its [pylock.toml](https://packaging.python.org/en/latest/specifications/pylock-toml/#pylock-toml-spec),  [uv.lock](https://docs.astral.sh/uv/concepts/projects/layout/#the-lockfile), or classic [requirements.txt](https://pip.pypa.io/en/stable/reference/requirements-file-format/).

    You can point it at an existing project and OSS IQ will **detect dependencies automatically**.

    ```bash
    OSSIQ_GITHUB_TOKEN=$(gh auth token) \
    uv run hatch run ossiq-cli overview testdata/npm/project1/ 
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
    