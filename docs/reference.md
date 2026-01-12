---
weight: 5
---

# Reference


## Data Model

The `ossiq` domain model is located in the `ossiq.domain` module. It defines the core entities used for analysis.

### Project

A software project being analyzed. Each `Project` contains a `name` and lists of its direct production and development `dependencies`.

For full details, see [`ossiq/domain/project.py`](https://github.com/ossiq/ossiq/tree/main/src/ossiq/domain/project.py).

### Package

A dependency of a `Project`. A `Package` is defined by its `name` and contains a list of all its available `versions`.

For full details, see [`ossiq/domain/package.py`](https://github.com/ossiq/ossiq/tree/main/src/ossiq/domain/package.py).

### Version Models

The version-related models capture details from different sources and are aggregated into a single `Version` object.

The primary `Version` object aggregates `package_data` (from a package registry) and `repository_data` (from a source code repository). Other data classes like `Commit` and `User` provide granular detail about the source code history.

For a complete definition of all version-related data classes, see [`ossiq/domain/version.py`](https://github.com/ossiq/ossiq/tree/main/src/ossiq/domain/version.py).

---

## System Behavior

### Dependency Resolution

-   **Dependency Graph**: The system operates on a flat list of dependencies resolved from a lockfile (e.g., `package-lock.json`). It does not build or traverse a dependency graph.
-   **Transitive Dependencies**: Transitive dependency resolution is not performed. The tool relies on the dependency resolution of the target project's native package manager (e.g., `npm`, `pip`, `uv`).

### Data Provenance

Package metadata is sourced from ecosystem-specific repositories (e.g., npm registry, PyPI). This is handled by a set of adapters in the `ossiq.adapters` module (e.g., `ossiq.adapters.api_npm`).

### Analysis Output

A single analysis run produces a `ProjectMetrics` object.

**Class**: `ossiq.service.project.ProjectMetrics`

**Description**: Contains an analysis of each dependency, including version lags, time lags, and associated vulnerabilities.

---

!!! warning

    Everything below is vibe-coded draft what needs to be described.
    Since there are quite a few halluzinations, list might be incorrect.


## Inputs

 - What OSS IQ consumes
 - Software Ecosystem Analysis
 - Manifest Files
 - Lockfiles
 - SBOM Formats (SPDX, CycloneDX, etc.)
 - External Data Sources (enumerated, no justification)
 - Configuration Parameters
 - Policy Definitions

## Outputs

 - What OSS IQ produces
 - OSS IQ Score (overall)
 - Dimension Scores
 - Security
 - Maintenance Activity Signals
 - Supply Chain Exposure
 - Per-Dependency Scores
 - Risk Aggregation
 - Longitudinal Analysis (if applicable)
 - Output Formats (JSON, SARIF, CLI, etc.)

## Scoring Model

 - Formal definitions, no motivation
 - Score Dimensions
 - Signal Normalization
 - Weighted Scoring Models
 - Score Ranges & Interpretation Bounds
 - Risk Propagation (transitive impact)
 - Missing Data Bias Handling

## Metric Operationalization

Atomic, inspectable units

For each metric:

 - Name
 - Metric Validity & Scope
 - Input Data
 - Output Type
 - Scope (dependency / project)
 - Stability (stable / experimental)

## Structural Dependency Risk

 - How structure is interpreted
 - Graph Directionality
 - Depth Handling
 - Cycles
 - Optional / Dev Dependencies
 - Runtime vs Build Dependencies
 - Workspace / Monorepo Handling

## Policy Enforcement

 - Deterministic behavior
 - Policy Syntax
 - Thresholds
 - Gates
 - Fail / Warn / Inform Outcomes
 - CI Exit Codes

## Versioning & Stability Guarantees

What users can rely on

 - Score Versioning
 - Metric Deprecation
 - Backward Compatibility
 - Reproducible Analysis

## CLI & API Reference

Pure interface definition

 - CLI Commands
 - Flags & Options
 - Environment Variables
 - API Endpoints (if applicable)
 - Response Schemas
