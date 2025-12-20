---
weight: 5
---

# Reference


## Concepts & Data Model

 - What exists, and how it is named
 - Project
 - Dependency
 - Dependency Graph Modeling
 - Transitive Dependency Analysis
 - SBOM as System Representation
 - Provenance Tracking (ecosystem-specific)
 - Version & Version Range
 - Snapshot / Analysis Run

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
