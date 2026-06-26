from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from ossiq.domain.common import ConstraintType, ProjectPackagesRegistry


@dataclass(frozen=True)
class CandidateVersion:
    """A single registry version distilled to what the encoder needs."""

    version: str
    age_days: int | None
    is_deprecated: bool
    is_prerelease: bool
    is_yanked: bool
    runtime_requirements: dict[str, str] | None
    has_cve: bool = False
    requires: dict[str, str | None] | None = None


@dataclass(frozen=True)
class PackageConstraint:
    """Declared constraint for one package as seen by the solver."""

    package_name: str
    version_constraint: str | None
    constraint_type: ConstraintType
    installed_version: str
    # All version specifiers from every direct parent; empty for direct deps.
    # When non-empty, the encoder applies each as an independent L1 hard rejection
    # so a version must satisfy ALL parent constraints (diamond-dep correctness).
    all_constraints: tuple[str, ...] = ()


@dataclass(frozen=True)
class SolverProblem:
    """Typed input to the ConstraintEncoder (Phase 3).

    Uses frozen=True for the no-mutation guarantee; note that dict fields
    (candidates values, engine_context) are mutable — do not call hash() on instances.
    """

    constraints: tuple[PackageConstraint, ...]
    candidates: dict[str, tuple[CandidateVersion, ...]]
    engine_context: dict[str, str]
    registry: ProjectPackagesRegistry = ProjectPackagesRegistry.PYPI

    def fingerprint(self) -> str:
        """SHA-256 of canonical JSON — stable cache key for future memoisation."""
        payload = {
            "registry": self.registry.value,
            "engine_context": sorted(self.engine_context.items()),
            "constraints": sorted(
                [
                    {
                        "name": c.package_name,
                        "constraint": c.version_constraint,
                        "type": c.constraint_type,
                        "installed": c.installed_version,
                        "all_constraints": sorted(c.all_constraints),
                    }
                    for c in self.constraints
                ],
                key=lambda d: d["name"],
            ),
            "candidates": {
                pkg: sorted(
                    [
                        {
                            "v": cv.version,
                            "age_days": cv.age_days,
                            "cve": cv.has_cve,
                            "deprecated": cv.is_deprecated,
                            "prerelease": cv.is_prerelease,
                            "yanked": cv.is_yanked,
                            "rt": sorted((cv.runtime_requirements or {}).items()),
                            "requires": sorted((cv.requires or {}).items()),
                        }
                        for cv in cvs
                    ],
                    key=lambda d: d["v"],
                )
                for pkg, cvs in sorted(self.candidates.items())
            },
        }

        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()
