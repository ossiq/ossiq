"""HPDR solver adapter: chains SolvablePool → ConstraintEncoder → HPDRKernel."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.unit_of_work.solver.driver import ConflictSet
from ossiq.unit_of_work.solver.driver_pysat import PySATDriver
from ossiq.unit_of_work.solver.encoder import ConstraintEncoder
from ossiq.unit_of_work.solver.kernel import HPDRKernel
from ossiq.unit_of_work.solver.universe import SolvablePool

logger = logging.getLogger(__name__)


def solve_direct(
    deps: Sequence,
    registry: AbstractPackageRegistryApi,
    engine_context: dict[str, str],
    *,
    allow_prerelease: bool = False,
) -> dict[str, str]:
    """Run HPDR solver over direct dependencies.

    Args:
        deps: Direct dependency descriptors satisfying the _DepLike Protocol
              (canonical_name, version, version_constraint, constraint_info).
        registry: Registry instance with warm cache from the preceding scan pass.
        engine_context: Project engine versions for L2 clause generation.
                        Pass {} in Phase 4 — populating from project metadata is Phase 5+.
        allow_prerelease: When True, include pre-release candidates.

    Returns:
        Mapping of canonical_name → recommended version string.
        Returns {} when the solver cannot select any version or when deps is empty.
    """
    if not deps:
        return {}

    problem = SolvablePool.build(deps, registry, engine_context, allow_prerelease=allow_prerelease)
    encoded = ConstraintEncoder().encode(problem)
    result = HPDRKernel(PySATDriver()).solve(encoded)

    if isinstance(result, ConflictSet):
        logger.debug("HPDR solver returned ConflictSet: %s", result.unsatisfied_clauses)
        return {}

    return dict(result.selected)
