"""
PyPI-based constraint enrichment for Python package manager parsers.
"""

import logging

import requests

from ossiq.clients.batch import BatchClient
from ossiq.clients.client_pypi import PypiVersionBatchStrategy
from ossiq.clients.common import get_user_agent
from ossiq.domain.common import ConstraintType, normalize_dist_name
from ossiq.domain.project import ConstraintSource, Dependency
from ossiq.domain.version import classify_pypi_specifier
from ossiq.solver.pep508 import applicable_requirements

logger = logging.getLogger(__name__)


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": get_user_agent()})
    return session


def batch_fetch_requires_dist(
    packages: list[tuple[str, str]],
    session: requests.Session,
) -> dict[tuple[str, str], list[str]]:
    """Batch-fetch requires_dist for a list of (name, version) pairs.

    Returns an empty dict on any failure — callers degrade gracefully.
    """
    strategy = PypiVersionBatchStrategy(session)
    client = BatchClient(strategy)
    result: dict[tuple[str, str], list[str]] = {}
    try:
        for chunk_result in client.run_batch(packages):
            result.update(chunk_result)
    except Exception as exc:  # broad catch; batch generator propagates strategy-level errors of unknown types
        logger.debug("PyPI enrichment batch failed: %s", exc)
    return result


def enrich_registry_constraints(
    registry: dict[frozenset, Dependency],
    session: requests.Session | None = None,
    *,
    python_floor: str | None = None,
    root: Dependency | None = None,
) -> None:
    """Walk all registry nodes and record what each one's PyPI metadata asks of its children.

    A lockfile says which version was picked, not what each parent asked of it, so every parent's
    requires_dist is fetched at its pinned version. Each parent's specifier for a child is appended
    to the child's `parent_constraints` (the solver's multi-parent L1), and the first one seen also
    fills a missing `version_defined`. Requirements gated on an extra count only when the parent
    enables that extra, and those gated on an environment marker only when some environment at or
    above *python_floor* reaches them.

    The project's own *root* node is never fetched: its dependencies come from the manifest, and
    PyPI may hold an unrelated package of the same name.

    Safe to call when PyPI is unreachable — enrichment is silently skipped.
    ADDITIVE and OVERRIDE constraint types are never downgraded.
    """
    if session is None:
        session = make_session()

    parents = [
        node for node in registry.values() if node is not root and {**node.dependencies, **node.optional_dependencies}
    ]
    if not parents:
        return

    requires_dist_map = batch_fetch_requires_dist(
        [(node.canonical_name, node.version_installed) for node in parents], session
    )

    for node in parents:
        raw = requires_dist_map.get((node.canonical_name, node.version_installed))
        if not raw:
            continue
        spec_map = applicable_requirements(raw, node.extras or (), python_floor)
        for child in {**node.dependencies, **node.optional_dependencies}.values():
            specifier = spec_map.get(normalize_dist_name(child.canonical_name))
            if specifier is None:
                continue
            # One entry per parent, duplicates kept: update_impact removes a single occurrence
            # when it replaces the spec that one parent imposed.
            if specifier:
                child.parent_constraints.append(specifier)
            if child.version_defined is not None:
                continue
            child.version_defined = specifier or None
            if child.constraint_info.type not in (ConstraintType.ADDITIVE, ConstraintType.OVERRIDE):
                child.constraint_info = ConstraintSource(
                    type=classify_pypi_specifier(specifier or None),
                    source_file=child.constraint_info.source_file,
                )
