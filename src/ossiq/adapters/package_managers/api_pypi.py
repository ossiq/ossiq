"""
PyPI-based constraint enrichment for Python package manager parsers.
"""

import logging

import requests
from packaging.requirements import Requirement

from ossiq.adapters.package_managers.utils import normalize_dist_name
from ossiq.clients.batch import BatchClient
from ossiq.clients.client_pypi import PypiVersionBatchStrategy
from ossiq.clients.common import get_user_agent
from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource, Dependency
from ossiq.domain.version import classify_pypi_specifier

logger = logging.getLogger(__name__)


def parse_requires_dist(requires_dist: list[str]) -> dict[str, str]:
    """Parse PyPI requires_dist strings into {normalized_name: specifier_str} map.

    Skips extras-conditional entries (marker contains 'extra').
    Returns an empty string for unconstrained dependencies.
    """
    result: dict[str, str] = {}
    for req_str in requires_dist:
        try:
            req = Requirement(req_str)
            if req.marker and "extra" in str(req.marker):
                continue
            result[normalize_dist_name(req.name)] = str(req.specifier)
        except Exception:
            continue
    return result


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
    except Exception as exc:
        logger.debug("PyPI enrichment batch failed: %s", exc)
    return result


def enrich_registry_constraints(
    registry: dict[frozenset, Dependency],
    session: requests.Session | None = None,
) -> None:
    """Walk all registry nodes and fill in missing child constraints from PyPI.

    For each node whose children lack version_defined, fetches the node's
    requires_dist from PyPI at its pinned version and updates child nodes.

    Safe to call when PyPI is unreachable — enrichment is silently skipped.
    ADDITIVE and OVERRIDE constraint types are never downgraded.
    """
    if session is None:
        session = make_session()

    packages_to_fetch: list[tuple[str, str]] = [
        (node.canonical_name, node.version_installed)
        for node in registry.values()
        if {**node.dependencies, **node.optional_dependencies}
        and any(c.version_defined is None for c in {**node.dependencies, **node.optional_dependencies}.values())
    ]

    if not packages_to_fetch:
        return

    requires_dist_map = batch_fetch_requires_dist(packages_to_fetch, session)

    for node in registry.values():
        raw = requires_dist_map.get((node.canonical_name, node.version_installed))
        if not raw:
            continue
        spec_map = parse_requires_dist(raw)
        for child in {**node.dependencies, **node.optional_dependencies}.values():
            if child.version_defined is not None:
                continue
            specifier = spec_map.get(normalize_dist_name(child.canonical_name))
            if specifier is None:
                continue
            child.version_defined = specifier or None
            if child.constraint_info.type not in (ConstraintType.ADDITIVE, ConstraintType.OVERRIDE):
                child.constraint_info = ConstraintSource(
                    type=classify_pypi_specifier(specifier or None),
                    source_file=child.constraint_info.source_file,
                )
