"""
Aggregates EPSS scores across the dependency graph.
"""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from itertools import chain

from ossiq.adapters.package_managers.dependency_tree import GraphExporter
from ossiq.domain.project import Dependency
from ossiq.risk.epss import grouped_epss, package_epss
from ossiq.service.project import models


@dataclass(frozen=True)
class ProjectEpss:
    """Project-wide EPSS aggregation."""

    score: float | None
    """EPSSg over every distinct scored package, direct and transitive. None if nothing is scored."""

    scored_packages: int
    """How many distinct packages contributed to `score`."""

    unscored_cve_packages: int
    """Packages that carry a CVE but where no CVE has an EPSS score."""

    by_direct: dict[str, float]
    """Direct dependency canonical name -> EPSSg over its own subtree. Absent when the subtree has
    no scored package."""


def reachable_names(root: Dependency) -> Iterator[str]:
    """
    Canonical names reachable from `root` over production edges, `root` itself included, each yielded once.

    Iterative DFS with a visited set
    """

    seen: set[int] = set()
    stack = [root]

    while stack:
        node = stack.pop()

        if id(node) in seen:
            continue

        seen.add(id(node))
        yield node.canonical_name
        stack.extend(node.dependencies.values())


def is_published_after_cutoff(record: "models.ScanRecord") -> bool:
    """True when the installed version did not exist yet at the scan's cutoff date.

    version_age_days is measured against the cutoff rather than today, so a version published after it
    comes out negative - that describes a release that had not happened yet, so it is left unscored.
    """

    return record.version_age_days is not None and record.version_age_days < 0


def populate_epss(records: Iterable["models.ScanRecord"], walker: GraphExporter) -> ProjectEpss:
    """Assign `record.epss` on every record and aggregate the project and per-direct-dependency scores."""

    record_list = list(records)
    scored_by_name: dict[str, float] = {}
    unscored_cve_packages = 0

    for record in record_list:
        if is_published_after_cutoff(record):
            record.epss = None
            continue

        record.epss = package_epss(record.cve)
        if record.epss is not None:
            scored_by_name[record.package_name] = record.epss
        elif record.cve:
            unscored_cve_packages += 1

    direct_roots = chain(walker.root.dependencies.values(), walker.root.optional_dependencies.values())
    by_direct: dict[str, float] = {}
    for root in direct_roots:
        subtree_scores = [scored_by_name[name] for name in set(reachable_names(root)) if name in scored_by_name]
        subtree_score = grouped_epss(subtree_scores)
        if subtree_score is not None:
            by_direct[root.canonical_name] = subtree_score

    return ProjectEpss(
        score=grouped_epss(scored_by_name.values()),
        scored_packages=len(scored_by_name),
        unscored_cve_packages=unscored_cve_packages,
        by_direct=by_direct,
    )
