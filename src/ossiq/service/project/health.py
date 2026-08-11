"""
Populates Health Score fields that depend on graph position and the risk formulas.
"""

from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from itertools import chain

from ossiq.adapters.package_managers.dependency_tree import GraphExporter
from ossiq.domain.project import Dependency
from ossiq.risk.exposure import (
    DependencyTier,
    combine_incident_probability,
    compute_expected_exposure,
    compute_impact,
    fitness_projection,
)
from ossiq.risk.gate import get_gate_decision
from ossiq.risk.p_supplychain import compute_p_supplychain
from ossiq.risk.p_vuln import compute_p_vuln
from ossiq.service.project.models import ScanRecord


@dataclass(frozen=True)
class GraphMetrics:
    """Graph-derived inputs to compute_impact() for one installed package."""

    tier: DependencyTier
    """Where the package sits in the build: "runtime" (production edge) or "dev"."""

    normalized_fan_out: float
    """How much of the project reaches this package, in [0, 1]: distinct direct roots whose subtree
    contains it, divided by the number of direct roots in its own tier. Direct dependencies are
    roots themselves, so they get 1.0."""

    transitive_count: int
    """Unique descendants reachable from this package over production edges - its own blast radius
    when it pulls the rest of the tree in. Damped by log1p in compute_impact()."""


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


def compute_dependency_tree_metrics(
    walker: GraphExporter, include_optional_roots: bool = True
) -> dict[str, GraphMetrics]:
    """
    Tier/Fan-Out/Transitive-count for every installed package
    """

    prod_roots = list(walker.root.dependencies.values())
    dev_roots = list(walker.root.optional_dependencies.values())
    prod_root_names = {d.name for d in prod_roots}
    dev_root_names = {d.name for d in dev_roots}

    counts = walker.descendant_counts(include_optional_roots=include_optional_roots)

    # Direct dependencies are roots of themselves, so their fan-out is 1.0 by definition.
    # Prod is merged last, so it wins for a package declared in both tiers.
    metrics = {d.canonical_name: GraphMetrics("dev", 1.0, counts[d.canonical_name]) for d in dev_roots}
    metrics |= {d.canonical_name: GraphMetrics("runtime", 1.0, counts[d.canonical_name]) for d in prod_roots}

    walk_roots = chain(prod_roots, dev_roots) if include_optional_roots else iter(prod_roots)
    reached_by: defaultdict[str, set[str]] = defaultdict(set)
    for root in walk_roots:
        for canonical_name in reachable_names(root):
            reached_by[canonical_name].add(root.name)

    for canonical_name, roots in reached_by.items():
        if canonical_name in metrics:
            continue

        prod_hits = roots & prod_root_names
        hits = prod_hits or roots & dev_root_names
        universe = prod_root_names if prod_hits else dev_root_names
        tier: DependencyTier = "runtime" if prod_hits else "dev"
        metrics[canonical_name] = GraphMetrics(
            tier=tier,
            normalized_fan_out=len(hits) / len(universe) if universe else 0.0,
            transitive_count=counts[canonical_name],
        )

    return metrics


def populate_health_fields(
    records: Iterable[ScanRecord],
    graph_metrics: dict[str, GraphMetrics],
    cooldown_days: int,
) -> None:
    """Aggregate and assign health score metrics"""
    for record in records:
        metrics = graph_metrics[record.package_name]
        record.p_vuln = compute_p_vuln(record.cve, record.exposure_window_days)
        record.p_supplychain = compute_p_supplychain(record, cooldown_days)
        record.impact = compute_impact(
            metrics.tier,
            metrics.normalized_fan_out,
            metrics.transitive_count,
            record.runs_code_at_install,
        )
        p_incident = combine_incident_probability(record.p_vuln, record.p_supplychain)
        record.expected_exposure = compute_expected_exposure(record.impact, p_incident)
        record.fitness = fitness_projection(record.expected_exposure)
        record.gate_decision = get_gate_decision(record, cooldown_days)
