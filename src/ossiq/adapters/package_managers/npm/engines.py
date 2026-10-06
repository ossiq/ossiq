"""
Reading the `engines` field: what a package requires of node, and the floor a project declares.
"""

from typing import Any

from ossiq.solver.npm_range import Operator, parse_npm_range


def parse_node_engine(engines: dict[str, str] | list[str] | None) -> str | None:
    """Extract the node engine constraint from an engines field (dict or list form)."""
    if isinstance(engines, dict):
        return engines.get("node")
    if isinstance(engines, list) and engines:
        return engines[0]
    return None


# Operators whose version the range itself admits, so a minimum equal to it is a named bound.
NODE_FLOOR_OPERATORS = frozenset({Operator.GTE, Operator.EQ})


def extract_min_node_version(node_range: str) -> str | None:
    """Return the lowest concrete version admitted by an engines.node range.

    ">=18.0.0" -> "18.0.0", "^18" -> "18.0.0", "~18.4" -> "18.4.0", "18 || 20" -> "18.0.0",
    ">=18.0.0 <20.0.0" -> "18.0.0", "16.0.0 - 18.0.0" -> "16.0.0", "18.x" -> "18.0.0",
    ">=18.x" -> "18.0.0", ">17" -> "18.0.0".
    None for ranges with no lower bound this can name exactly ("<20", "*", "<16 || >=18",
    ">18.0.0") or that fail to parse ("!=19") — mirrors utils.extract_min_python_version's
    contract, which accepts only >=, ~= and == for the same reason: an exclusive ">18.0.0" names a
    bound the range itself excludes. ">17" is not exclusive in that sense: npm reads it as ">=18.0.0".

    The minimum is node-semver's own `minVersion`, via `solver.npm_range` — the same parser
    `solver.version_matchers` matches against — kept only when an inclusive bound names it.
    """
    try:
        npm_range = parse_npm_range(node_range)
    except ValueError:
        return None
    floor = npm_range.min_version()
    named = {
        comparator.version
        for comparators in npm_range.comparator_sets
        for comparator in comparators
        if comparator.operator in NODE_FLOOR_OPERATORS
    }
    return str(floor) if floor is not None and floor in named else None


# The engine keys a project's own `engines` block can declare a floor for. Kept in step with
# solver.version_matchers.NPM_SEMVER_ENGINES: a floor for an engine nothing evaluates is noise,
# and one evaluated only when declared is worse than noise.
DECLARABLE_ENGINES: tuple[str, ...] = ("node", "npm")


def declared_engine_floors(engines: Any) -> dict[str, str] | None:
    """Lowest version the project's own manifest claims to support, per engine key.

    Used when no runtime probe ran (`--no-probe-runtime`, or a probe that failed): the floor is
    what the project says it supports, not what it is running on. Keys whose range names no exact
    lower bound are dropped rather than guessed at.

    Args:
        engines: The manifest's `engines` value; anything but a non-empty mapping yields None.

    Returns:
        {engine_key: floor_version}, or None when nothing could be determined.
    """
    if not isinstance(engines, dict) or not engines:
        return None
    floors: dict[str, str] = {}
    for key in DECLARABLE_ENGINES:
        declared = engines.get(key)
        if not isinstance(declared, str):
            continue
        if floor := extract_min_node_version(declared):
            floors[key] = floor
    return floors or None
