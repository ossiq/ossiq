"""Tests for qa/update_strategies_regression.py.

The script is loaded by path: `qa/` is not an importable package. Only the offline core is
covered - the fixtures and their expectations, the reference range checks the script judges OSS
IQ by, plan parsing and the known-issue bookkeeping. The runs themselves need the network.
"""

import importlib.util
import sys
from dataclasses import replace
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "qa" / "update_strategies_regression.py"


def load_script() -> ModuleType:
    """Import update_strategies_regression.py from its file path.

    Returns:
        The loaded module.
    """
    spec = importlib.util.spec_from_file_location("update_strategies_regression", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # @dataclass resolves its module through sys.modules, so registering it is not optional.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


regression = load_script()
TIER = {tier.name: tier for tier in regression.TIERS}

PLAN_OUTPUT = """
───────────── OSS IQ — Plan: regression-update-strategies-npm ─────────────
  Package Manager: npm  |  Direct: 1  |  Transitive: 0

  Package       Current    Recommended    Age     Type
  semver CVE    5.7.1      5.7.2          529d    direct

Requires constraint widening — a newer version exists outside the declared range:
  Package     Current    Declared    Reachable    Scope         Type
  minimist    0.0.8      ~0.0.8      0.2.4        same major    direct

3 more updates available under --update-strategy standard.
"""


def observed(**overrides: Any) -> Any:
    """Build an Observed export row for a drift-free package, with *overrides* applied."""
    base = regression.Observed(
        name="pkg",
        installed="1.0.0",
        declared="^1.0.0",
        recommended=None,
        rung=None,
        widening=False,
        strategy_widening=False,
        motives=frozenset(),
        withheld_reason=None,
        escalation=None,
        next_action=None,
        advisories=frozenset(),
    )
    return replace(base, **overrides)


def run(tier: str, pkg: Any) -> Any:
    """A TierRun holding just *pkg*."""
    return regression.TierRun(tier=TIER[tier], packages={pkg.name: pkg}, echoed_strategy=tier)


@pytest.mark.parametrize(
    "fixture_dir",
    sorted(path.parent for path in regression.FIXTURES_ROOT.glob(f"*/{regression.EXPECTATIONS_FILE}")),
    ids=lambda path: path.name,
)
def test_committed_fixtures_match_their_expectations(fixture_dir: Path) -> None:
    fixture = regression.load_fixture(fixture_dir)

    failed = [check for check in regression.fixture_checks(fixture) if check.status is not regression.Status.PASS]

    assert failed == []
    assert all(set(expected.outcomes) == set(regression.TIER_NAMES) for expected in fixture.packages.values())


@pytest.mark.parametrize(
    ("spec", "version", "admitted"),
    [
        ("^2.0.0", "2.1.3", True),
        ("^5.7.1", "7.6.3", False),
        ("~0.0.8", "0.2.4", False),
        ("1.0.0", "1.1.1", False),
        # npm's prerelease rule, which univers alone gets wrong
        ("^12.0.0", "13.0.0-0", False),
        ("^2.0.0", "3.0.0-canary.1", False),
        ("^13.0.0-0", "13.0.0-1", True),
        ("^3.0.0-canary.1", "3.0.0-canary.202508261828", True),
    ],
)
def test_npm_admits_follows_npm_semantics(spec: str, version: str, admitted: bool) -> None:
    assert regression.NpmEcosystem().admits(spec, version) is admitted


@pytest.mark.parametrize(
    ("spec", "version", "admitted"),
    [
        (">=3.0,<4", "3.10", True),
        ("==23.1.0", "25.3.0", False),
        # PEP 440: an exclusive upper bound excludes that version's own prereleases
        (">=0.20,<0.22", "0.22rc5", False),
        (">=0.20", "0.22rc5", True),
    ],
)
def test_pypi_admits_follows_pep_440(spec: str, version: str, admitted: bool) -> None:
    assert regression.PypiEcosystem().admits(spec, version) is admitted


def test_parse_plan_splits_update_and_widening_tables() -> None:
    sections = regression.parse_plan(PLAN_OUTPUT, regression.NpmEcosystem())

    assert set(sections.updates) == {"semver"}
    assert "5.7.2" in sections.updates["semver"]
    assert set(sections.widening) == {"minimist"}
    assert "0.2.4" in sections.widening["minimist"]


@pytest.mark.parametrize(
    "raw",
    [
        {"recommended": "1.0.1", "widen": True},
        {"recommended": "1.0.1", "withheld": True},
        {"widening": "yes"},
        "1.0.1",
    ],
)
def test_parse_outcome_rejects_what_would_go_unchecked(raw: Any) -> None:
    with pytest.raises(regression.FixtureError):
        regression.parse_outcome("cell", raw)


def test_security_move_without_a_cve_breaks_the_motive_rule() -> None:
    pkg = observed(recommended="1.1.0", rung="in_range", motives=frozenset({"drift"}))

    problems = dict(regression.package_rules(regression.NpmEcosystem(), TIER["security"], pkg))

    assert problems["moves-only-on-admitted-motive"]
    assert dict(regression.package_rules(regression.NpmEcosystem(), TIER["standard"], pkg)) == {
        name: [] for name in problems
    }


def test_widening_flag_is_checked_against_the_range_itself() -> None:
    # The flag agrees with the rung, but the rung is wrong: `<0.22` excludes 0.22rc5.
    pkg = observed(installed="0.20.1", declared=">=0.20,<0.22", recommended="0.22rc5", rung="in_range")

    problems = dict(regression.package_rules(regression.PypiEcosystem(), TIER["cutting-edge"], pkg))

    assert problems["widening-flag-matches-range"]
    assert problems["no-prerelease-below-cutting-edge"] == []


def test_apply_monotonic_catches_a_higher_tier_that_writes_less() -> None:
    security = observed(installed="5.7.1", recommended="5.7.2", rung="in_range")
    standard = observed(installed="5.7.1", recommended="7.6.3", rung="latest", widening=True)
    fixture = regression.load_fixture(regression.FIXTURES_ROOT / "npm")

    checks = regression.cross_tier_invariants(fixture, [run("security", security), run("standard", standard)])

    by_name = {check.name: check.status for check in checks}
    assert by_name == {"recommendation-monotonic": regression.Status.PASS, "apply-monotonic": regression.Status.FAIL}


def test_known_issue_turns_its_failures_into_xfail_and_flags_a_fix_as_xpass() -> None:
    fixture = regression.load_fixture(regression.FIXTURES_ROOT / "npm")
    known = [
        (key, tier) for key, exp in fixture.packages.items() for tier, out in exp.outcomes.items() if out.known_issue
    ]
    (failing_key, failing_tier), (fixed_key, fixed_tier) = known[0], known[1]
    checks = [
        regression.Check(fixture.name, failing_tier, failing_key, "expectation", regression.Status.FAIL, "boom"),
        regression.Check(fixture.name, fixed_tier, fixed_key, "expectation", regression.Status.PASS),
        regression.Check(fixture.name, "latest", "ms", "expectation", regression.Status.FAIL, "real"),
    ]

    resolved = regression.resolve_known_issues(fixture, frozenset(regression.TIER_NAMES), checks)

    statuses = {(check.package, check.tier, check.name): check.status for check in resolved}
    assert statuses[(failing_key, failing_tier, "expectation")] is regression.Status.XFAIL
    assert statuses[(fixed_key, fixed_tier, "known-issue")] is regression.Status.XPASS
    assert statuses[("ms", "latest", "expectation")] is regression.Status.FAIL
