"""Per-run and per-package tier selection.

`parse_overrides` and `commands.plan.parse_override_specs` are the same parse — same `name=value`
shape, same duplicate-conflict rejection, same scoped-npm-name handling — so both now call
`domain.common.parse_name_value_specs`. Names are normalised with `normalize_dist_name`, as
`ProjectSources` already does for `--ignore`.

Flag naming: `--strategy-override pkg=tier`, deliberately not `--override-strategy`, because
`--override pkg==version` already exists and means "force this exact version". Reading
`--override-strategy` next to `--override` invites the wrong mental model; `--strategy-override`
parses as "an override of the strategy".
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from ossiq.domain.common import parse_name_value_specs
from ossiq.strategy.pyramid import PRERELEASE_TIERS, PYRAMID, UpdateStrategy, tier_index


def parse_strategy(value: str) -> UpdateStrategy:
    """Parse a `--update-strategy` value. Raises ValueError listing the valid tier names."""
    try:
        return UpdateStrategy(value)
    except ValueError as exc:
        valid = ", ".join(tier.value for tier in PYRAMID)
        raise ValueError(f"Unknown update strategy '{value}'; must be one of: {valid}") from exc


def parse_overrides(raw: Iterable[str] | None) -> tuple[tuple[str, UpdateStrategy], ...]:
    """Parse `--strategy-override` values of the form `package=tier` into (name, tier) pairs.

    Args:
        raw: The raw option values, or None when the option was never given.

    Returns:
        (canonical_name, tier) pairs. Scoped npm names (@scope/pkg=cutting-edge) survive intact.

    Raises:
        ValueError: On a malformed spec, an unknown tier, or a package given two conflicting tiers.
    """
    return parse_name_value_specs(raw, separator="=", flag="--strategy-override", value_parser=parse_strategy)


@dataclass(frozen=True)
class StrategyPlan:
    """The tier in force for a run, plus per-package overrides."""

    default: UpdateStrategy
    overrides: Mapping[str, UpdateStrategy] = field(default_factory=dict)

    def for_package(self, canonical_name: str) -> UpdateStrategy:
        """The tier in force for one package: its override, or the run default."""
        return self.overrides.get(canonical_name, self.default)

    @property
    def max_tier(self) -> UpdateStrategy:
        """The highest tier anywhere in the run — the default, or any per-package override."""
        tiers = [self.default, *self.overrides.values()]
        return max(tiers, key=tier_index)

    @property
    def prerelease_packages(self) -> tuple[str, ...]:
        """Packages overridden to a prerelease-admitting tier (cutting-edge)."""
        return tuple(name for name, tier in self.overrides.items() if tier in PRERELEASE_TIERS)
