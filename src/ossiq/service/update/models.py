"""Value types of an update plan: its entries and the plan itself."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime

from ossiq.domain.common import (
    ConstraintType,
    OverrideHold,
    PassOrdering,
    PeerHold,
    RecommendationRung,
    display_package_name,
)
from ossiq.domain.provenance import PolicyHold
from ossiq.service.project.models import PeerRepair
from ossiq.service.update_impact import TransitiveImpact
from ossiq.solver.reason import RecommendationReason
from ossiq.strategy.pyramid import DEFAULT_STRATEGY, UpdateStrategy


@dataclass(frozen=True)
class UpdateEntry:
    """A single package recommended for update by the solver."""

    package_name: str
    current_version: str
    recommended_version: str
    is_direct: bool
    reason: RecommendationReason | None
    # Manifest key when it differs from the registry name (npm aliases: `uuid-v7: "npm:uuid@^7.0.0"`).
    # None for transitive records. Read it through `identity`.
    dependency_name: str | None = None
    transitive_impacts: list[TransitiveImpact] = field(default_factory=list)
    # False when transitive conflicts exist and no conflict-free candidate was found.
    is_actionable: bool = True
    version_defined: str | None = None
    constraint_type: ConstraintType = ConstraintType.DECLARED
    # The installed version carries a CVE; exempts the entry from the cooldown hold.
    is_security: bool = False
    # Set by --override; bypasses the solver and the cooldown.
    is_forced: bool = False
    # Ladder rung recommended_version came from. IN_MAJOR/LATEST need version_defined widened first, so
    # is_held_for_widening holds them out of the plan unless the tier or widening_authorized reaches
    # that far.
    from_rung: RecommendationRung | None = None
    # recommended_version sits outside version_defined (from_rung is IN_MAJOR/LATEST). Not the same as
    # is_held_for_widening: a written entry can still widen, and command_apply asks for a second
    # confirmation either way.
    widens_constraint: bool = False
    # The target's major line is a known API or module-system break. For a direct record,
    # build_candidates admitted the newest release because every installable one was gated. That pick
    # can sit inside version_defined (`uuid@>11.0.0` admitting ESM-only 14.0.2), so widens_constraint
    # is False and this flag alone triggers the confirmation.
    carries_known_break: bool = False
    # select_target took a release younger than the cooldown because an escalating motive (exploitable
    # CVE, end-of-life) left nothing aged that resolved it. Exempts the entry from the cooldown hold
    # like is_security, and also covers end-of-life.
    cooldown_bypassed: bool = False
    # select_target went past the tier's base reach because of an escalating motive (exploitable CVE,
    # end-of-life). Exempts the entry from the widening hold; widens_constraint stays True, so
    # command_apply still asks.
    widening_authorized: bool = False
    # Set on a held entry when the package manager's own release cutoff holds it, not OSS IQ's cooldown:
    # the setting that refuses the release (e.g. "uv exclude-newer") and the newest publish instant it
    # admits. Nothing OSS IQ decides lifts that hold.
    held_by: str | None = None
    held_cutoff: datetime | None = None
    # npm only: the range an override for this entry is keyed to, when the installed version alone is
    # not enough (see override_bump_entry). None keys it to current_version.
    override_key: str | None = None
    # npm only: the 1-based `npm install` pass that applies this entry, set by assign_install_passes.
    install_pass: int = 1

    @property
    def move_key(self) -> str:
        """One id per package copy that moves: an alias, or a nested copy, is a move of its own."""
        return f"{self.identity}@{self.override_key or self.current_version}"

    @property
    def identity(self) -> str:
        """The manifest key this entry writes to, which is the plan's unit of identity.

        Two npm aliases of one package (`uuid-v7`, `uuid-v11`) share a `package_name` but not an identity,
        so the plan's partitions and the manifest rewrite key on this. `package_name` stays the registry
        name, which the solver, OSV and the registry clients key on.
        """
        return self.dependency_name or self.package_name

    @property
    def display_name(self) -> str:
        """How to name this entry to a human — see domain.common.display_package_name."""
        return display_package_name(self.package_name, self.dependency_name)


@dataclass(frozen=True)
class UpdatePlan:
    """Atomic update plan derived from solver recommendations for a scanned project."""

    project_name: str
    project_path: str
    registry_type: str
    package_manager_name: str
    direct_entries: list[UpdateEntry]
    transitive_entries: list[UpdateEntry]
    pin_all: bool = False
    installed_versions: dict[str, str] = field(default_factory=dict)
    # Recommendations withheld because the target version is younger than the cooldown period.
    held_for_cooldown: list[UpdateEntry] = field(default_factory=list)
    cooldown_period: int = 0
    # True when the package manager holds new packages to cooldown_period at install time, so the plan
    # need not warn that they are outside it.
    enforces_cooldown_on_install: bool = False
    # --override targets absent from the scanned dependency tree.
    unknown_override_packages: tuple[str, ...] = ()
    # Recommendations withheld because the run's tier does not reach their rung yet; see
    # is_held_for_widening.
    held_for_widening: list[UpdateEntry] = field(default_factory=list)
    # The run's default tier; per-package tiers are in strategy_overrides.
    strategy: UpdateStrategy = DEFAULT_STRATEGY
    strategy_overrides: dict[str, UpdateStrategy] = field(default_factory=dict)
    # Packages withheld at the run's tier, counted by the lowest higher tier that would move them.
    # Feeds the "N more updates available under --update-strategy X" footer.
    available_at_higher_tier: dict[UpdateStrategy, int] = field(default_factory=dict)
    # User-written overrides that kept an update out of the plan. OSS IQ never rewrites one, so only
    # the user can release them.
    held_by_user_overrides: list[OverrideHold] = field(default_factory=list)
    # The newest release refused per package because an installed package peer-requires a range it
    # falls outside. Without it, such a package would drop out of the plan unexplained.
    held_by_peers: list[PeerHold] = field(default_factory=list)
    # The newest release refused per package by the supply-chain policy in the config file. Only the
    # user can relax a policy, so the plan names what it kept out rather than going quiet.
    held_by_policy: list[PolicyHold] = field(default_factory=list)
    # Peers installed only out of their requirers' reach. Each is added to the manifest, and its
    # family's stale copies move with it (those moves are in transitive_entries).
    peer_repairs: list[PeerRepair] = field(default_factory=list)
    # Why entries span several install passes; empty for a one-pass plan.
    pass_orderings: list[PassOrdering] = field(default_factory=list)

    @property
    def all_entries(self) -> list[UpdateEntry]:
        return self.direct_entries + self.transitive_entries

    @property
    def pass_count(self) -> int:
        return max((entry.install_pass for entry in self.all_entries), default=1)

    def through_pass(self, number: int) -> UpdatePlan:
        """The plan as it stands once pass *number* has run: those entries only, and cumulative.

        Peer repairs describe the final tree, so they wait for the last pass.
        """
        return dataclasses.replace(
            self,
            direct_entries=[e for e in self.direct_entries if e.install_pass <= number],
            transitive_entries=[e for e in self.transitive_entries if e.install_pass <= number],
            peer_repairs=self.peer_repairs if number >= self.pass_count else [],
        )
