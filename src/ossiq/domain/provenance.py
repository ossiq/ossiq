"""What a registry says about how a release was built and published, and the policy held against it."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum


class TrustTier(StrEnum):
    """How strong the build evidence for one release is. Definition order is the ranking, weakest first."""

    NONE = "none"
    """The release carries no provenance attestation: it was published with a plain registry token."""

    PROVENANCE = "provenance"
    """A signed build attestation is attached, but the publish did not come from a trusted publisher."""

    TRUSTED_PUBLISHER = "trusted-publisher"
    """Attested and published through the registry's OIDC trusted-publisher flow (no long-lived token)."""

    @property
    def rank(self) -> int:
        """Position on the ladder; a higher rank is stronger evidence."""
        return list(type(self)).index(self)


class SourceLevel(StrEnum):
    """How well a package's source repository protects its history. Definition order is the ranking.

    Read from the repository's current default-branch controls, not from a signed source attestation
    (GitHub publishes none), so it says what is enforced now rather than what held when a release was cut.
    """

    VERSION_CONTROLLED = "version-controlled"
    """SLSA Source L1: the source lives in a version control system we could read."""

    PROTECTED_HISTORY = "protected-history"
    """SLSA Source L2: the default branch blocks force-pushes and deletion."""

    REVIEWED = "reviewed"
    """Protected history, and a pull request with at least one approval is required to change the branch."""

    @property
    def rank(self) -> int:
        """Position on the ladder; a higher rank is stronger controls."""
        return list(type(self)).index(self)


SOURCE_REASON_PREFIX = "source repository is"
"""How every reason about a package's repository begins. The export carries reasons as plain strings, so
this is what lets a surface tell a Source violation from a Build one; the report's `provenanceBadges.ts`
repeats it."""

VersionBlocks = Mapping[str, Mapping[str, tuple[str, ...]]]
"""Releases the policy rules out: package name -> version -> the reasons. A package or version that is
absent is allowed."""


@dataclass(frozen=True)
class ProvenanceFacts:
    """What is known about the build and source evidence behind one installed package."""

    build_tier: TrustTier | None = None
    """Evidence for the installed release. None when the registry could not be read, which is not NONE."""

    source_level: SourceLevel | None = None
    """How well the package's source repository protects its history. None when it was not read: the
    package is transitive, the repository is not on GitHub, or the lookup failed."""

    violations: tuple[str, ...] = ()
    """Why the package breaks the configured policy; empty when it passes or no rule is on."""

    @property
    def source_violations(self) -> tuple[str, ...]:
        """The reasons about the repository, so a surface can mark the Source cell and not the Build one."""
        return tuple(reason for reason in self.violations if reason.startswith(SOURCE_REASON_PREFIX))

    @property
    def build_violations(self) -> tuple[str, ...]:
        """The reasons about how the release was built, which is every reason that is not about the repository."""
        return tuple(reason for reason in self.violations if not reason.startswith(SOURCE_REASON_PREFIX))


@dataclass(frozen=True)
class PolicyHold:
    """The newest release of a package that a supply-chain policy refused.

    Named so the plan can say why a package stayed put: a policy hold is the user's own rule at work,
    which only they can relax.
    """

    package: str
    """The package whose newer release was refused."""

    blocked_version: str
    """The release that was refused."""

    reason: str
    """Which rules it broke, in the policy's own words."""
