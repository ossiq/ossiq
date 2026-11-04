"""The rules a project commits to for the packages it installs, and the waivers that lift them."""

from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from fnmatch import fnmatchcase

from ossiq.domain.provenance import SourceLevel, TrustTier


class PolicyRule(StrEnum):
    """A rule a waiver can lift. The values are the block names in the policy file."""

    COOLDOWN = "cooldown"
    BUILD = "build"
    SOURCE = "source"


@dataclass(frozen=True)
class PolicyException:
    """A waiver: the named rules do not apply to the releases it matches."""

    package: str
    """A registry name, or a glob over names such as `@myorg/*`."""

    reason: str
    """Why the waiver exists. Required so a reviewer can tell a decision from a shrug."""

    versions: tuple[str, ...] = ()
    """The releases it covers; empty means every release."""

    rules: frozenset[PolicyRule] = frozenset(PolicyRule)
    """The rules it lifts; the default is all of them."""

    expires: date | None = None
    """The last day it holds; None means it never lapses."""

    def covers(self, rule: PolicyRule, name: str, version: str) -> bool:
        """Whether this waiver lifts `rule` for one release.

        Args:
            rule: The rule being judged.
            name: The package, spelled the way `package` spells it.
            version: The release.

        Returns:
            True when the waiver names the rule, matches the package, and names no versions or this one.
        """
        return (
            rule in self.rules and fnmatchcase(name, self.package) and (not self.versions or version in self.versions)
        )


@dataclass(frozen=True)
class Policy:
    """The project's supply-chain rules; every rule is off by default."""

    no_downgrade: bool = False
    """A release must not carry weaker build evidence than an earlier one of its major line."""

    min_build: TrustTier = TrustTier.NONE
    """The weakest build tier a release may carry. NONE asks for nothing."""

    min_source: SourceLevel | None = None
    """The weakest source level a package's repository may have. None asks for nothing."""

    cooldown_days: int | None = None
    """Days a release must age before it is recommended. None leaves the machine's setting in charge."""

    exceptions: tuple[PolicyException, ...] = ()
    """Waivers, with package names already in the registry's canonical spelling."""

    @property
    def gates_builds(self) -> bool:
        """Whether any rule judges a release from registry data alone, which every package can be held to."""
        return self.no_downgrade or self.min_build is not TrustTier.NONE

    @property
    def is_active(self) -> bool:
        """Whether any provenance rule is switched on."""
        return self.gates_builds or self.min_source is not None

    def waives(self, rule: PolicyRule, name: str, version: str) -> bool:
        """Whether an exception lifts `rule` for one release.

        Args:
            rule: The rule being judged.
            name: The package, spelled the way the exceptions spell it.
            version: The release.

        Returns:
            True when any exception covers it.
        """
        return any(exception.covers(rule, name, version) for exception in self.exceptions)
