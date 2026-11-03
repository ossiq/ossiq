"""Which releases of a package a supply-chain policy rules out, judged from registry evidence alone."""

from collections.abc import Callable, Hashable, Iterable, Sequence
from datetime import datetime

from ossiq.domain.provenance import SOURCE_REASON_PREFIX, ProvenancePolicy, SourceLevel, TrustTier
from ossiq.domain.version import PackageVersion
from ossiq.timeutil import parse_iso_datetime

MajorOf = Callable[[str], Hashable | None]
"""Names the major line of a version, or None when the version cannot be parsed."""

TIER_LABEL = {
    TrustTier.NONE: "no provenance",
    TrustTier.PROVENANCE: "provenance",
    TrustTier.TRUSTED_PUBLISHER: "trusted-publisher provenance",
}


def published_at(release: PackageVersion) -> datetime | None:
    """When a release was published, or None when the registry gave no usable timestamp."""
    try:
        return parse_iso_datetime(release.published_date_iso)
    except ValueError:
        return None


def is_excluded(exclude: Iterable[str], name: str, version: str) -> bool:
    """Whether an exclude entry covers a release.

    Args:
        exclude: `name` entries (every release) or `name@version` entries (one release).
        name: The package, spelled the way the entries are.
        version: The release.

    Returns:
        True when an entry names this package, and either names no version or this one.
    """
    for entry in exclude:
        # A leading "@" is an npm scope, not the start of a version.
        at = entry.rfind("@")
        if at > 0:
            if entry[:at] == name and entry[at + 1 :] == version:
                return True
        elif entry == name:
            return True
    return False


def source_violation(policy: ProvenancePolicy, level: SourceLevel | None) -> str | None:
    """Why a repository's source level breaks the policy, or None when it passes.

    Args:
        policy: The configured rules.
        level: How well the package's repository protects its history; None when it was not measured.

    Returns:
        The reason. An unmeasured repository never violates: not knowing is a gap in the data, not
        a finding about the repository.
    """
    if policy.min_source is None or level is None or level.rank >= policy.min_source.rank:
        return None
    return f"{SOURCE_REASON_PREFIX} {level.value}, below the required {policy.min_source.value}"


def build_violations(
    releases: Sequence[PackageVersion],
    policy: ProvenancePolicy,
    name: str,
    major_of: MajorOf,
) -> dict[str, tuple[str, ...]]:
    """The releases that break a build-evidence rule, with the reasons.

    `no_downgrade` compares a release with the strongest tier of every release published before it
    in the same major line, so a maintenance branch is never judged against evidence first
    introduced on a newer one. A stable release ignores prerelease history; a prerelease is judged
    against both. Evidence that could not be read never violates and never counts as history, and a
    release published at the same instant as another does not count as earlier than it.

    Args:
        releases: Every release of the package, including ones older than the installed version.
        policy: The configured rules; nothing is returned unless a build rule is on.
        name: The package, spelled the way `policy.exclude` spells it.
        major_of: Names a version's major line (None excludes it from line comparisons).

    Returns:
        Reasons per version; versions that pass are absent.
    """
    if not policy.gates_builds:
        return {}

    reasons: dict[str, list[str]] = {}
    judged = [(pv, tier) for pv in releases if (tier := pv.trust_tier) is not None]

    for pv, tier in judged:
        if tier.rank < policy.min_build.rank and not is_excluded(policy.exclude, name, pv.version):
            reasons.setdefault(pv.version, []).append(
                f"{TIER_LABEL[tier]}, below the required {TIER_LABEL[policy.min_build]}"
            )

    if policy.no_downgrade:
        dated = sorted(
            (
                (when, pv, tier)
                for pv, tier in judged
                if (when := published_at(pv)) and major_of(pv.version) is not None
            ),
            key=lambda item: item[0],
        )
        # Strongest tier seen so far per major line: stable releases only, and everything.
        best_stable: dict[Hashable, TrustTier] = {}
        best_any: dict[Hashable, TrustTier] = {}
        start = 0
        while start < len(dated):
            end = start
            while end < len(dated) and dated[end][0] == dated[start][0]:
                end += 1
            group = dated[start:end]
            for _, pv, tier in group:
                prior = (best_any if pv.is_prerelease else best_stable).get(major_of(pv.version))
                if prior is not None and prior.rank > tier.rank and not is_excluded(policy.exclude, name, pv.version):
                    reasons.setdefault(pv.version, []).append(
                        f"trust downgrade: {TIER_LABEL[tier]}, but earlier releases of this major line had "
                        f"{TIER_LABEL[prior]} (possible package takeover)"
                    )
            for _, pv, tier in group:
                line = major_of(pv.version)
                best_any[line] = max(tier, best_any.get(line, tier), key=lambda t: t.rank)
                if not pv.is_prerelease:
                    best_stable[line] = max(tier, best_stable.get(line, tier), key=lambda t: t.rank)
            start = end

    return {version: tuple(found) for version, found in reasons.items()}
