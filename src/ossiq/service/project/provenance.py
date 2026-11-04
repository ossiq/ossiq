"""Wires the supply-chain policy to a scan: which releases it rules out, and what each record shows."""

from collections.abc import Iterable, Mapping
from dataclasses import replace
from functools import partial

from packaging.utils import canonicalize_name

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi
from ossiq.domain.common import ProjectPackagesRegistry, RepositoryProvider
from ossiq.domain.exceptions import UnknownPackageVersion
from ossiq.domain.policy import Policy, PolicyRule
from ossiq.domain.provenance import ProvenanceFacts, SourceLevel, VersionBlocks
from ossiq.domain.version import PackageVersion
from ossiq.risk.provenance import build_violations, source_violation
from ossiq.service.project.models import ScanRecord
from ossiq.service.project.prefetch import prefetch_repository_source_levels, prefetch_source_code_repositories_info
from ossiq.solver.version_matchers import major_key
from ossiq.sources.core import AbstractProjectSources


def registry_policy(policy: Policy, registry: ProjectPackagesRegistry) -> Policy:
    """The policy, with its exceptions spelled the way `registry` spells package names.

    Args:
        policy: The project's policy as written in its config file.
        registry: The registry the scanned project installs from.

    Returns:
        The policy; only PyPI names change, since npm names are matched as written.
    """
    if registry is not ProjectPackagesRegistry.PYPI:
        return policy
    return replace(
        policy,
        exceptions=tuple(replace(e, package=canonicalize_name(e.package)) for e in policy.exceptions),
    )


def compute_version_blocks(
    names: Iterable[str],
    registry: AbstractPackageRegistryApi,
    policy: Policy,
    source_levels: Mapping[str, SourceLevel] | None = None,
) -> VersionBlocks:
    """The releases the policy rules out, for every named package.

    Build rules are computed over a package's whole history rather than only the releases newer than
    the installed one, because `no-downgrade` judges a release against everything published before
    it. That also means the installed release's own verdict is the same lookup as a candidate's.

    A repository below the source floor is a fact about the package, not about one release, so it
    rules out every release of it (the installed one included, which is how it gets flagged).

    Args:
        names: Packages to judge, spelled as `registry.package_versions` takes them.
        registry: Registry with the scan's warm cache.
        policy: The configured rules, with exception names in the registry's spelling.
        source_levels: Package -> how well its repository protects its history, for the packages
            that were measured.

    Returns:
        Package -> version -> reasons, listing only violating releases. Empty when no rule that
        needs release history is on, in which case the registry is not read at all.
    """
    major_of = partial(major_key, registry=registry.package_registry)
    blocks: dict[str, dict[str, tuple[str, ...]]] = {}
    for name in sorted(set(names)):
        source_reason = source_violation(policy, (source_levels or {}).get(name))
        if not policy.gates_builds and source_reason is None:
            continue
        try:
            releases = list(registry.package_versions(name))
        except UnknownPackageVersion:
            continue
        violations = build_violations(releases, policy, name, major_of)
        if source_reason is not None:
            for pv in releases:
                if not policy.waives(PolicyRule.SOURCE, name, pv.version):
                    violations[pv.version] = (*violations.get(pv.version, ()), source_reason)
        if violations:
            blocks[name] = violations
    return blocks


def populate_provenance(
    records: Iterable[ScanRecord],
    versions_since: Mapping[tuple[str, str], list[PackageVersion]],
    blocks: VersionBlocks,
    source_levels: Mapping[str, SourceLevel] | None = None,
) -> None:
    """Record, for each package, the build and source evidence behind its installed release.

    The single writer of `ScanRecord.provenance`.

    Args:
        records: Every record of the scan, direct and transitive.
        versions_since: Releases from the installed one onward, keyed by (package, installed version).
        blocks: The scan's policy verdicts; the installed release is one lookup away.
        source_levels: Package -> source level, for the direct packages that were measured.
    """
    for record in records:
        releases = versions_since.get((record.package_name, record.installed_version), [])
        installed = next((pv for pv in releases if pv.version == record.installed_version), None)
        record.provenance = ProvenanceFacts(
            build_tier=installed.trust_tier if installed else None,
            source_level=(source_levels or {}).get(record.package_name),
            violations=blocks.get(record.package_name, {}).get(record.installed_version, ()),
        )


def fetch_source_level(sources: AbstractProjectSources, repo_url: str | None) -> SourceLevel | None:
    """Read one package's source level on demand, for a package that is not in a scan yet.

    Args:
        sources: Supplies the GitHub provider.
        repo_url: The package's declared repository, if it has one.

    Returns:
        The level, or None when there is no GitHub repository or GitHub could not say. Not knowing is
        not a finding, so a caller treats None as "no violation".
    """
    if not repo_url:
        return None
    provider = sources.get_source_code_provider(RepositoryProvider.PROVIDER_GITHUB)
    repositories = prefetch_source_code_repositories_info(provider, [repo_url]).data
    return prefetch_repository_source_levels(provider, repositories, [repo_url]).data.get(repo_url)
