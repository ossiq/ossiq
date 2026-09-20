"""Which packages the GitHub-only activity channels could say nothing about, and why.

Commits, engagement flow and the README banner all come from GitHub, so `prefetch.github_only`
drops everything else before a single request is made. That is the right call - a GitLab-hosted
package is unmeasured, not unhealthy - but it used to leave no trace: `ScanRecord.stability`,
`.maintenance` and `.triage` all came back None whether the package had no repository, sat on
another host, or was a GitHub repo whose fetch failed. This module is where those three are told
apart, once, so every surface can name the packages behind `ProjectStability.unknown_packages`.
"""

from collections import defaultdict
from collections.abc import Iterable
from typing import TYPE_CHECKING

from ossiq.adapters.detectors import is_github_url
from ossiq.domain.common import SignalCoverage
from ossiq.domain.repository import Repository

if TYPE_CHECKING:
    from ossiq.service.project import models


def classify_signal_coverage(
    repo_url: str | None,
    repository: Repository | None,
    *,
    commits_expected: bool = False,
    has_commits: bool = False,
) -> SignalCoverage:
    """Say whether this package's upstream signals were readable, and if not, what stopped it.

    Covers both GitHub fetches a package can lose, because both count toward the scan's degraded
    warning and neither used to be attributable: the `/repos` call every package in the graph
    gets, and the commit history only direct dependencies get.

    The repository test is keyed off `repository` rather than `stability`, which is also empty
    under `--no-stability`. A flag the user set is not a gap in the data - which is also why
    `commits_expected` exists rather than being inferred from an empty commit map.

    Args:
        repo_url: The source repository URL the registry reported, if any.
        repository: The fetched repository metadata for that URL, if it came back.
        commits_expected: Whether the commit channel ran for this package at all - true only for
            a direct dependency on a scan where stability sampling was enabled.
        has_commits: Whether that channel returned anything for this package.

    Returns:
        The coverage state, FULL when nothing was missing.
    """
    if not repo_url:
        return SignalCoverage.NO_REPOSITORY
    if not is_github_url(repo_url):
        return SignalCoverage.UNSUPPORTED_HOST
    if repository is None:
        return SignalCoverage.REPOSITORY_UNAVAILABLE
    if commits_expected and not has_commits:
        return SignalCoverage.ACTIVITY_UNAVAILABLE
    return SignalCoverage.FULL


def coverage_gaps(records: Iterable["models.ScanRecord"]) -> dict[SignalCoverage, list[str]]:
    """Group the packages that contributed no upstream signal by what stopped them.

    Args:
        records: The scan records to summarise; FULL records are left out entirely.

    Returns:
        Display names per state, deduplicated and sorted. States with no packages are absent, so
        an empty mapping means every package was covered.
    """
    grouped: dict[SignalCoverage, set[str]] = defaultdict(set)
    for record in records:
        if record.signal_coverage != SignalCoverage.FULL:
            grouped[record.signal_coverage].add(record.display_name)
    return {state: sorted(names) for state, names in grouped.items()}
