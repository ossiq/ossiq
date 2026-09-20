"""
Module with various rules to detect different types of data sources
"""

from urllib.parse import urlparse

from ossiq.domain.common import RepositoryProvider, UnsupportedRepositoryProvider

GITHUB_HOSTNAME = "github.com"


def is_github_url(repo_url: str | None) -> bool:
    """True when this URL points at github.com itself.

    The single definition of the host test, shared by everything that has to agree on which
    packages GitHub can answer for: `prefetch.github_only` decides what to fetch with it,
    `coverage.classify_signal_coverage` decides what to report with it, and `get_repo_url` decides
    what counts as a repository with it.

    Subdomains (gist., raw.githubusercontent.) are excluded: they serve neither the commits nor
    the activity API, so treating them as GitHub would promise data no fetch can deliver.
    """
    if not repo_url:
        return False
    return (urlparse(repo_url).hostname or "").lower() == GITHUB_HOSTNAME


def is_repository_root_url(url: str | None) -> bool:
    """True when this URL is a GitHub repository root — `github.com/owner/name`, nothing deeper.

    The depth check is what makes it safe to scan every `project_urls` entry for a repository:
    a project's "Issues", "Releases" or "Changelog" link is the same host with a third path
    segment, and only the root is something the repository API can be asked about.
    """
    if not is_github_url(url):
        return False
    segments = [segment for segment in urlparse(url or "").path.split("/") if segment]
    return len(segments) == 2


def detect_source_code_provider(repo_url: str | None) -> RepositoryProvider:
    """
    Identify Source Code Provider by URL.
    """

    if not repo_url:
        return RepositoryProvider.PROVIDER_UNKNOWN

    if repo_url.startswith("https://github.com/") or repo_url.startswith("git@github.com:"):
        return RepositoryProvider.PROVIDER_GITHUB

    raise UnsupportedRepositoryProvider(f"Unknown repository provider for the URL: {repo_url}")


GIT_MARKERS = (
    "git+",
    "git://",
    "git@",
    "github:",
    "gitlab:",
    "bitbucket:",
    "gist:",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
)


def is_git_hosted_source(spec: str | None, source: str | None) -> bool:
    """True if an npm dependency resolves from git/URL rather than the npm registry.

    Checks both the manifest version spec (github:..., owner/repo#..., git+...) and the
    lockfile 'resolved' source (git+https://github.com/...). Registry sources
    (https://registry.npmjs.org/...) do NOT match.
    """
    if source and any(marker in source.lower() for marker in GIT_MARKERS):
        return True
    if not spec:
        return False
    text = spec.strip()
    if any(marker in text.lower() for marker in GIT_MARKERS):
        return True
    # npm 'owner/repo[#ref]' shorthand — and any URL/tarball/file: spec (all contain '/').
    # A registry semver never contains '/'; npm: aliases are excluded.
    return "/" in text and not text.lower().startswith("npm:")
