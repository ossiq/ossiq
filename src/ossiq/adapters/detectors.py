"""
Module with various rules to detect different types of data sources
"""

from ossiq.domain.common import RepositoryProvider, UnsupportedRepositoryProvider


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
