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
