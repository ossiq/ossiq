"""
Module with various rules to detect different types of data sources
"""

import re


def is_github_repository(url: str | None) -> bool:
    """
    Check if a given URL is a GitHub repository.
    """
    if not url:
        return False

    s = url.strip().removeprefix("git+").removeprefix("https://")
    m = re.search(r"github\.com[:/](?P<owner>[^/]+)/(?P<name>[^/.]+)", s)

    if m:
        return True

    return False
