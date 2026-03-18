""" """

import os

import requests


class GithubSession(requests.Session):
    """A pre-configured Session for GitHub API."""

    def __init__(self, token: str | None = None):
        super().__init__()
        self.token = token or os.getenv("GITHUB_TOKEN")

        # Essential GitHub Headers
        self.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "ossiq-research-tool",
            }
        )
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"
