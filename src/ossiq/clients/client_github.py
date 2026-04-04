"""
Pre-configured batch strategy for the GitHub repository info API.
"""

import re

import requests

from ossiq.clients.batch import BatchClient, BatchStrategy, BatchStrategySettings, ChunkResult

GITHUB_API = "https://api.github.com"
_GITHUB_URL_RE = re.compile(r"github\.com[:/](?P<owner>[^/]+)/(?P<name>[^/.]+)")


class GithubRepoBatchStrategy(BatchStrategy):
    """
    BatchStrategy implementation for fetching GitHub repository metadata.

    Since the GitHub REST API has no bulk /repos endpoint, chunk_size=1
    fetches repos individually but in parallel across max_workers threads.

    prepare_item   : url str -> (original_url, "repos/owner/name")
    perform_request: GET /repos/owner/name
    process_response: {original_url: raw_repo_dict}
    """

    def __init__(self, session: requests.Session):
        self.session = session

    @property
    def config(self) -> BatchStrategySettings:
        return BatchStrategySettings(
            chunk_size=1,
            max_retries=3,
            max_workers=5,
            request_timeout=15.0,
            has_pagination=False,
        )

    def prepare_item(self, item: str) -> tuple[str, str]:
        s = item.strip().removeprefix("git+").removeprefix("https://")
        m = _GITHUB_URL_RE.search(s)
        if not m:
            raise ValueError(f"Invalid GitHub URL: {item}")
        return (item, f"repos/{m.group('owner')}/{m.group('name')}")

    def perform_request(self, chunk: list) -> requests.Response:
        _, api_path = chunk[0]
        return self.session.get(f"{GITHUB_API}/{api_path}", timeout=self.config.request_timeout)

    def process_response(self, source_items: list, response: ChunkResult) -> dict[str, dict]:
        original_url, _ = source_items[0]
        return {original_url: response.data[0]}


__all__ = ("BatchClient", "GithubRepoBatchStrategy")
