"""
Implementation of SourceCodeApiClient for Github
"""
import datetime
import re
from typing import Iterable, Tuple, List, Set

import requests
from rich.console import Console

from .api_interfaces import AbstractSourceCodeApiClient
from ..domain.exceptions import GithubRateLimitError
from ..config import Settings
from ..domain.repository import Repository
from ..domain.version import RepositoryVersion, PackageVersion, sort_versions, Commit, User, normalize_version
from ..domain.common import (
    REPOSITORY_PROVIDER_GITHUB,
    VERSION_DATA_SOURCE_GITHUB_RELEASES,
    VERSION_DATA_SOURCE_GITHUB_TAGS
)
import itertools

console = Console()

GITHUB_API = "https://api.github.com"


class GithubSourceCodeApiClient(AbstractSourceCodeApiClient):
    """
    Implementation of SourceCodeApiClient for Github    
    """
    settings: Settings

    def __init__(self, settings: Settings):
        self.settings = settings

    def _extract_next_url(self, link_header: str):
        """
        Parse header <https://api.github.com/repositories/47118129/tags?page=2>;
            rel="next" and extract URL
        """
        if link_header is None:
            return None

        match = re.search(r"<(.*?)>; rel=\"next\"", link_header)
        if match:
            return match.group(1)

        return None

    def _make_github_api_request(self, url: str, timeout: int = 15) -> Tuple[str | None, dict]:
        """
        Make a request to the GitHub API and properly handle pagination
        """
        headers = {}
        if self.settings.github_token:
            headers["Authorization"] = f"Bearer {self.settings.github_token}"

        response = requests.get(url, timeout=timeout, headers=headers)

        # Basically let user know that we're done here with Github.
        if response.status_code == 403:
            remaining_rate_limit = response.headers.get(
                "x-ratelimit-remaining", "N/A")

            try:
                reset_rate_limit_time = datetime.datetime.fromtimestamp(
                    int(response.headers.get("x-ratelimit-reset", "N/A"))
                ).isoformat()
            except (ValueError, TypeError):
                reset_rate_limit_time = "N/A"

            total_rate_limit = response.headers.get("x-ratelimit-limit", "N/A")

            raise GithubRateLimitError(
                remaining=remaining_rate_limit,
                total=total_rate_limit,
                reset_time=reset_rate_limit_time,
            )

        response.raise_for_status()

        return self._extract_next_url(response.headers.get("Link", None)), response.json()

    def _paginate_github_api_request(self, url: str) -> Iterable[dict]:
        """
        Paginate stuff from Github API while there"s any
        """
        next_url = url

        while next_url:
            next_url, data = self._make_github_api_request(next_url)
            for item in data:
                yield item

    def get_repository(self,
                       repository_url: str) -> Repository:
        """
        Extract GitHub repository info from a given github URL.
        """
        s = repository_url.strip().removeprefix("git+").removeprefix("https://")
        m = re.search(r"github\.com[:/](?P<owner>[^/]+)/(?P<name>[^/.]+)", s)

        if not m:
            raise ValueError(f"Invalid GitHub URL: {repository_url}")

        owner, repo_name = m.group("owner"), m.group("name")

        # Fetch repository details to get the description
        repo_api_url = f"{GITHUB_API}/repos/{owner}/{repo_name}"
        _, repo_data = self._make_github_api_request(repo_api_url)

        return Repository(
            provider=REPOSITORY_PROVIDER_GITHUB,
            name=repo_name,
            owner=owner,
            description=repo_data.get("description")
        )

    def _load_releases(self,
                       repository: Repository,
                       versions_set: Set[str]) -> Iterable[RepositoryVersion]:
        """
        Fetch releases from a GitHub repo that match the provided versions.
        """
        url = f"{GITHUB_API}/repos/{repository.owner}/{repository.name}/releases"

        n = 0
        # NOTE: we need to pull all the releases we're interested in and then break iteration
        for release in self._paginate_github_api_request(url):
            normalized_tag = normalize_version(release["tag_name"])
            if normalized_tag in versions_set:
                yield RepositoryVersion(
                    version_source_type=VERSION_DATA_SOURCE_GITHUB_RELEASES,
                    version=normalized_tag,
                    ref_name=release["tag_name"],
                    release_name=release["name"],
                    release_notes=release.get("body", None),
                    source_url=release["html_url"],
                    patch_url=None,
                    commits=None,
                    ref_previous=None,
                )
                n += 1

            if n == len(versions_set):
                break

    def _load_commits_between_refs(self,
                                   repository: Repository,
                                   start_ref: str,
                                   end_ref: str) -> Tuple[str, List[Commit]]:
        """
        Load commits between two git references (tags/commits) and its patch URL.

        NOTE: A potential optimization is to pull all commits between the oldest and 
        newest versions in one API call, then associate them with tags client-side.
        This would reduce API calls but increase complexity.
        """
        compare_url = f"{GITHUB_API}/repos/{repository.owner}/"\
            f"{repository.name}/compare/{start_ref}...{end_ref}"

        _, compare_data = self._make_github_api_request(compare_url)

        commits_raw = compare_data.get("commits", [])
        commits = []

        for commit_data in commits_raw:
            commit = commit_data["commit"]
            author, committer = commit_data.get(
                "author"), commit_data.get("committer")

            author_user = None
            if author and commit.get("author"):
                author_user = User(
                    id=author.get("id"),
                    username=author.get("login"),
                    profile_url=author.get("html_url"),
                    display_name=commit["author"].get("name"),
                    email=commit["author"].get("email")
                )

            committer_user = None
            if committer and commit.get("committer"):
                committer_user = User(
                    id=committer.get("id"),
                    username=committer.get("login"),
                    profile_url=committer.get("html_url"),
                    display_name=commit["committer"].get("name"),
                    email=commit["committer"].get("email")
                )

            commits.append(Commit(
                sha=commit_data["sha"],
                message=commit["message"],
                author=author_user,
                committer=committer_user,
                authored_at=commit.get("author", {}).get("date"),
                committed_at=commit.get("committer", {}).get("date")
            ))

        return compare_data.get("patch_url"), commits

    def _get_diff_for_version(self,
                              repository: Repository,
                              repository_version: RepositoryVersion) -> RepositoryVersion:
        """
        Pull commits associated with the given RepositoryVersion by 
        comparing it to its previous ref.
        """
        patch_url, commits = self._load_commits_between_refs(
            repository,
            repository_version.ref_previous,
            repository_version.ref_name,
        )

        repository_version.patch_url = patch_url
        repository_version.commits = commits

        return repository_version

    def _load_versions_from_tags(self,
                                 repository: Repository,
                                 versions_set: Set[str]) -> Iterable[RepositoryVersion]:
        """
        Fetch tags from a GitHub repo and convert them to RepositoryVersion objects.
        """
        url = f"{GITHUB_API}/repos/{repository.owner}/{repository.name}/tags"

        n = 0
        for tag in self._paginate_github_api_request(url):
            version = normalize_version(tag["name"])
            if version in versions_set:
                source_url = f"{repository.html_url}/releases/tag/{tag["name"]}"
                yield RepositoryVersion(
                    version_source_type=VERSION_DATA_SOURCE_GITHUB_TAGS,
                    version=version,
                    ref_name=tag["name"],
                    release_name=None,
                    source_url=source_url,
                    commits=None,
                    ref_previous=None,
                    release_notes=None,
                    patch_url=None
                )
                n += 1
            if n == len(versions_set):
                break

    def get_versions(self,
                     repository: Repository,
                     package_versions: List[PackageVersion]) -> Iterable[RepositoryVersion]:
        """
        Pull versions info available from the given repository. Github releases
        is the default way to get it, then fallback to tags.
        """
        versions_set = {pv.version for pv in package_versions}

        # 1. Try loading from releases first, as they contain more metadata.
        releases = list(self._load_releases(repository, versions_set))

        released_versions = releases

        # 2. If some versions were not found as releases, fall back to checking tags.
        # This handles cases where a version is tagged but not formally released.
        if len(releases) != len(versions_set):
            released_versions_set = {rv.version for rv in releases}
            missing_versions = versions_set - released_versions_set
            tags_as_versions = self._load_versions_from_tags(
                repository, missing_versions)
            released_versions = list(
                itertools.chain(releases, tags_as_versions))

        # 3. Sort all found versions semantically.
        versions = sort_versions(released_versions)
        if not versions:
            return

        # 4. The first (oldest) version is our baseline; yield it as is.
        yield versions[0]

        # 5. For all subsequent versions, calculate the commit difference from the previous one.
        for version_from, version_to in itertools.zip_longest(versions, versions[1:]):
            if not version_to:
                break

            version_to.ref_previous = version_from.ref_name

            version_to_with_diff = self._get_diff_for_version(
                repository, version_to)

            yield version_to_with_diff
