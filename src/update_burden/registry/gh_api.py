"""
Module to abstract out operations with Github API
"""
import re
import datetime
import os

from typing import List, Tuple, Iterable, Set
from rich.console import Console

import requests

from .common import (
    REPOSITORY_PROVIDER_GITHUB,
    VERSION_DATA_SOURCE_GITHUB_RELEASES
)

from .repository import Repository
from .versions import normalize_version, RepositoryVersion, Commit, User

GITHUB_API = "https://api.github.com"
HEADERS = {"Accept": "application/vnd.github.v3+json"}

# TODO: maybe it should be pulled from the environment variable
TIMEOUT = 15
MAX_RETRIES = 5
BACKOFF_FACTOR = 0.1

console = Console()


def extract_next_url(link_header: str):
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


def make_github_api_request(url: str, github_token: str | None = None) -> Tuple[bool, dict]:
    """
    Make a request to the GitHub API and properly handle pagination
    """
    headers = {}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    response = requests.get(url, timeout=TIMEOUT, headers=headers)

    # Basically let user know that we're done here with Github.
    if response.status_code == 403:
        remaining_rate_limit = response.headers.get(
            "x-ratelimit-remaining", "N/A")

        try:
            reset_rate_limit_time = datetime.datetime.fromtimestamp(
                int(response.headers.get("x-ratelimit-reset", "N/A"))
            ).isoformat()
        except ValueError:
            reset_rate_limit_time = "N/A"

        total_rate_limit = response.headers.get("x-ratelimit-limit", "N/A")

        console.print(
            f"[red bold]\\[-] Github Rate Limit Exceeded[/red bold]: [bold]Rate Limit: [/bold]"
            f"{remaining_rate_limit} out of {total_rate_limit}, "
            f"[bold]reset at[/bold] {reset_rate_limit_time}")
        console.print(
            "[bold yellow]NOTE[/bold yellow] You could increase limit "
            "by passing Github API token via `GITHUB_TOKEN` evironment variable")
    response.raise_for_status()

    return extract_next_url(response.headers.get("Link", None)), response.json()


def paginate_github_api_request(url: str, github_token: str | None = None) -> Iterable[list]:
    """
    Paginate stuff from Github API while there"s any
    """
    next_url = url

    while next_url:
        next_url, data = make_github_api_request(next_url, github_token)
        for item in data:
            yield item


def extract_github_repo_ownership(raw: str) -> tuple[str, str] | None:
    if not raw:
        return None

    s = raw.strip().removeprefix("git+").removeprefix("https://")
    m = re.search(r"github\.com[:/](?P<owner>[^/]+)/(?P<name>[^/.]+)", s)

    if m:
        return m.group("owner"), m.group("name")

    return None


def load_github_repository(repo_url: str) -> Repository:
    """
    Extract GitHub repository info from a given github URL.
    """
    owner, repo_name = extract_github_repo_ownership(repo_url)

    # TODO: pull description from github and sum up repository description
    return Repository(
        provider=REPOSITORY_PROVIDER_GITHUB,
        name=repo_name,
        owner=owner,
        description=None
    )


def load_releases_from_github(owner: str, repo: str, versions_set: Set[str], github_token: str | None = None):
    """
    Fetch releases from a GitHub repo.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/releases"

    aggregated_releases = []
    # NOTE: we need to pull all the releases we're interested in and then break iteration
    for release in paginate_github_api_request(url, github_token):
        if normalize_version(release["tag_name"]) in versions_set:
            aggregated_releases.append(release)

        if len(aggregated_releases) == len(versions_set):
            break

    return list(aggregated_releases)


def load_commits_between_tags(repository: Repository,
                              start_tag: str, end_tag: str,
                              github_token: str | None = None) -> Tuple[str, List[Commit]]:
    """
    Load commits between two tags and its patch.
    """
    compare_url = f"{GITHUB_API}/repos/{repository.owner}/"\
        f"{repository.name}/compare/{start_tag}...{end_tag}"

    _, compare_data = make_github_api_request(compare_url, github_token)

    commits_raw = compare_data.get("commits", [])
    commits = []

    for commit_data in commits_raw:
        commit = commit_data["commit"]
        author, committer = commit_data["author"], commit_data.get(
            "committer", None)

        author_user = None
        if author:
            author_user = User(
                id=author["id"],
                login=author["login"],
                html_url=author["html_url"],
                name=commit["author"]["name"],
                email=commit["author"]["email"])

        commiter_user = None
        if committer:
            commiter_user = User(
                id=committer["id"],
                login=committer["login"],
                html_url=committer["html_url"],
                name=commit["committer"]["name"],
                email=commit["committer"]["email"])

        commits.append(Commit(
            sha=commit_data["sha"],
            message=commit["message"],
            author=author_user,
            committer=commiter_user,
            author_date=commit.get("author", {}).get("date", None),
            committer_date=commit.get("committer", {}).get("date", None)
        ))

    return compare_data["patch_url"], commits


def load_tags_from_github(owner: str, repo: str,
                          versions_set: Set[str],
                          github_token: str | None = None) -> Iterable[RepositoryVersion]:
    """
    Fetch tags from a GitHub repo.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/tags"

    aggregated_tags = []
    for tag in paginate_github_api_request(url, github_token):
        if tag["name"] in versions_set:
            aggregated_tags.append(tag)

        if len(aggregated_tags) == len(versions_set):
            break

    return list(aggregated_tags)


def load_github_code_versions_releases(repository: Repository,
                                       releases: list[dict],
                                       github_token: str | None = None) -> Iterable[RepositoryVersion]:
    """
    Pull commits associated with the given releases.
    """
    for n in range(len(releases)):
        if n + 1 >= len(releases):
            break

        version_to, version_from = releases[n], releases[n + 1]
        patch_url, commits = load_commits_between_tags(
            repository,
            version_from["tag_name"],
            version_to["tag_name"],
            github_token
        )

        yield RepositoryVersion(
            version_source_type=VERSION_DATA_SOURCE_GITHUB_RELEASES,
            commits=commits,
            version=version_to["tag_name"],
            prev_version=version_from["tag_name"],
            name=version_to["name"],
            description=version_to["body"],
            repository_version_url=version_to["html_url"],
            patch_url=patch_url
        )


def load_github_code_versions_tags(
        repository: Repository,
        tags: list[dict],
        github_token: str | None = None) -> Iterable[RepositoryVersion]:
    """
    Pull commits associated with the given releases.
    """
    for n in range(len(tags)):
        if n + 1 >= len(tags):
            break

        version_to, version_from = tags[n], tags[n + 1]
        patch_url, commits = load_commits_between_tags(
            repository,
            version_from["name"],
            version_to["name"],
            github_token
        )
        html_url = f"{repository.html_url}/tree/{version_to["name"]}"
        yield RepositoryVersion(
            version_source_type=VERSION_DATA_SOURCE_GITHUB_RELEASES,
            commits=commits,
            version=normalize_version(version_to["name"]),
            prev_version=normalize_version(version_from["name"]),
            name=version_to["name"],
            description=None,
            repository_version_url=html_url,
            patch_url=patch_url
        )


def load_github_code_versions(repository: Repository,
                              package_versions: List[RepositoryVersion],
                              github_token: str | None = None) -> List[RepositoryVersion]:
    """
    Pull versions info available from the given repository. Github releases
    is the default way to get it, then fallback to tags.
    """
    versions_set = set([pv.version for pv in package_versions])
    releases = load_releases_from_github(
        repository.owner,
        repository.name,
        versions_set,
        github_token
    )
    # NOTE: if infrastructure based on github releases, then that's it
    if releases:
        released_versions = list(load_github_code_versions_releases(
            repository, releases, github_token))

        if len(released_versions) != len(versions_set):
            # NOTE: we would need to identify difference between what was released and what was
            # registered in the Package Registry and fill the gap
            released_versions_set = set(
                [rv.version for rv in released_versions])
            versions_difference = versions_set - released_versions_set
            tags = list(load_tags_from_github(
                repository.owner,
                repository.name,
                versions_difference,
                github_token))
            tag_versions = list(load_github_code_versions_tags(
                repository, tags, github_token))

            return sorted(
                released_versions + tag_versions,
                key=lambda x: x.version
            )

    # otherwise fall back to git tags to establish link between code and package version
    else:
        tags = list(load_tags_from_github(
            repository.owner,
            repository.name,
            versions_set,
            github_token))

        if not tags:
            raise ValueError(
                f"Seems like there is unrecognized "
                f"versioning method for {repository.html_url}")

        return list(load_github_code_versions_tags(repository, tags, github_token))
