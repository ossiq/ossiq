"""
Module to abstract out operations with Github API
"""
import re
import datetime
import os

from typing import List, Tuple, Iterable
from rich.console import Console

import requests

from .common import (
    REPOSITORY_PROVIDER_GITHUB,
    VERSION_DATA_SOURCE_GITHUB_RELEASES
)

from .repository import Repository
from .versions import compare_versions, RepositoryVersion, Commit, User

GITHUB_API = "https://api.github.com"
HEADERS = {"Accept": "application/vnd.github.v3+json"}

# TODO: maybe it should be pulled from the environment variable
TIMEOUT = 15
MAX_RETRIES = 5
BACKOFF_FACTOR = 0.1

console = Console()
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", None)
if GITHUB_TOKEN:
    console.print(
        "[bold yellow]NOTE[/bold yellow] "
        "You're using [bold]Github API[/bold] with the Token")
    HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"


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


def make_github_api_request(url: str) -> Tuple[bool, dict]:
    """
    Make a request to the GitHub API and properly handle pagination
    """

    response = requests.get(url, timeout=TIMEOUT, headers=HEADERS)

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
            f"[red bold]\[-] Github Rate Limit Exceeded[/red bold]: [bold]Rate Limit: [/bold]"
            f"{remaining_rate_limit} out of {total_rate_limit}, "
            f"[bold]reset at[/bold] {reset_rate_limit_time}")
        console.print(
            "[bold yellow]NOTE[/bold yellow] You could increase limit "
            "by passing Github API token via `GITHUB_TOKEN` evironment variable")
    response.raise_for_status()

    return extract_next_url(response.headers.get("Link", None)), response.json()


def paginate_github_api_request(url: str) -> Iterable[list]:
    """
    Paginate stuff from Github API while there"s any
    """
    next_url = url

    while next_url:
        next_url, data = make_github_api_request(next_url)
        import ipdb
        ipdb.set_trace()
        yield data


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


def load_releases_from_github(owner: str, repo: str):
    """
    Fetch releases from a GitHub repo.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/releases"

    return list(paginate_github_api_request(url))


def load_tags_from_github(owner: str, repo: str) -> list[dict]:
    """
    Fetch tags from a GitHub repo.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/tags"

    return list(paginate_github_api_request(url))


def load_commits_between_tags(repository: Repository,
                              start_tag: str, end_tag: str) -> Tuple[str, List[Commit]]:
    """
    Load commits between two tags and its patch.
    """
    compare_url = f"{GITHUB_API}/repos/{repository.owner}/"
    f"{repository.name}/compare/{start_tag}...{end_tag}"

    r = requests.get(compare_url, headers=HEADERS, timeout=30)
    r.raise_for_status()
    compare_data = r.json()
    commits_raw = compare_data.get("commits", [])
    commits = []

    for commit_data in commits_raw:
        commit = commit_data["commit"]
        author, commiter = commit_data["author"], commit_data.get(
            "commiter", None)

        author_user = User(
            id=author["id"],
            login=author["login"],
            html_url=author["html_url"],
            name=commit["author"]["name"],
            email=commit["author"]["email"])
        commiter_user = None

        if commiter:
            commiter_user = User(
                id=commiter["id"],
                login=commiter["login"],
                html_url=commiter["html_url"],
                name=commit["author"]["name"],
                email=commit["author"]["email"])

        commits.append(Commit(
            sha=commit_data["sha"],
            message=commit["message"],
            author=author_user,
            committer=commiter_user,
            author_date=commit["author"]["date"],
            committer_date=commit["commiter"]["date"] if commiter else None
        ))

    return compare_data["patch_url"], commits


def load_github_code_versions_releases(repository: Repository,
                                       releases: list[dict]) -> Iterable[RepositoryVersion]:
    """
    Pull commits associated with the given releases.
    """
    for n in range(len(releases)):
        if n + 1 >= len(releases):
            break

        version_to, version_from = releases[n], releases[n + 1]
        patch_url, commits = load_commits_between_tags(
            repository, version_from["tag_name"], version_to["tag_name"])

        for release in releases:
            yield RepositoryVersion(
                version_source_type=VERSION_DATA_SOURCE_GITHUB_RELEASES,
                commits=commits,
                version=release["tag_name"],
                description=release["body"],
                repository_version_url=release["html_url"],
                patch_url=patch_url
            )


def load_github_code_versions(repository: Repository, package_versions: List[RepositoryVersion] | None) -> List[RepositoryVersion]:
    """
    Pull versions info available from the given repository. Github releases
    is the default way to get it, then fallback to tags.
    """

    all_tags = load_tags_from_github(repository.owner, repository.name)

    releases = load_releases_from_github(repository.owner, repository.name)

    versions = []
    if releases:
        versions = list(
            load_github_code_versions_releases(repository, releases))
    else:
        # TODO: use package_versions to filter out irrelevant tags
        # Branch for tags
        package_versions_set = set([p.version for p in package_versions])
        all_tags = load_tags_from_github(repository.owner, repository.name)
        if not all_tags:
            raise ValueError(
                f"Seems like there is unrecognized "
                f"versioning method for {repository.html_url}")

        target_tags = [t for t in all_tags
                       if t["name"] in package_versions_set]

        import ipdb
        ipdb.set_trace()

    return versions


def filter_releases_between(releases: list[dict], installed: str, latest: str) -> list[dict]:
    out = []
    for r in releases:
        tag = (r.get("tag_name") or "").lstrip("v")
        if not tag:
            continue
        if compare_versions(tag, installed) > 0 and compare_versions(tag, latest) <= 0:
            out.append(r)
    return out


def filter_tags_between(tags: list[dict], owner: str, repo: str, installed: str, latest_tag: str = None):
    """
    Fetch commits between the latest and previous tags of a GitHub repo.
    Aggregate commit messages and return summary counts.

    Steps:
      1. List tags
      2. Find latest and previous tag
      3. Compare commits between them
      4. Aggregate commit messages
      5. Produce per-commit summary + aggregated summary
    """
    session = requests.Session()
    headers = {"Accept": "application/vnd.github.v3+json"}

    if latest_tag is None:
        # tags are returned in reverse chronological order
        latest_tag = tags[0]["name"]

    prev_tag = tags[1]["name"]

    # 2. Compare commits between tags
    compare_url = f"{GITHUB_API}/repos/{owner}/{repo}/compare/{prev_tag}...{latest_tag}"
    r = session.get(compare_url, headers=headers, timeout=30)
    r.raise_for_status()
    compare_data = r.json()
    commits = compare_data.get("commits", [])

    import pprint
    pprint.pprint({
        "commits": commits,
        "tags": tags
    })
    if not commits:
        return {"latest": latest_tag, "previous": prev_tag, "commits": [], "summary": {}}

    # 3. Extract commit messages
    messages = [c["commit"]["message"].split("\n")[0] for c in commits]

    # 4. Aggregate commit messages
    # counter = Counter()
    # for msg in messages:
    #     if msg.lower().startswith("fix"):
    #         counter["fix"] += 1
    #     elif msg.lower().startswith("feat") or msg.lower().startswith("feature"):
    #         counter["feature"] += 1
    #     elif "breaking" in msg.lower():
    #         counter["breaking"] += 1
    #     else:
    #         counter["other"] += 1
    counter = {}
    summary = {
        "latest": latest_tag,
        "previous": prev_tag,
        "commit_count": len(messages),
        "category_counts": dict(counter),
        "commits": messages,
    }

    return summary
