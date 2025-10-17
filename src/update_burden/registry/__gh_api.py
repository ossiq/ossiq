"""
Module to abstract out operations with Github API
"""
import re
import datetime
import itertools

from typing import List, Tuple, Iterable, Set
from rich.console import Console

import requests

from ..domain.common import (
    REPOSITORY_PROVIDER_GITHUB,
    VERSION_DATA_SOURCE_GITHUB_RELEASES,
    VERSION_DATA_SOURCE_GITHUB_TAGS
)

from ..domain.repository import Repository
from ..domain.version import (
    PackageVersion,
    RepositoryVersion,
    Commit,
    User,
    normalize_version,
    sort_versions
)

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


def extract_github_repo_ownership(raw: str) -> tuple[str, str] | None:
    """
    Extract GitHub repository ownership from a given URL.
    """
    s = raw.strip().removeprefix("git+").removeprefix("https://")
    m = re.search(r"github\.com[:/](?P<owner>[^/]+)/(?P<name>[^/.]+)", s)

    if m:
        return m.group("owner"), m.group("name")

    return None, None


def load_github_repository(repo_url: str) -> Repository:
    """
    Extract GitHub repository info from a given github URL.
    """
    owner, repo_name = extract_github_repo_ownership(repo_url)

    if not owner or not repo_name:
        raise ValueError(f"Invalid GitHub URL: {repo_url}")

    # TODO: pull description from github and sum up repository description
    return Repository(
        provider=REPOSITORY_PROVIDER_GITHUB,
        name=repo_name,
        owner=owner,
        description=None
    )


def load_releases_from_github(owner: str, repo: str,
                              versions_set: Set[str],
                              github_token: str | None = None) -> Iterable[RepositoryVersion]:
    """
    Fetch releases from a GitHub repo.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/releases"

    n = 0
    # NOTE: we need to pull all the releases we're interested in and then break iteration
    for release in paginate_github_api_request(url, github_token):
        if normalize_version(release["tag_name"]) in versions_set:
            yield RepositoryVersion(
                version_source_type=VERSION_DATA_SOURCE_GITHUB_RELEASES,
                version=normalize_version(release["tag_name"]),
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
                username=author["login"],
                profile_url=author["html_url"],
                display_name=commit["author"]["name"],
                email=commit["author"]["email"])

        commiter_user = None
        if committer:
            commiter_user = User(
                id=committer["id"],
                username=committer["login"],
                profile_url=committer["html_url"],
                display_name=commit["committer"]["name"],
                email=commit["committer"]["email"])

        commits.append(Commit(
            sha=commit_data["sha"],
            message=commit["message"],
            author=author_user,
            committer=commiter_user,
            authored_at=commit.get("author", {}).get("date", None),
            committed_at=commit.get("committer", {}).get("date", None)
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


def load_and_calculate_difference(repository: Repository,
                                  repository_version: RepositoryVersion,
                                  github_token: str | None = None) -> RepositoryVersion:
    """
    Pull commits associated with the given RepositoryVersion.
    """
    patch_url, commits = load_commits_between_tags(
        repository,
        repository_version.ref_previous,
        repository_version.ref_name,
        github_token
    )

    repository_version.patch_url = patch_url
    repository_version.commits = commits

    return repository_version


def load_github_code_tags(
        repository: Repository,
        versions: Set[str],
        github_token: str | None = None) -> Iterable[RepositoryVersion]:
    """
    Pull commits associated with the given releases.
    """
    for tag in load_tags_from_github(repository.owner, repository.name, versions, github_token):
        source_url = f"${repository.html_url}/commits/{tag["name"]}"

        yield RepositoryVersion(
            version_source_type=VERSION_DATA_SOURCE_GITHUB_TAGS,
            version=normalize_version(tag["name"]),
            ref_name=tag["name"],
            release_name=None,
            source_url=source_url,
            commits=None,
            ref_previous=None,
            release_notes=None,
            patch_url=None
        )


def load_github_code_versions(repository: Repository,
                              package_versions: List[PackageVersion],
                              github_token: str | None = None) -> Iterable[RepositoryVersion]:
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

    # NOTE: Since calculation of difference based on the git history we would need
    # to use it as a source of truth for changes regardless of what is registered in the Registry.
    if not releases:
        released_versions = list(load_github_code_tags(
            repository, versions_set, github_token))
    else:
        released_versions = list(releases)
        # Edge case #1: more package versions than releases (deleded tag?). No recovery.
        # Edge case #2: there's less releases on github than on NPM (release has been deleted).
        # Edge case #3: there might be tag, but no release (why? is it really the case?)
        # Edge case #4: initially versioning with tags, then transition to releases
        # Edge case #5: intially versioning with releases, then drop releases and go with tags only
        if len(released_versions) != len(versions_set):
            # Assumption: tags are always there regardless releases
            released_versions_set = set(
                [rv.version for rv in released_versions])
            missing_versions = versions_set - released_versions_set
            released_versions = itertools.chain(
                released_versions,
                load_github_code_tags(
                    repository, missing_versions, github_token)
            )

    # version have to be list at this point
    versions = sort_versions(released_versions)
    if not versions:
        return

    # return very first version (installed package)
    yield versions[0]

    for verion_from, version_to in itertools.zip_longest(versions, versions[1:]):
        if not version_to:
            break

        version_to.ref_previous = verion_from.ref_name

        version_to = load_and_calculate_difference(
            repository, version_to, github_token)

        yield version_to
