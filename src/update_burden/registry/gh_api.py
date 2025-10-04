"""
Module to abstract out operations with Github API
"""
import re
import requests
from .repository import Repository
from .versions import compare_versions

GITHUB_API = "https://api.github.com"


def extract_github_repo_ownership(raw: str) -> tuple[str, str] | None:
    if not raw:
        return None

    s = raw.strip().removeprefix("git+").removeprefix("https://")
    m = re.search(r"github\.com[:/](?P<owner>[^/]+)/(?P<name>[^/.]+)", s)

    if m:
        return m.group("owner"), m.group("name")

    return None


def fetch_releases(owner: str, repo: str) -> list[dict]:
    """
    Fetch releases from a GitHub repo.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/releases"
    r = requests.get(url, timeout=15, headers={
                     "Accept": "application/vnd.github.v3+json"})
    r.raise_for_status()
    return r.json()


def fetch_tags(owner: str, repo: str) -> list[dict]:
    """
    Fetch tags from a GitHub repo.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/tags"
    r = requests.get(url, timeout=15, headers={
                     "Accept": "application/vnd.github.v3+json"})
    r.raise_for_status()
    return r.json()


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
