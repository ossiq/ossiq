#!/usr/bin/env python3
"""GH-174 scorer: judge each run's manifest against npm, PyPI and OSV directly.

Imports nothing from ossiq on purpose: OSS IQ is one of the arms, so it can't also be the judge.

For every finished run in a batch it reads the manifest the agent wrote, finds the version each
dependency resolved to (lockfile first, else what the declared spec admitted when the run started),
and scores it against the registry *as of the run's start*:

  exists, version_found    the name, and a release matching the declared spec, are on the registry
  exact                    the agent pinned one version rather than a range
  lag_days, majors_behind  the distance to the newest stable release
  deprecated               the package or the version is deprecated, yanked, archived or Inactive
  cves                     OSV advisories against the resolved version

It also locks each manifest from scratch (`uv lock`, `npm install --package-lock-only`) inside the
experiment image, and reads from the transcript whether the agent used OSS IQ. Registry answers and
lock results are cached in the batch directory, so re-scoring reproduces the numbers; `--refresh`
fetches and locks again.

Writes runs.csv (one row per run), pins.csv (one row per declared dependency), summary.md (counts per
arm, then the worst pins) and summary.html (the same tables plus two charts) into the batch
directory, and prints the Markdown summary.

Usage:

    uv run python qa/agent_freshness/eval.py --batch pilot
    uv run python qa/agent_freshness/eval.py --batch main --refresh

Exit status: 0 on success, 2 when the batch has no finished runs or the experiment image is missing.
"""

import argparse
import csv
import json
import logging
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, fields, replace
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote, unquote

import requests
import semver
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from univers.version_range import NpmVersionRange
from univers.versions import SemverVersion

HERE = Path(__file__).resolve().parent
LOG_ROOT = HERE.parent.parent / "qa_logs" / "agent_freshness"

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI = "https://pypi.org"
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI"}
PYPI_SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"
INACTIVE_CLASSIFIER = "Development Status :: 7 - Inactive"
RETIRED_STATUSES = frozenset({"archived", "deprecated", "quarantined"})
HTTP_TIMEOUT = 60

IMAGE = "ossiq-exp"
MANIFESTS = {"npm": "package.json", "pypi": "pyproject.toml"}
LOCKFILES = {"npm": "package-lock.json", "pypi": "uv.lock"}
RESOLVE_COMMANDS = {
    "npm": "npm install --package-lock-only --ignore-scripts --no-audit --no-fund",
    "pypi": "uv lock",
}
RESOLVE_TIMEOUT_S = 300
WORST_PINS = 10

NOT_FOUND = {
    "npm": (
        re.compile(r"'(@?[^'@\s]+)@[^']*' is not in (?:this|the npm) registry"),
        re.compile(r"404 Not Found - GET https://registry\.npmjs\.org/([^\s/]+(?:%2[fF][^\s/]+)?)"),
    ),
    "pypi": (
        re.compile(r"Because ([A-Za-z0-9._-]+) was not found in the package registry"),
        re.compile(r"No matching distribution found for ([A-Za-z0-9._-]+)"),
    ),
}
OSSIQ_COMMAND = re.compile(r"(?:^|[\s/;&|('\"])ossiq\s+(?:info|status|add|plan|export|update-context)\b")
# What OSS IQ, as CLI or MCP tool, answers for a directory that has no manifest yet.
OSSIQ_NO_PROJECT = "Unable to identify Package Manager"

# univers declares its versions with attrs' `attr.s` API, whose generated __init__ ty cannot see.
build_semver = cast(Callable[[str], SemverVersion], SemverVersion)

logger = logging.getLogger("ossiq-qa.agent-freshness.eval")


@dataclass(frozen=True)
class Release:
    """One published version: when it went out, and why not to use it, if anything."""

    version: str
    published: datetime
    deprecated: str | None


@dataclass(frozen=True)
class PackageRecord:
    """What a registry says about a package; `retired` is set when the package as a whole is."""

    exists: bool
    releases: Mapping[str, Release]
    retired: str | None


MISSING = PackageRecord(exists=False, releases={}, retired=None)


@dataclass(frozen=True)
class DeclaredDependency:
    """A dependency the agent's manifest declares, with the version its lockfile pinned, if any."""

    name: str
    declared: str
    locked: str | None


@dataclass(frozen=True)
class DependencyScore:
    """One declared dependency, scored against the registry as of the run's start."""

    name: str
    declared: str
    exact: bool
    installed: str | None
    installed_from: str | None
    newest: str | None
    exists: bool
    version_found: bool
    deprecated: bool
    deprecation_note: str | None
    lag_days: int | None
    majors_behind: int | None
    cves: tuple[str, ...]


@dataclass(frozen=True)
class TranscriptFacts:
    """What the agent did, read from Claude Code's stream-json event stream."""

    commands: tuple[str, ...]
    outputs: tuple[str, ...]
    tool_calls: int
    ossiq_used: bool
    ossiq_skill_used: bool
    ossiq_no_project: bool
    web_search_used: bool
    cost_usd: float | None
    input_tokens: int
    output_tokens: int


def parse_iso(text: str) -> datetime:
    """Parse an ISO-8601 timestamp; registries write UTC with a trailing Z."""
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def package_key(ecosystem: str, name: str) -> str:
    """The name a registry treats as identical: PEP 503-normalized on PyPI, as written on npm."""
    return canonicalize_name(name) if ecosystem == "pypi" else name


def stable_version(ecosystem: str, version: str) -> Version | None:
    """Parse a stable release into one comparable type; None for prereleases and unparseable strings."""
    if ecosystem == "npm":
        try:
            parsed = semver.Version.parse(version)
        except ValueError:
            return None
        return None if parsed.prerelease else Version(f"{parsed.major}.{parsed.minor}.{parsed.patch}")
    try:
        release = Version(version)
    except InvalidVersion:
        return None
    return None if release.is_prerelease else release


def admits(ecosystem: str, spec: str, version: str) -> bool | None:
    """Whether a declared range admits `version`; None when the spec isn't a version range at all."""
    spec = spec.strip()
    if ecosystem == "npm":
        if spec in ("", "*", "latest", "x"):
            return True
        try:
            return build_semver(version) in NpmVersionRange.from_native(spec)
        except ValueError:
            return None
    try:
        return SpecifierSet(spec).contains(version, prereleases=True)
    except (InvalidSpecifier, InvalidVersion):
        return None


def is_exact(ecosystem: str, spec: str) -> bool:
    """Whether a declared spec names one version, as the prompt asks, rather than a range."""
    spec = spec.strip()
    if ecosystem == "npm":
        try:
            semver.Version.parse(spec.removeprefix("=").removeprefix("v"))
        except ValueError:
            return False
        return True
    return re.fullmatch(r"===?[^,*\s]+", spec) is not None


def npm_record(packument: Mapping[str, Any]) -> PackageRecord:
    """Read a full npm packument. Unpublished versions keep a `time` entry but leave `versions`."""
    times = packument.get("time") or {}
    versions = packument.get("versions") or {}
    releases = {
        version: Release(version, parse_iso(times[version]), meta.get("deprecated") or None)
        for version, meta in versions.items()
        if version in times
    }
    latest = (packument.get("dist-tags") or {}).get("latest")
    retired = (versions.get(latest) or {}).get("deprecated") or None if latest else None
    return PackageRecord(exists=True, releases=releases, retired=retired)


def pypi_record(project: Mapping[str, Any], simple: Mapping[str, Any] | None) -> PackageRecord:
    """Read PyPI's JSON API (releases, classifiers) and simple API (PEP 792 project status)."""
    releases = {}
    for version, files in (project.get("releases") or {}).items():
        if not files:
            continue
        published = min(parse_iso(file["upload_time_iso_8601"]) for file in files)
        yanked = all(file.get("yanked") for file in files)
        note = f"yanked: {files[0].get('yanked_reason') or 'no reason given'}" if yanked else None
        releases[version] = Release(version, published, note)
    status = ((simple or {}).get("project-status") or {}).get("status")
    retired = None
    if status in RETIRED_STATUSES:
        reason = ((simple or {}).get("project-status") or {}).get("reason")
        retired = f"project status {status}" + (f": {reason}" if reason else "")
    elif INACTIVE_CLASSIFIER in ((project.get("info") or {}).get("classifiers") or []):
        retired = INACTIVE_CLASSIFIER
    return PackageRecord(exists=True, releases=releases, retired=retired)


def newest_stable(ecosystem: str, record: PackageRecord, as_of: datetime, spec: str | None = None) -> Release | None:
    """The newest stable release published by `as_of`, optionally within a declared range.

    Deprecated and yanked releases are passed over unless nothing else is left, as for a package
    its registry retired outright.
    """
    candidates = []
    for release in record.releases.values():
        parsed = stable_version(ecosystem, release.version)
        if parsed is None or release.published > as_of:
            continue
        if spec is not None and not admits(ecosystem, spec, release.version):
            continue
        candidates.append((parsed, release))
    clean = [candidate for candidate in candidates if candidate[1].deprecated is None] or candidates
    return max(clean, key=lambda candidate: candidate[0])[1] if clean else None


def content_items(event: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """The content blocks of a Claude stream-json message event."""
    content = (event.get("message") or {}).get("content")
    return [item for item in content if isinstance(item, dict)] if isinstance(content, list) else []


def flatten_text(content: Any) -> str:
    """Tool output as text, whether it came as a string or as a list of text blocks."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(flatten_text(item.get("text") if isinstance(item, dict) else item) for item in content)
    return "" if content is None else json.dumps(content)


def parse_transcript(lines: Iterable[str]) -> TranscriptFacts:
    """Read one run's event stream. Lines that aren't JSON events are skipped."""
    commands: list[str] = []
    outputs: list[str] = []
    invoked: list[str] = []
    web_search = skill_used = False
    cost: float | None = None
    input_tokens = output_tokens = 0
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        kind = event.get("type")
        if kind == "assistant":  # the model's turn, with its tool calls
            for item in content_items(event):
                if item.get("type") != "tool_use":
                    continue
                name, tool_input = str(item.get("name", "")), item.get("input") or {}
                invoked.append(f"{name} {json.dumps(tool_input)}")
                web_search |= name in ("WebSearch", "WebFetch")
                # Claude loads an installed skill through the Skill tool, by the skill's directory name.
                skill_used |= (
                    name == "Skill" and isinstance(tool_input, dict) and "ossiq" in str(tool_input.get("skill"))
                )
                if isinstance(tool_input, dict) and isinstance(tool_input.get("command"), str):
                    commands.append(tool_input["command"])
        elif kind == "user":  # tool results
            outputs.extend(
                flatten_text(item.get("content")) for item in content_items(event) if item.get("type") == "tool_result"
            )
        elif kind == "result":  # the closing summary
            cost = event.get("total_cost_usd")
            usage = event.get("usage") or {}
            input_tokens += sum(
                usage.get(key) or 0
                for key in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
            )
            output_tokens += usage.get("output_tokens") or 0

    blob = "\n".join(invoked).lower()
    return TranscriptFacts(
        commands=tuple(commands),
        outputs=tuple(outputs),
        tool_calls=len(invoked),
        ossiq_used="mcp__ossiq__" in blob or any(OSSIQ_COMMAND.search(command) for command in commands),
        ossiq_skill_used=skill_used or "ossiq-dependency-check" in blob or "skills/ossiq/" in blob,
        ossiq_no_project=any(OSSIQ_NO_PROJECT in output for output in outputs),
        web_search_used=web_search,
        cost_usd=cost,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )


def not_found_names(ecosystem: str, outputs: Iterable[str]) -> set[str]:
    """Package names the package manager reported as missing from the registry."""
    names = set()
    for output in outputs:
        for pattern in NOT_FOUND[ecosystem]:
            names.update(package_key(ecosystem, unquote(match)) for match in pattern.findall(output))
    return names


def npm_declared(project: Path) -> dict[str, str]:
    """Every dependency package.json declares, with its range."""
    manifest = project / "package.json"
    if not manifest.is_file():
        return {}
    data = json.loads(manifest.read_text(encoding="utf-8"))
    declared: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        declared.update(data.get(section) or {})
    return declared


def npm_locked(project: Path) -> dict[str, str]:
    """Top-level versions in package-lock.json; nested copies belong to their parents."""
    lock = project / "package-lock.json"
    if not lock.is_file():
        return {}
    packages = json.loads(lock.read_text(encoding="utf-8")).get("packages") or {}
    return {
        path.removeprefix("node_modules/"): meta["version"]
        for path, meta in packages.items()
        if path.startswith("node_modules/") and "/node_modules/" not in path and "version" in meta
    }


def requirement_lines(project: Path) -> list[str]:
    """Requirement strings from pyproject.toml (all groups and extras) and top-level requirements*.txt."""
    lines: list[str] = []
    pyproject = project / "pyproject.toml"
    if pyproject.is_file():
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        lines += (data.get("project") or {}).get("dependencies") or []
        for extra in ((data.get("project") or {}).get("optional-dependencies") or {}).values():
            lines += extra
        for group in (data.get("dependency-groups") or {}).values():
            lines += [entry for entry in group if isinstance(entry, str)]
    for requirements in sorted(project.glob("requirements*.txt")):
        for raw in requirements.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line and not line.startswith("-"):
                lines.append(line)
    return lines


def pypi_declared(project: Path) -> dict[str, str]:
    """Every dependency the project declares, keyed by normalized name, with its specifier."""
    declared = {}
    for line in requirement_lines(project):
        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            continue
        declared[canonicalize_name(requirement.name)] = str(requirement.specifier)
    return declared


def pypi_locked(project: Path) -> dict[str, str]:
    """Versions pinned in uv.lock, keyed by normalized name."""
    lock = project / "uv.lock"
    if not lock.is_file():
        return {}
    packages = tomllib.loads(lock.read_text(encoding="utf-8")).get("package") or []
    return {canonicalize_name(entry["name"]): entry["version"] for entry in packages if "version" in entry}


def declared_dependencies(ecosystem: str, workspace: Path) -> list[DeclaredDependency]:
    """What the agent's manifest declares, with the version its lockfile pinned, if it wrote one."""
    declared, locked = (npm_declared, npm_locked) if ecosystem == "npm" else (pypi_declared, pypi_locked)
    pins = locked(workspace)
    return [DeclaredDependency(name, spec, pins.get(name)) for name, spec in sorted(declared(workspace).items())]


class Registry:
    """npm, PyPI and OSV lookups, cached as JSON under the batch so a re-score is reproducible."""

    def __init__(self, cache_root: Path, refresh: bool) -> None:
        self.cache_root = cache_root
        self.refresh = refresh
        self.session = requests.Session()
        self.records: dict[tuple[str, str], PackageRecord] = {}

    def fetch(self, cache: Path, url: str, body: Mapping[str, Any] | None = None, accept: str | None = None) -> Any:
        """GET (or POST `body` to) `url`; None on a 404."""
        if cache.is_file() and not self.refresh:
            return json.loads(cache.read_text(encoding="utf-8"))["body"]
        headers = {"Accept": accept} if accept else {}
        if body is None:
            response = self.session.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        else:
            response = self.session.post(url, json=body, headers=headers, timeout=HTTP_TIMEOUT)
        if response.status_code != 404:
            response.raise_for_status()
        payload = None if response.status_code == 404 else response.json()
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({"url": url, "status": response.status_code, "body": payload}), encoding="utf-8")
        return payload

    def record(self, ecosystem: str, name: str) -> PackageRecord:
        """The registry's view of a package, or MISSING when it doesn't exist."""
        key = (ecosystem, name)
        if key not in self.records:
            stem = self.cache_root / ecosystem / quote(name, safe="")
            if ecosystem == "npm":
                packument = self.fetch(stem.with_suffix(".json"), f"{NPM_REGISTRY}/{quote(name, safe='@')}")
                record = MISSING if packument is None else npm_record(packument)
            else:
                project = self.fetch(stem.with_suffix(".json"), f"{PYPI}/pypi/{name}/json")
                simple = None
                if project is not None:
                    simple = self.fetch(
                        stem.with_suffix(".simple.json"), f"{PYPI}/simple/{name}/", accept=PYPI_SIMPLE_JSON
                    )
                record = MISSING if project is None else pypi_record(project, simple)
            self.records[key] = record
        return self.records[key]

    def cves(self, ecosystem: str, name: str, version: str) -> tuple[str, ...]:
        """OSV advisory IDs against one version."""
        cache = self.cache_root / "osv" / ecosystem / f"{quote(name, safe='')}@{version}.json"
        body = {"package": {"name": name, "ecosystem": OSV_ECOSYSTEMS[ecosystem]}, "version": version}
        # shortcut: reads OSV's first page only (up to 1000 advisories); add next_page_token if one ever fills it.
        answer = self.fetch(cache, OSV_QUERY, body=body) or {}
        return tuple(sorted(vuln["id"] for vuln in answer.get("vulns") or []))


def score_dependency(
    ecosystem: str, dependency: DeclaredDependency, record: PackageRecord, as_of: datetime
) -> DependencyScore:
    """Score one declared dependency against the registry as it stood when the run started.

    Without a lockfile entry (the agent wrote the manifest and never locked it), the installed
    version is what the declared spec would have resolved to at the run's start.
    """
    installed, installed_from = None, None
    if dependency.locked in record.releases:
        installed, installed_from = record.releases[dependency.locked], "lock"
    elif record.exists:
        installed = newest_stable(ecosystem, record, as_of, spec=dependency.declared)
        installed_from = "resolved" if installed else None
    newest = newest_stable(ecosystem, record, as_of)

    lag_days = majors_behind = None
    if installed and newest:
        lag_days = max(0, (newest.published - installed.published).days)
        installed_parsed = stable_version(ecosystem, installed.version)
        newest_parsed = stable_version(ecosystem, newest.version)
        if installed_parsed and newest_parsed:
            majors_behind = max(0, newest_parsed.major - installed_parsed.major)
    note = record.retired or (installed.deprecated if installed else None)
    return DependencyScore(
        name=dependency.name,
        declared=dependency.declared,
        exact=is_exact(ecosystem, dependency.declared),
        installed=installed.version if installed else dependency.locked,
        installed_from=installed_from,
        newest=newest.version if newest else None,
        exists=record.exists,
        # A pin to a prerelease resolves to nothing above, yet the version exists.
        version_found=installed is not None
        or any(admits(ecosystem, dependency.declared, version) for version in record.releases),
        deprecated=note is not None,
        deprecation_note=note,
        lag_days=lag_days,
        majors_behind=majors_behind,
        cves=(),
    )


def score_run(run_dir: Path, meta: Mapping[str, Any], registry: Registry, refresh: bool) -> tuple[dict, list[dict]]:
    """Score one finished run.

    Returns:
        The run's row (worst value per metric over its pins, plus transcript facts), and one row
        per declared dependency.
    """
    ecosystem = meta["ecosystem"]
    as_of = parse_iso(meta["started_at"])
    transcript = run_dir / "transcript.jsonl"
    facts = parse_transcript(transcript.read_text(encoding="utf-8", errors="replace").splitlines())

    scores = []
    for dependency in declared_dependencies(ecosystem, run_dir / "workspace"):
        record = registry.record(ecosystem, dependency.name)
        score = score_dependency(ecosystem, dependency, record, as_of)
        if score.exists and score.installed:
            score = replace(score, cves=registry.cves(ecosystem, score.name, score.installed))
        scores.append(score)

    # Names the agent tried and dropped never reach the manifest; the package manager's errors keep them.
    attempted = not_found_names(ecosystem, facts.outputs) - {score.name for score in scores}
    hallucinated = sorted(
        {score.name for score in scores if not score.exists}
        | {name for name in attempted if not registry.record(ecosystem, name).exists}
    )
    lags = [score.lag_days for score in scores if score.lag_days is not None]
    majors = [score.majors_behind for score in scores if score.majors_behind is not None]
    row = {key: meta[key] for key in ("run_id", "model", "arm", "task", "ecosystem", "rep", "exit_code", "timed_out")}
    row |= {
        "duration_s": meta["duration_s"],
        "pins": " ".join(f"{score.name}@{score.installed or score.declared}" for score in scores),
        "n_pins": len(scores),
        "not_exact": sum(not score.exact for score in scores),
        "lag_days": max(lags) if lags else None,
        "majors_behind": max(majors) if majors else None,
        "cves": sum(len(score.cves) for score in scores),
        "deprecated": sum(score.deprecated for score in scores),
        "hallucinated_names": " ".join(hallucinated),
        "missing_versions": " ".join(
            f"{score.name}@{score.declared}" for score in scores if score.exists and not score.version_found
        ),
        "resolves": resolves(ecosystem, run_dir, refresh),
        "ossiq_used": facts.ossiq_used,
        "ossiq_skill_used": facts.ossiq_skill_used,
        "ossiq_no_project": facts.ossiq_no_project,
        "web_search_used": facts.web_search_used,
        "tool_calls": facts.tool_calls,
        "cost_usd": facts.cost_usd,
        "input_tokens": facts.input_tokens,
        "output_tokens": facts.output_tokens,
    }
    pins = [
        {"run_id": meta["run_id"], "model": meta["model"], "arm": meta["arm"], "task": meta["task"], **asdict(score)}
        for score in scores
    ]
    return row, pins


def resolves(ecosystem: str, run_dir: Path, refresh: bool) -> bool | None:
    """Whether the agent's manifest locks from scratch; None when it wrote no manifest.

    Locks a copy without the agent's lockfile, so only the manifest is tested, and does it inside the
    experiment image: resolving can build an sdist, which runs code from a package the agent picked.
    """
    cache = run_dir / "resolve.json"
    if cache.is_file() and not refresh:
        return json.loads(cache.read_text(encoding="utf-8"))["ok"]
    workspace = run_dir / "workspace"
    if not (workspace / MANIFESTS[ecosystem]).is_file():
        return None
    command = RESOLVE_COMMANDS[ecosystem]
    # The container writes as uid 1000, which the host user may not be allowed to delete.
    with tempfile.TemporaryDirectory(dir=run_dir, ignore_cleanup_errors=True) as scratch:
        copy = Path(scratch) / "workspace"
        shutil.copytree(workspace, copy, ignore=shutil.ignore_patterns("node_modules", ".venv"))
        (copy / LOCKFILES[ecosystem]).unlink(missing_ok=True)
        docker = ["docker", "run", "--rm", "--user", "1000:1000", "-v", f"{copy}:/work", IMAGE]
        result = subprocess.run(
            [*docker, "timeout", str(RESOLVE_TIMEOUT_S), "sh", "-c", command],
            capture_output=True,
            text=True,
            check=False,
        )
    ok = result.returncode == 0
    record = {
        "ok": ok,
        "command": command,
        "exit_code": result.returncode,
        "output": (result.stdout + result.stderr)[-4000:],
    }
    cache.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return ok


@dataclass(frozen=True)
class ArmStats:
    """Every summary figure for one arm; summary.md and summary.html both read these."""

    arm: str
    runs: int
    pins: int
    not_exact: int
    lags: tuple[int, ...]
    behind_major: int
    with_cves: int
    deprecated: int
    not_found: int
    locked: int
    lock_checked: int
    used_ossiq: int

    @property
    def median_lag(self) -> int | None:
        return round(statistics.median(self.lags)) if self.lags else None


ARM_HEADER = [
    "arm",
    "runs",
    "pins",
    "not exact",
    "median lag (d)",
    "max lag (d)",
    "≥1 major behind",
    "with CVEs",
    "deprecated",
    "not found",
    "resolves",
    "used OSS IQ",
]
ARM_ALIGN = "l" + "r" * 11
WORST_HEADER = ["arm", "run", "package", "pinned", "newest", "lag (d)", "majors", "CVEs", "deprecated", "found"]
WORST_ALIGN = "lllll" + "rrr" + "ll"
# Colour follows the arm, never its position: baseline is always categorical slot 1, ossiq slot 2.
ARM_SLOTS = {"baseline": 1, "ossiq": 2}
# Each problem the bar chart shows, with how to count it for an arm as (hits, out of): a share of
# the arm's pins, or of its runs for the lock check.
PROBLEMS: tuple[tuple[str, Callable[[ArmStats], tuple[int, int]]], ...] = (
    ("pins with CVEs", lambda s: (s.with_cves, s.pins)),
    ("deprecated pins", lambda s: (s.deprecated, s.pins)),
    ("pinned version not found", lambda s: (s.not_found, s.pins)),
    ("pins ≥1 major behind", lambda s: (s.behind_major, s.pins)),
    ("runs that don't resolve", lambda s: (s.lock_checked - s.locked, s.lock_checked)),
)
HTML_STYLE = """
:root { color-scheme: light; --page: #f9f9f7; --surface: #fcfcfb; --ink: #0b0b0b; --ink2: #52514e;
  --muted: #898781; --grid: #e1e0d9; --axis: #c3c2b7; --border: rgba(11, 11, 11, 0.1);
  --series-1: #2a78d6; --series-2: #eb6834; --series-3: #1baf7a; }
@media (prefers-color-scheme: dark) {
  :root { color-scheme: dark; --page: #0d0d0d; --surface: #1a1a19; --ink: #f0efec; --ink2: #c3c2b7;
    --grid: #2c2c2a; --axis: #383835; --border: rgba(255, 255, 255, 0.1);
    --series-1: #3987e5; --series-2: #d95926; --series-3: #199e70; }
}
body { margin: 0; background: var(--page); color: var(--ink);
  font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 960px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 15px; margin: 0 0 4px; }
p { margin: 0 0 8px; color: var(--ink2); }
section { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
  padding: 16px 20px; margin: 16px 0; }
.scroll { overflow-x: auto; }
svg { display: block; width: 100%; min-width: 560px; max-width: 680px; height: auto; }
.s1 { --c: var(--series-1); } .s2 { --c: var(--series-2); } .s3 { --c: var(--series-3); }
.legend span { margin-right: 16px; }
.key { display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: var(--c);
  margin-right: 6px; }
.dot { fill: var(--c); stroke: var(--surface); stroke-width: 2; }
.bar { fill: var(--c); }
.grid { stroke: var(--grid); stroke-width: 1; }
.axis { stroke: var(--axis); stroke-width: 1; }
.median { stroke: var(--ink2); stroke-width: 2; }
.lbl { fill: var(--ink); font-size: 12px; }
.val { fill: var(--ink2); font-size: 11px; }
.tick { fill: var(--muted); font-size: 11px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { padding: 6px 8px; text-align: left; border-bottom: 1px solid var(--grid); white-space: nowrap; }
th { color: var(--ink2); font-weight: 600; white-space: normal; vertical-align: bottom; }
.scroll + p { margin-top: 12px; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
"""


def arm_stats(rows: Sequence[Mapping[str, Any]], pins: Sequence[Mapping[str, Any]]) -> list[ArmStats]:
    """Count each arm's runs and pins once, so every report quotes the same numbers."""
    stats = []
    for arm in sorted({row["arm"] for row in rows}):
        arm_rows = [row for row in rows if row["arm"] == arm]
        arm_pins = [pin for pin in pins if pin["arm"] == arm]
        locks = [row["resolves"] for row in arm_rows if row["resolves"] is not None]
        stats.append(
            ArmStats(
                arm=arm,
                runs=len(arm_rows),
                pins=len(arm_pins),
                not_exact=sum(not pin["exact"] for pin in arm_pins),
                lags=tuple(pin["lag_days"] for pin in arm_pins if pin["lag_days"] is not None),
                behind_major=sum((pin["majors_behind"] or 0) > 0 for pin in arm_pins),
                with_cves=sum(bool(pin["cves"]) for pin in arm_pins),
                deprecated=sum(pin["deprecated"] for pin in arm_pins),
                not_found=sum(not pin["version_found"] for pin in arm_pins),
                locked=sum(locks),
                lock_checked=len(locks),
                used_ossiq=sum(row["ossiq_used"] for row in arm_rows),
            )
        )
    return stats


def arm_cells(stats: ArmStats) -> list[Any]:
    """One arm's row of the summary table, in ARM_HEADER order."""
    return [
        stats.arm,
        stats.runs,
        stats.pins,
        stats.not_exact,
        "-" if stats.median_lag is None else stats.median_lag,
        max(stats.lags) if stats.lags else "-",
        stats.behind_major,
        stats.with_cves,
        stats.deprecated,
        stats.not_found,
        f"{stats.locked}/{stats.lock_checked}",
        f"{stats.used_ossiq}/{stats.runs}",
    ]


def worst_pins(pins: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """The pins most worth a look: not found, then CVEs, then deprecated, then the longest lag."""
    return sorted(
        pins,
        key=lambda pin: (not pin["version_found"], len(pin["cves"]), pin["deprecated"], pin["lag_days"] or 0),
        reverse=True,
    )[:WORST_PINS]


def worst_cells(pin: Mapping[str, Any]) -> list[Any]:
    """One pin's row of the worst-pins table, in WORST_HEADER order."""
    return [
        pin["arm"],
        pin["run_id"],
        pin["name"],
        pin["installed"] or pin["declared"],
        pin["newest"] or "-",
        "-" if pin["lag_days"] is None else pin["lag_days"],
        "-" if pin["majors_behind"] is None else pin["majors_behind"],
        len(pin["cves"]),
        "yes" if pin["deprecated"] else "",
        "" if pin["version_found"] else "NO",
    ]


def markdown_table(header: Sequence[str], rows: Sequence[Sequence[Any]], align: str) -> list[str]:
    """A Markdown table as lines; `align` holds one `l` or `r` per column."""
    rule = "|" + "|".join("---:" if a == "r" else "---" for a in align) + "|"
    body = ("| " + " | ".join(str(cell) for cell in row) + " |" for row in rows)
    return ["| " + " | ".join(header) + " |", rule, *body]


def html_table(header: Sequence[str], rows: Sequence[Sequence[Any]], align: str) -> str:
    """An HTML table; every cell is escaped, since package names come from the agent's manifest."""
    attrs = [' class="num"' if a == "r" else "" for a in align]
    head = "".join(f"<th{attr}>{escape(h)}</th>" for h, attr in zip(header, attrs, strict=True))
    body = "".join(
        "<tr>" + "".join(f"<td{attr}>{escape(str(c))}</td>" for c, attr in zip(row, attrs, strict=True)) + "</tr>"
        for row in rows
    )
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def tick_step(top: int) -> int:
    """The smallest round tick spacing that keeps an axis to six intervals."""
    return next((step for step in (50, 100, 200, 250, 500, 1000, 2000, 5000) if top / step <= 6), 10000)


def bar_path(x: float, y: float, w: float, h: float) -> str:
    """A horizontal bar with a square edge on the baseline and a 4px rounded tip."""
    r = min(4.0, w, h / 2)
    return (
        f"M{x:.1f},{y:.1f}h{w - r:.1f}a{r:.1f},{r:.1f} 0 0 1 {r:.1f},{r:.1f}"
        f"v{h - 2 * r:.1f}a{r:.1f},{r:.1f} 0 0 1 -{r:.1f},{r:.1f}h-{w - r:.1f}z"
    )


def lag_strip(stats: Sequence[ArmStats], pins: Sequence[Mapping[str, Any]]) -> str:
    """Strip plot: one dot per pin along days behind, one row per arm, a tick at each arm's median."""
    width, left, right, row = 640, 84, 28, 104
    lanes = tuple((k - 2.5) * 11 for k in range(6))  # dots at similar lags spread over lanes instead of stacking
    plotted = {
        s.arm: sorted((p for p in pins if p["arm"] == s.arm and p["lag_days"] is not None), key=lambda p: p["lag_days"])
        for s in stats
    }
    top = max((p["lag_days"] for arm_pins in plotted.values() for p in arm_pins), default=0)
    step = tick_step(top)
    ticks = list(range(0, max(top, 1) + step, step))
    height = len(stats) * row

    def x(days: float) -> float:
        return left + days / ticks[-1] * (width - left - right)

    out = [
        f'<svg viewBox="0 0 {width} {height + 28}" role="img" '
        'aria-label="Days behind the newest release for each pin, by arm">'
    ]
    for tick in ticks:
        out.append(
            f'<line class="grid" x1="{x(tick):.1f}" x2="{x(tick):.1f}" y1="0" y2="{height}"/>'
            f'<text class="tick" x="{x(tick):.1f}" y="{height + 18}" text-anchor="middle">{tick}</text>'
        )
    out.append(f'<line class="axis" x1="{left}" x2="{width - right}" y1="{height}" y2="{height}"/>')
    for i, s in enumerate(stats):
        cy = i * row + row / 2
        out.append(f'<g class="s{ARM_SLOTS.get(s.arm, 3)}">')
        out.append(f'<text class="lbl" x="{left - 12}" y="{cy + 4}" text-anchor="end">{escape(s.arm)}</text>')
        if s.lags:
            mx = x(statistics.median(s.lags))
            anchor = "end" if mx > width - right - 50 else "middle"
            out.append(
                f'<line class="median" x1="{mx:.1f}" x2="{mx:.1f}" y1="{cy - 34}" y2="{cy + 34}"/>'
                f'<text class="val" x="{mx:.1f}" y="{cy - 40}" text-anchor="{anchor}">median {s.median_lag} d</text>'
            )
        last = [float("-inf")] * len(lanes)
        for pin in plotted[s.arm]:
            parts = [
                f"{pin['name']}@{pin['installed'] or pin['declared']}",
                f"{pin['lag_days']} days behind {pin['newest']}",
            ]
            if pin["cves"]:
                parts.append(f"{len(pin['cves'])} CVEs")
            if pin["deprecated"]:
                parts.append("deprecated")
            cx = x(pin["lag_days"])
            # The lane whose last dot is farthest left, so neighbours at similar lags don't overlap.
            lane = max(range(len(lanes)), key=lambda k: cx - last[k])
            last[lane] = cx
            cy_dot = cy + lanes[lane]
            # The invisible r=12 circle is the hover target: an 8px dot alone is too small to hit.
            out.append(
                f"<g><title>{escape(' · '.join(parts))} ({escape(pin['run_id'])})</title>"
                f'<circle cx="{cx:.1f}" cy="{cy_dot}" r="12" fill="transparent"/>'
                f'<circle class="dot" cx="{cx:.1f}" cy="{cy_dot}" r="4"/></g>'
            )
        out.append("</g>")
    out.append("</svg>")
    return "".join(out)


def problem_bars(stats: Sequence[ArmStats]) -> str:
    """Grouped horizontal bars: for each problem, the share of an arm's pins (or runs) it hits."""
    width, left, right, thick, gap = 640, 176, 72, 14, 2
    group = len(stats) * thick + (len(stats) - 1) * gap
    pitch = group + 20
    span = width - left - right
    height = len(PROBLEMS) * pitch
    out = [
        f'<svg viewBox="0 0 {width} {height + 28}" role="img" '
        'aria-label="Share of pins and runs with each problem, by arm">'
    ]
    for pct in (0, 25, 50, 75, 100):
        gx = left + span * pct / 100
        out.append(
            f'<line class="grid" x1="{gx:.1f}" x2="{gx:.1f}" y1="0" y2="{height}"/>'
            f'<text class="tick" x="{gx:.1f}" y="{height + 18}" text-anchor="middle">{pct}%</text>'
        )
    out.append(f'<line class="axis" x1="{left}" x2="{left}" y1="0" y2="{height}"/>')
    for i, (label, count) in enumerate(PROBLEMS):
        top = i * pitch + 10
        out.append(
            f'<text class="lbl" x="{left - 10}" y="{top + group / 2 + 4:.1f}" text-anchor="end">{escape(label)}</text>'
        )
        for j, s in enumerate(stats):
            hits, total = count(s)
            y = top + j * (thick + gap)
            length = span * hits / total if total else 0
            out.append(
                f'<g class="s{ARM_SLOTS.get(s.arm, 3)}">'
                f"<title>{escape(s.arm)}: {hits} of {total} {escape(label)}</title>"
                f'<rect fill="transparent" x="{left}" y="{y - 1}" width="{span}" height="{thick + 2}"/>'
            )
            if length:
                out.append(f'<path class="bar" d="{bar_path(left, y, length, thick)}"/>')
            out.append(
                f'<text class="val" x="{left + length + 6:.1f}" y="{y + thick - 2}">{hits} of {total}</text></g>'
            )
    out.append("</svg>")
    return "".join(out)


def render_html(
    name: str, batch: Mapping[str, Any], rows: Sequence[Mapping[str, Any]], pins: Sequence[Mapping[str, Any]]
) -> str:
    """A self-contained page: two charts, then the same tables as summary.md as their table view.

    Args:
        name: The batch name, shown in the title.
        batch: The batch's batch.json, for its start date and tool versions.
        rows: One scored row per run.
        pins: One scored row per declared dependency.

    Returns:
        The page, with its CSS and SVG inline and no script.
    """
    stats = arm_stats(rows, pins)
    facts = [f"{len(rows)} runs", f"{sum(s.pins for s in stats)} pins"]
    if batch.get("created_at"):
        facts.append(f"started {batch['created_at'][:10]}")
    facts += batch.get("versions", [])
    facts_line = escape(" · ".join(facts))
    legend = "".join(
        f'<span class="s{ARM_SLOTS.get(s.arm, 3)}"><i class="key"></i>{escape(s.arm)}</span>' for s in stats
    )
    unplotted = sum(s.pins - len(s.lags) for s in stats)
    note = f" Pins without a matching release aren't plotted ({unplotted})." if unplotted else ""
    worst = worst_pins(pins)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent dependency freshness: {escape(name)}</title>
<style>{HTML_STYLE}</style>
</head>
<body>
<main>
<h1>Agent dependency freshness</h1>
<p>Batch {escape(name)}: {facts_line}. Scored as of each run's start against npm, PyPI and OSV.</p>
<p class="legend">{legend}</p>
<section>
<h2>How far behind are the pins?</h2>
<p>Days between each pinned version and the newest stable release, one dot per pin.
The line marks each arm's median.{note}</p>
<div class="scroll">{lag_strip(stats, pins)}</div>
</section>
<section>
<h2>What goes wrong?</h2>
<p>The share of an arm's pins, or of its runs for the lock check, with each problem. Labels read hits of total.</p>
<div class="scroll">{problem_bars(stats)}</div>
</section>
<section>
<h2>Per arm</h2>
{html_table(ARM_HEADER, [arm_cells(s) for s in stats], ARM_ALIGN)}
</section>
<section>
<h2>Worst {len(worst)} pins</h2>
{html_table(WORST_HEADER, [worst_cells(p) for p in worst], WORST_ALIGN)}
<p>These are counts, not statistics: a few repeats show whether output varies, not that one arm is better.</p>
</section>
</main>
</body>
</html>
"""


def summarize(rows: Sequence[Mapping[str, Any]], pins: Sequence[Mapping[str, Any]]) -> str:
    """Counts per arm, then the worst pins, as a Markdown report."""
    worst = worst_pins(pins)
    lines = markdown_table(ARM_HEADER, [arm_cells(s) for s in arm_stats(rows, pins)], ARM_ALIGN)
    lines += ["", f"Worst {len(worst)} pins:", ""]
    lines += markdown_table(WORST_HEADER, [worst_cells(p) for p in worst], WORST_ALIGN)
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--batch", required=True, help="batch name under qa_logs/agent_freshness/")
    parser.add_argument("--refresh", action="store_true", help="re-fetch registry data instead of the batch cache")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler(sys.stdout))
    batch_dir = LOG_ROOT / args.batch
    batch_file = batch_dir / "batch.json"
    if not batch_file.is_file():
        logger.error(f"{batch_file} not found: run run.py --batch {args.batch} first")
        return 2
    if subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, check=False).returncode != 0:
        logger.error(f"docker image {IMAGE} not found: run `just exp-build`, the resolve check runs in it")
        return 2
    registry = Registry(batch_dir / "registry", refresh=args.refresh)

    rows, pins = [], []
    for meta_file in sorted(batch_dir.glob("*/meta.json")):
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        if meta.get("status") != "done":
            continue
        row, run_pins = score_run(meta_file.parent, meta, registry, args.refresh)
        rows.append(row)
        pins += run_pins
    if not rows:
        logger.error(f"no finished runs in {batch_dir}")
        return 2

    with (batch_dir / "runs.csv").open("w", encoding="utf-8", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with (batch_dir / "pins.csv").open("w", encoding="utf-8", newline="") as out:
        columns = ["run_id", "model", "arm", "task", *(field.name for field in fields(DependencyScore))]
        writer = csv.DictWriter(out, fieldnames=columns)
        writer.writeheader()
        writer.writerows({**pin, "cves": " ".join(pin["cves"])} for pin in pins)
    summary = summarize(rows, pins)
    (batch_dir / "summary.md").write_text(summary, encoding="utf-8")
    batch = json.loads(batch_file.read_text(encoding="utf-8"))
    (batch_dir / "summary.html").write_text(render_html(args.batch, batch, rows, pins), encoding="utf-8")
    logger.info(summary)
    logger.info(f"{len(rows)} runs scored; runs.csv, pins.csv, summary.md and summary.html in {batch_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
