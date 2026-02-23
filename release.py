#!/usr/bin/env python3
"""
Release automation script for ossiq-cli.

Usage:
    uv run python release.py --patch [--dry-run]
    uv run python release.py --minor [--dry-run]
    uv run python release.py --major [--dry-run]
    uv run python release.py --override-version=X.Y.Z [--dry-run]
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import requests
import semver
import typer
from jinja2 import BaseLoader, Environment
from requests.adapters import HTTPAdapter
from rich.console import Console
from urllib3.util.retry import Retry

# ============================================================================
# Enums and Data Classes
# ============================================================================


class BumpType(StrEnum):
    """Version bump type enumeration."""

    MAJOR = "major"
    MINOR = "minor"
    PATCH = "patch"


class CommitType(StrEnum):
    """Conventional commit types."""

    FEAT = "feat"
    FIX = "fix"
    DOCS = "docs"
    STYLE = "style"
    REFACTOR = "refactor"
    PERF = "perf"
    TEST = "test"
    BUILD = "build"
    CI = "ci"
    CHORE = "chore"
    REVERT = "revert"


@dataclass(frozen=True)
class CommitInfo:
    """Parsed commit information."""

    sha: str
    sha_short: str
    commit_type: CommitType | None
    scope: str | None
    is_breaking: bool
    description: str
    body: str
    author_name: str
    author_email: str
    date: datetime
    github_issues: list[str]  # GH-* references extracted from body


@dataclass(frozen=True)
class ReleaseConfig:
    """Release configuration."""

    dry_run: bool
    bump_type: BumpType | None
    override_version: str | None
    project_root: Path
    github_repo_url: str | None = None  # Read from pyproject.toml if not provided
    github_api_url: str | None = None  # Derived from github_repo_url


# ============================================================================
# Version Service
# ============================================================================


class VersionService:
    """Service for version-related operations."""

    PYPROJECT_VERSION_PATTERN = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)
    PYPROJECT_REPO_PATTERN = re.compile(r'^repository\s*=\s*"([^"]+)"', re.MULTILINE)

    @staticmethod
    def read_current_version(project_root: Path) -> str:
        """Read current version from pyproject.toml."""
        pyproject_path = project_root / "pyproject.toml"
        if not pyproject_path.exists():
            raise FileNotFoundError(f"pyproject.toml not found at {pyproject_path}")

        content = pyproject_path.read_text()
        match = VersionService.PYPROJECT_VERSION_PATTERN.search(content)
        if not match:
            raise ValueError("Could not find version in pyproject.toml")

        return match.group(1)

    @staticmethod
    def read_repository_url(project_root: Path) -> str:
        """Read repository URL from pyproject.toml [project.urls] section."""
        pyproject_path = project_root / "pyproject.toml"
        if not pyproject_path.exists():
            raise FileNotFoundError(f"pyproject.toml not found at {pyproject_path}")

        content = pyproject_path.read_text()
        match = VersionService.PYPROJECT_REPO_PATTERN.search(content)
        if not match:
            raise ValueError("Could not find repository URL in pyproject.toml [project.urls]")

        repo_url = match.group(1)
        # Remove .git suffix if present for cleaner URLs
        if repo_url.endswith(".git"):
            repo_url = repo_url[:-4]
        return repo_url

    @staticmethod
    def calculate_new_version(
        current_version: str,
        bump_type: BumpType | None,
        override_version: str | None,
    ) -> str:
        """Calculate new version based on bump type or override."""
        if override_version:
            try:
                semver.Version.parse(override_version)
            except (ValueError, TypeError) as e:
                raise ValueError(f"Invalid version format: {override_version}") from e
            return override_version

        if not bump_type:
            raise ValueError("Must specify --major, --minor, --patch, or --override-version")

        version = semver.Version.parse(current_version)

        match bump_type:
            case BumpType.MAJOR:
                return str(version.bump_major())
            case BumpType.MINOR:
                return str(version.bump_minor())
            case BumpType.PATCH:
                return str(version.bump_patch())

        raise ValueError(f"Unknown bump type: {bump_type}")

    @staticmethod
    def update_pyproject_version(project_root: Path, new_version: str, dry_run: bool) -> None:
        """Update version in pyproject.toml."""
        if dry_run:
            return

        pyproject_path = project_root / "pyproject.toml"
        content = pyproject_path.read_text()

        new_content = VersionService.PYPROJECT_VERSION_PATTERN.sub(f'version = "{new_version}"', content)

        pyproject_path.write_text(new_content)

        subprocess.run(
            ["uv", "sync"],
            check=True,
            shell=False,
        )


# ============================================================================
# Git Service
# ============================================================================


class GitService:
    """Service for git operations."""

    COMMIT_PATTERN = re.compile(
        r"^(?P<type>feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)"
        r"(?:\((?P<scope>[a-zA-Z0-9_/-]+)\))?"
        r"(?P<breaking>!)?"
        r":\s*(?P<description>.+)$"
    )

    FIELD_SEPARATOR = "<<<FIELD>>>"
    COMMIT_SEPARATOR = "<<<COMMIT>>>"

    @staticmethod
    def get_latest_tag() -> str | None:
        """Find latest git tag with 'v' prefix."""
        result = subprocess.run(
            ["git", "tag", "-l", "v*", "--sort=-v:refname"],
            capture_output=True,
            text=True,
            check=True,
            shell=False,
        )
        tags = result.stdout.strip().split("\n")
        return tags[0] if tags and tags[0] else None

    @staticmethod
    def get_commits_since_tag(tag: str | None) -> list[CommitInfo]:
        """Get all commits between tag and HEAD."""
        sep = GitService.FIELD_SEPARATOR
        end = GitService.COMMIT_SEPARATOR
        format_str = f"%H{sep}%s{sep}%b{sep}%an{sep}%ae{sep}%aI{end}"

        if tag:
            commit_range = f"{tag}..HEAD"
        else:
            commit_range = "HEAD"

        result = subprocess.run(
            ["git", "log", commit_range, f"--format={format_str}", "--no-merges"],
            capture_output=True,
            text=True,
            check=True,
            shell=False,
        )

        commits = []
        raw_commits = result.stdout.strip()
        if not raw_commits:
            return commits

        for raw in raw_commits.split(GitService.COMMIT_SEPARATOR):
            raw = raw.strip()
            if raw and GitService.FIELD_SEPARATOR in raw:
                commit = GitService.parse_commit_message(raw)
                commits.append(commit)

        return commits

    @staticmethod
    def parse_commit_message(raw_commit: str) -> CommitInfo:
        """Parse raw git log output into CommitInfo."""
        parts = raw_commit.split(GitService.FIELD_SEPARATOR, 5)
        if len(parts) < 6:
            parts.extend([""] * (6 - len(parts)))

        sha, subject, body, author_name, author_email, date_str = parts

        match = GitService.COMMIT_PATTERN.match(subject)
        if match:
            commit_type = CommitType(match.group("type"))
            scope = match.group("scope")
            is_breaking = bool(match.group("breaking"))
            description = match.group("description")
        else:
            commit_type = None
            scope = None
            is_breaking = False
            description = subject

        try:
            date = datetime.fromisoformat(date_str.strip()) if date_str.strip() else datetime.now()
        except ValueError:
            date = datetime.now()

        # Extract GH-* references and clean up body
        body_lines = body.split("\n")
        github_issues: list[str] = []
        cleaned_lines: list[str] = []

        gh_pattern = re.compile(r"^(GH-\d+)$")
        for line in body_lines:
            # Additional Space for better release notes formatting
            if line.strip() == "**":
                cleaned_lines.append("")
                continue

            if not line.strip():
                continue

            # Skip Signed-off-by lines
            if line.startswith("Signed-off-by:"):
                continue
            # Extract GH-* references
            gh_match = gh_pattern.match(line.strip())
            if gh_match:
                github_issues.append(gh_match.group(1))
            else:
                cleaned_lines.append(line)

        body_cleaned = "\n".join(cleaned_lines)

        return CommitInfo(
            sha=sha,
            sha_short=sha[:7],
            commit_type=commit_type,
            scope=scope,
            is_breaking=is_breaking,
            description=description,
            body=body_cleaned,
            author_name=author_name,
            author_email=author_email,
            date=date,
            github_issues=github_issues,
        )

    @staticmethod
    def create_release_commit(version: str, files: list[str], dry_run: bool) -> None:
        """Create release commit with conventional format."""
        if dry_run:
            return

        message = f"chore(release): {version}"

        subprocess.run(["git", "add"] + files, check=True, shell=False)
        subprocess.run(
            ["git", "commit", "-s", "-m", message],
            check=True,
            shell=False,
        )

    @staticmethod
    def create_tag(version: str, dry_run: bool) -> None:
        """Create git tag."""
        if dry_run:
            return

        tag_name = f"v{version}"
        subprocess.run(
            ["git", "tag", "-a", tag_name, "-m", f"Release {tag_name}"],
            check=True,
            shell=False,
        )

    @staticmethod
    def push_tag(version: str, dry_run: bool) -> None:
        """Create git tag."""
        if dry_run:
            return

        tag_name = f"v{version}"
        subprocess.run(
            ["git", "push", "origin", tag_name],
            check=True,
            shell=False,
        )


# ============================================================================
# Changelog Service
# ============================================================================


class ChangelogService:
    """Service for changelog generation."""

    TEMPLATE = (
        "## v{{ version }} ({{ date }})\n"
        "{% for type_name, type_commits in grouped_commits.items() %}"
        "{% if type_commits %}\n"
        "\n"
        "### {{ type_name }}\n"
        "{% for commit in type_commits %}\n"
        "* {{ commit.commit_type.value if commit.commit_type else 'unknown' }}"
        "{% if commit.scope %}({{ commit.scope }}){% endif %}"
        "{% if commit.is_breaking %}!{% endif %}: {{ commit.description }}"
        "{% if commit.github_issues %} ({{ commit.github_issues | join(', ') }}){% endif %} "
        "([`{{ commit.sha_short }}`]({{ github_repo_url }}/commit/{{ commit.sha }}))\n"
        "{% if commit.body %}{{ commit.body }}\n{% endif %}"
        "{% endfor %}"
        "{% endif %}"
        "{% endfor %}"
    )

    TYPE_DISPLAY_NAMES: dict[CommitType | None, str] = {
        CommitType.FEAT: "Feature",
        CommitType.FIX: "Fix",
        CommitType.DOCS: "Documentation",
        CommitType.STYLE: "Style",
        CommitType.REFACTOR: "Refactor",
        CommitType.PERF: "Performance",
        CommitType.TEST: "Test",
        CommitType.BUILD: "Build",
        CommitType.CI: "CI",
        CommitType.CHORE: "Chore",
        CommitType.REVERT: "Revert",
        None: "Unknown",
    }

    TYPE_PRIORITY = [
        "Feature",
        "Fix",
        "Performance",
        "Refactor",
        "Documentation",
        "Style",
        "Test",
        "Build",
        "CI",
        "Chore",
        "Revert",
        "Unknown",
    ]

    def __init__(self) -> None:
        # autoescape=False is intentional: output is markdown for CHANGELOG.md, not HTML
        self.template_env = Environment(loader=BaseLoader(), autoescape=False)
        self.template = self.template_env.from_string(self.TEMPLATE)

    def generate_changelog_entry(
        self,
        version: str,
        commits: list[CommitInfo],
        github_repo_url: str,
    ) -> str:
        """Generate changelog entry for new version."""
        grouped = self.group_commits_by_type(commits)

        return self.template.render(
            version=version,
            date=datetime.now().strftime("%Y-%m-%d"),
            grouped_commits=grouped,
            github_repo_url=github_repo_url,
        )

    def update_changelog_file(
        self,
        project_root: Path,
        changelog_entry: str,
        dry_run: bool,
    ) -> None:
        """Insert new changelog entry at top of CHANGELOG.md."""
        if dry_run:
            return

        changelog_path = project_root / "CHANGELOG.md"

        if changelog_path.exists():
            content = changelog_path.read_text()
            header_pattern = re.compile(r"^(# CHANGELOG\n+)", re.MULTILINE)
            match = header_pattern.search(content)
            if match:
                insert_pos = match.end()
                new_content = content[:insert_pos] + changelog_entry + "\n" + content[insert_pos:]
            else:
                new_content = "# CHANGELOG\n\n" + changelog_entry + "\n" + content
        else:
            new_content = "# CHANGELOG\n\n" + changelog_entry

        changelog_path.write_text(new_content)

    def group_commits_by_type(self, commits: list[CommitInfo]) -> dict[str, list[CommitInfo]]:
        """Group commits by their conventional commit type."""
        groups: dict[str, list[CommitInfo]] = {}

        for commit in commits:
            display_name = self.TYPE_DISPLAY_NAMES.get(commit.commit_type, "Unknown")
            if display_name not in groups:
                groups[display_name] = []
            groups[display_name].append(commit)

        ordered: dict[str, list[CommitInfo]] = {}
        for key in self.TYPE_PRIORITY:
            if key in groups:
                ordered[key] = groups[key]

        return ordered


# ============================================================================
# GitHub Service
# ============================================================================


class GitHubService:
    """Service for GitHub API operations."""

    def __init__(self, api_url: str, github_token: str | None = None) -> None:
        self.token = github_token or os.environ.get("OSSIQ_GITHUB_TOKEN")
        self.api_url = api_url
        self.session = self._create_session()

    @staticmethod
    def _create_session() -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[502, 503, 504],
        )
        session.mount("https://", HTTPAdapter(max_retries=retries))
        return session

    @staticmethod
    def derive_api_url(repo_url: str) -> str:
        """Derive GitHub API URL from repository URL.

        Example: https://github.com/ossiq/ossiq -> https://api.github.com/repos/ossiq/ossiq
        """
        if repo_url.startswith("https://github.com/"):
            repo_path = repo_url.replace("https://github.com/", "")
            return f"https://api.github.com/repos/{repo_path}"
        raise ValueError(f"Unsupported repository URL format: {repo_url}")

    def create_release(
        self,
        tag_name: str,
        release_notes: str,
        dry_run: bool,
    ) -> str | None:
        """Create GitHub release via API. Returns release URL."""
        if dry_run:
            return None

        if not self.token:
            raise ValueError("OSSIQ_GITHUB_TOKEN environment variable is required for GitHub release")

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        payload = {
            "tag_name": tag_name,
            "name": f"Release {tag_name}",
            "body": release_notes,
            "draft": False,
            "prerelease": False,
        }

        response = self.session.post(
            f"{self.api_url}/releases",
            headers=headers,
            json=payload,
            timeout=30,
        )

        if response.status_code == 201:
            return response.json().get("html_url")
        else:
            # Avoid logging response.text as it may contain sensitive information
            raise RuntimeError(f"Failed to create GitHub release: HTTP {response.status_code}")


# ============================================================================
# Release Orchestrator
# ============================================================================


class ReleaseOrchestrator:
    """Orchestrates the entire release process."""

    def __init__(
        self,
        config: ReleaseConfig,
        console: Console,
    ) -> None:
        self.config = config
        self.console = console
        self.version_svc = VersionService()
        self.git_svc = GitService()
        self.changelog_svc = ChangelogService()
        self.github_repo_url: str | None = None
        self.github_api_url: str | None = None
        self.github_svc: GitHubService | None = None

    def execute(self) -> int:
        """Execute the full release workflow. Returns exit code."""
        try:
            self.console.print("[bold blue]Step 1:[/] Reading current version and repository info...")
            current_version = self.version_svc.read_current_version(self.config.project_root)
            self.console.print(f"  Current version: [green]{current_version}[/]")

            # Read repository URL from pyproject.toml or use config override
            self.github_repo_url = self.config.github_repo_url or self.version_svc.read_repository_url(
                self.config.project_root
            )
            self.github_api_url = self.config.github_api_url or GitHubService.derive_api_url(self.github_repo_url)
            self.console.print(f"  Repository: [green]{self.github_repo_url}[/]")

            # Initialize GitHub service with derived API URL
            self.github_svc = GitHubService(api_url=self.github_api_url)

            self.console.print("[bold blue]Step 2:[/] Calculating new version...")
            new_version = self.version_svc.calculate_new_version(
                current_version,
                self.config.bump_type,
                self.config.override_version,
            )
            self.console.print(f"  New version: [green]{new_version}[/]")

            self.console.print("[bold blue]Step 3:[/] Finding latest git tag...")
            latest_tag = self.git_svc.get_latest_tag()
            self.console.print(f"  Latest tag: [green]{latest_tag or 'None'}[/]")

            self.console.print("[bold blue]Step 4:[/] Getting commits since last tag...")
            commits = self.git_svc.get_commits_since_tag(latest_tag)
            self.console.print(f"  Found [green]{len(commits)}[/] commits")

            if not commits:
                self.console.print("[yellow]Warning: No commits found since last tag![/]")

            self.console.print("[bold blue]Step 5:[/] Generating changelog entry...")
            changelog_entry = self.changelog_svc.generate_changelog_entry(
                new_version,
                commits,
                self.github_repo_url,
            )

            if self.config.dry_run:
                self._print_dry_run_output(current_version, new_version, changelog_entry)
            else:
                self._execute_release(new_version, changelog_entry)

            return 0

        except (FileNotFoundError, ValueError, subprocess.CalledProcessError, RuntimeError) as e:
            self.console.print(f"[bold red]Error:[/] {e}")
            return 1
        except requests.RequestException as e:
            self.console.print(f"[bold red]Network error:[/] {e}")
            return 1

    def _print_dry_run_output(
        self,
        current_version: str,
        new_version: str,
        changelog_entry: str,
    ) -> None:
        """Print dry-run output showing what would happen."""
        self.console.print("\n[bold yellow]DRY RUN - No changes will be made[/]\n")

        self.console.print("[bold]Changelog entry that would be added:[/]")
        self.console.print("-" * 60)
        self.console.print(changelog_entry)
        self.console.print("-" * 60)

        self.console.print("\n[bold]Commands that would be executed:[/]")
        self.console.print(
            f'  1. Update pyproject.toml: version = "{current_version}" -> "{new_version}" and execute `uv sync`'
        )
        self.console.print("  2. Update CHANGELOG.md with new entry")
        self.console.print("  3. git add pyproject.toml CHANGELOG.md")
        self.console.print(f'  4. git commit -s -m "chore(release): {new_version}"')
        self.console.print(f'  5. git tag -a v{new_version} -m "Release v{new_version}"')
        self.console.print(f"  6. git push origin v{new_version} ")
        self.console.print(f"  7. POST {self.github_api_url}/releases")
        self.console.print(f"     - tag_name: v{new_version}")
        self.console.print(f"     - name: Release v{new_version}")

    def _execute_release(self, new_version: str, changelog_entry: str) -> None:
        """Execute the actual release."""
        self.console.print("[bold blue]Step 6:[/] Updating pyproject.toml...")
        self.version_svc.update_pyproject_version(self.config.project_root, new_version, dry_run=False)

        self.console.print("[bold blue]Step 7:[/] Updating CHANGELOG.md...")
        self.changelog_svc.update_changelog_file(self.config.project_root, changelog_entry, dry_run=False)

        self.console.print("[bold blue]Step 8:[/] Creating release commit...")
        self.git_svc.create_release_commit(new_version, ["uv.lock", "pyproject.toml", "CHANGELOG.md"], dry_run=False)

        self.console.print("[bold blue]Step 9:[/] Creating git tag...")
        self.git_svc.create_tag(new_version, dry_run=False)
        self.console.print("[bold blue]Step 10:[/] Pushing git tag...")
        self.git_svc.push_tag(new_version, dry_run=False)

        self.console.print("[bold blue]Step 11:[/] Creating GitHub release...")
        assert self.github_svc is not None, "GitHub service not initialized"
        release_url = self.github_svc.create_release(
            f"v{new_version}",
            changelog_entry,
            dry_run=False,
        )

        self.console.print(f"\n[bold green]Release v{new_version} created successfully![/]")
        if release_url:
            self.console.print(f"  GitHub release: {release_url}")
        self.console.print("\n[bold yellow]Don't forget to push & backmerge:[/]")
        self.console.print("  git push origin production")
        self.console.print("  git checkout main && git merge production")


# ============================================================================
# CLI Entry Point
# ============================================================================

app = typer.Typer(help="Release automation for ossiq-cli")
console = Console()


@app.command()
def release(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", "-n", help="Print what would happen without executing"),
    ] = False,
    major: Annotated[
        bool,
        typer.Option("--major", help="Bump major version (X.0.0)"),
    ] = False,
    minor: Annotated[
        bool,
        typer.Option("--minor", help="Bump minor version (0.X.0)"),
    ] = False,
    patch: Annotated[
        bool,
        typer.Option("--patch", help="Bump patch version (0.0.X)"),
    ] = False,
    override_version: Annotated[
        str | None,
        typer.Option("--override-version", help="Override version directly (X.Y.Z format)"),
    ] = None,
) -> None:
    """
    Create a new release for ossiq-cli.

    Requires exactly one of: --major, --minor, --patch, or --override-version
    """
    bump_count = sum([major, minor, patch])

    if not dry_run and not override_version and not os.environ.get("OSSIQ_GITHUB_TOKEN"):
        console.print("[red]Error: OSSIQ_GITHUB_TOKEN environment variable is required for actual releases.[/]")
        console.print("[red]       Please set it or use --dry-run.[/]")
        raise typer.Exit(1)

    if override_version and bump_count > 0:
        console.print("[red]Error: Cannot use --override-version with --major/--minor/--patch[/]")
        raise typer.Exit(1)

    if not override_version and bump_count != 1:
        console.print("[red]Error: Must specify exactly one of: --major, --minor, --patch, or --override-version[/]")
        raise typer.Exit(1)

    bump_type = None
    if major:
        bump_type = BumpType.MAJOR
    elif minor:
        bump_type = BumpType.MINOR
    elif patch:
        bump_type = BumpType.PATCH

    config = ReleaseConfig(
        dry_run=dry_run,
        bump_type=bump_type,
        override_version=override_version,
        project_root=Path.cwd(),
    )

    orchestrator = ReleaseOrchestrator(config, console)
    exit_code = orchestrator.execute()
    raise typer.Exit(exit_code)


if __name__ == "__main__":
    app()
