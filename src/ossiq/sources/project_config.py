"""Find and read the project's `.ossiq.yaml`, the policy a team commits next to its manifest."""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from functools import cache
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.protocols import Validator

from ossiq.domain.exceptions import InvalidPolicyFile
from ossiq.domain.policy import Policy, PolicyException, PolicyRule
from ossiq.domain.provenance import SourceLevel, TrustTier

CONFIG_FILE_NAME = ".ossiq.yaml"
SUPPORTED_VERSION = 1
SCHEMA_FILE = "project_config_v1.schema.json"


class DateAsStringLoader(yaml.SafeLoader):
    """A SafeLoader that leaves `2027-01-31` a string, so the schema's `format: date` judges it."""


DateAsStringLoader.yaml_implicit_resolvers = {
    first: [(tag, pattern) for tag, pattern in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


@cache
def schema_validator() -> Validator:
    """The validator for the bundled schema; built once, since the schema never changes at runtime."""
    schema = json.loads(files("ossiq.data").joinpath(SCHEMA_FILE).read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def find_project_config(project_path: Path) -> Path | None:
    """Find the `.ossiq.yaml` that governs a project.

    Walks from the project up through its parents so a monorepo's root file covers its packages. The
    walk ends at the first directory that holds a `.git`, so a file outside the repository is never read.

    Args:
        project_path: The directory being scanned.

    Returns:
        The file's path, or None when there is none.
    """
    start = project_path.resolve()
    for directory in (start, *start.parents):
        candidate = directory / CONFIG_FILE_NAME
        if candidate.is_file():
            return candidate
        if (directory / ".git").exists():
            return None
    return None


def read_project_config(path: Path) -> Mapping[str, Any]:
    """Read and validate a `.ossiq.yaml`.

    Args:
        path: The file to read.

    Returns:
        The document, checked against the schema.

    Raises:
        InvalidPolicyFile: The file cannot be read, is not valid YAML, or breaks the schema.
    """
    try:
        raw = yaml.load(path.read_text(encoding="utf-8"), Loader=DateAsStringLoader)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise InvalidPolicyFile(f"{path}: {error}") from error

    if not isinstance(raw, Mapping):
        raise InvalidPolicyFile(f"{path}: expected a mapping with a `version` key at the top level.")
    if raw.get("version") != SUPPORTED_VERSION:
        raise InvalidPolicyFile(
            f"{path}: version {raw.get('version')!r} is not supported.",
            hint=f"This OSS IQ reads `version: {SUPPORTED_VERSION}`. Upgrade OSS IQ if the file is newer.",
        )

    problems = [
        f"{'.'.join(str(part) for part in error.absolute_path) or '(top level)'}: {error.message}"
        for error in sorted(schema_validator().iter_errors(raw), key=lambda e: [str(p) for p in e.absolute_path])
    ]
    if problems:
        raise InvalidPolicyFile(f"{path}:\n  " + "\n  ".join(problems))
    return raw


def load_project_policy(path: Path, today: date) -> tuple[Policy, list[str]]:
    """Read a policy file.

    Args:
        path: The `.ossiq.yaml` to read.
        today: The date an exception's `expires` is judged against.

    Returns:
        The policy, and one warning for each exception that has expired and was therefore left out.

    Raises:
        InvalidPolicyFile: The file cannot be read, is not valid YAML, or breaks the schema.
    """
    return build_policy(read_project_config(path).get("policy") or {}, today, path)


@dataclass(frozen=True)
class UpgradeConfig:
    """The project's defaults for `ossiq upgrade start`; a flag on the command line beats them."""

    limit: int | None = None
    test_command: str | None = None


def load_upgrade_config(project_path: Path) -> UpgradeConfig:
    """Read the `upgrade:` block of the project's `.ossiq.yaml`.

    Args:
        project_path: The directory being upgraded.

    Returns:
        The defaults it sets; empty when there is no file or no block.

    Raises:
        InvalidPolicyFile: The file exists but cannot be read or breaks the schema.
    """
    path = find_project_config(project_path)
    if path is None:
        return UpgradeConfig()
    block = read_project_config(path).get("upgrade") or {}
    return UpgradeConfig(limit=block.get("limit"), test_command=block.get("test-command"))


def build_policy(block: Mapping[str, Any], today: date, path: Path) -> tuple[Policy, list[str]]:
    """Turn a validated `policy:` block into a Policy.

    Args:
        block: The block, already checked against the schema.
        today: The date an exception's `expires` is judged against.
        path: The file it came from, named in the expiry warnings.

    Returns:
        The policy and its expiry warnings.
    """
    warnings: list[str] = []
    exceptions: list[PolicyException] = []
    for entry in block.get("exceptions", ()):
        expires = date.fromisoformat(entry["expires"]) if "expires" in entry else None
        if expires is not None and expires < today:
            warnings.append(
                f"Policy exception for {entry['package']} expired on {expires}, so its rules apply again. "
                f"Renew or remove it in {path.name}."
            )
            continue
        exceptions.append(
            PolicyException(
                package=entry["package"],
                reason=entry["reason"],
                versions=tuple(entry.get("versions", ())),
                rules=frozenset(PolicyRule(rule) for rule in entry.get("rules", PolicyRule)),
                expires=expires,
            )
        )

    build = block.get("build", {})
    source = block.get("source")
    cooldown = block.get("cooldown")
    policy = Policy(
        no_downgrade=build.get("no-downgrade", False),
        min_build=TrustTier(build.get("minimum", TrustTier.NONE)),
        min_source=SourceLevel(source["minimum"]) if source else None,
        cooldown_days=cooldown["days"] if cooldown else None,
        exceptions=tuple(exceptions),
    )
    return policy, warnings
