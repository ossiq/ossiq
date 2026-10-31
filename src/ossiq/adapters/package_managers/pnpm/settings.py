"""
pnpm's `minimumReleaseAge` family of settings, read the way pnpm reads them, as a ReleaseCutoff.

pnpm refuses to install a release younger than `minimumReleaseAge` minutes, so a target OSS IQ
picks past that age fails `apply` the same way a release past uv's `exclude-newer` does. The same
settings, written rather than read, are how `apply` holds new packages to OSS IQ's own cooldown.
"""

import json
import logging
import sys
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from ossiq.adapters.package_managers.pnpm.constants import WORKSPACE_FILE
from ossiq.domain.common import normalize_dist_name
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.release_cutoff import ReleaseCutoff
from ossiq.tree.builder import NodeKey

logger = logging.getLogger(__name__)

MINIMUM_RELEASE_AGE_SOURCE = "pnpm minimumReleaseAge"

MINUTES_PER_DAY = 1440

# pnpm 11's built-in age when none is set. It is non-strict: pnpm falls back instead of failing.
IMPLICIT_MINIMUM_RELEASE_AGE = MINUTES_PER_DAY

GLOBAL_CONFIG_FILE = "config.yaml"

# Setting -> env var suffix.
ENV_SUFFIXES = {
    "minimumReleaseAge": "minimum_release_age",
    "minimumReleaseAgeStrict": "minimum_release_age_strict",
    "minimumReleaseAgeExclude": "minimum_release_age_exclude",
}

# pnpm 11+ reads the first pair and ignores `npm_config_*`; pnpm 10 reads only the second pair.
# Reading both can only add a cutoff pnpm does not apply, which holds a release back, never lets one through.
ENV_PREFIXES = ("pnpm_config_", "PNPM_CONFIG_", "npm_config_", "NPM_CONFIG_")

# The exclude list is the opposite: pnpm 10 takes it from the environment as a plain string and
# ignores it, so reading `npm_config_*` would let through a release that pnpm 10 still refuses.
EXCLUDE_ENV_PREFIXES = ENV_PREFIXES[:2]


def read_yaml_settings(path: Path) -> dict[str, Any]:
    """Read one YAML settings file pnpm would read, failing the way pnpm does on a malformed one.

    Args:
        path: The file; one that does not exist reads as empty.

    Returns:
        The top-level mapping, or an empty one when the file is absent or holds no mapping.

    Raises:
        PackageManagerLockfileParsingError: The file exists but cannot be read or parsed.
    """
    if not path.is_file():
        return {}
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PackageManagerLockfileParsingError(f"Failed to read pnpm settings from {path}") from exc
    return document if isinstance(document, dict) else {}


def global_config_path(environ: Mapping[str, str], platform: str = sys.platform) -> Path:
    """Return where pnpm 11 and later look for the global `config.yaml`."""
    if xdg := environ.get("XDG_CONFIG_HOME"):
        return Path(xdg) / "pnpm" / GLOBAL_CONFIG_FILE
    if platform == "darwin":
        return Path.home() / "Library" / "Preferences" / "pnpm" / GLOBAL_CONFIG_FILE
    if platform == "win32":
        local = environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local"
        return Path(local) / "pnpm" / "config" / GLOBAL_CONFIG_FILE
    return Path.home() / ".config" / "pnpm" / GLOBAL_CONFIG_FILE


def env_names(setting: str, prefixes: Sequence[str] = ENV_PREFIXES) -> list[str]:
    """Return every environment variable name pnpm may read *setting* from."""
    suffix = ENV_SUFFIXES[setting]
    return [prefix + (suffix.upper() if prefix.isupper() else suffix) for prefix in prefixes]


def env_settings(environ: Mapping[str, str]) -> dict[str, Any]:
    """Return the cutoff settings the environment carries, under their `camelCase` setting names.

    The exclude list is a JSON array; one that is not valid JSON is skipped, as pnpm would not apply it.
    """
    found: dict[str, Any] = {}
    for setting in ENV_SUFFIXES:
        prefixes = EXCLUDE_ENV_PREFIXES if setting == "minimumReleaseAgeExclude" else ENV_PREFIXES
        value = next((environ[name] for name in env_names(setting, prefixes) if environ.get(name)), None)
        if value is None:
            continue
        if setting == "minimumReleaseAgeExclude":
            try:
                value = json.loads(value)
            except ValueError:
                logger.debug("Ignoring pnpm %s value %r: not a JSON array", setting, value)
                continue
        found[setting] = value
    return found


def pnpm_settings_layers(project_path: Path, environ: Mapping[str, str]) -> list[dict[str, Any]]:
    """Return the settings pnpm reads for this project, highest precedence first.

    shortcut: pnpm 10's `.npmrc` and global `rc`, and a workspace file above `project_path`, are not
    read; add them if users hit a refused apply.
    """
    return [
        env_settings(environ),
        read_yaml_settings(project_path / WORKSPACE_FILE),
        read_yaml_settings(global_config_path(environ)),
    ]


def effective_setting(layers: Sequence[Mapping[str, Any]], key: str) -> Any:
    """Return *key* from the highest-precedence layer that sets it, or None."""
    return next((layer[key] for layer in layers if key in layer), None)


def release_cutoff_from_pnpm_settings(layers: Sequence[Mapping[str, Any]], *, now: datetime) -> ReleaseCutoff | None:
    """Build the cutoff `pnpm install` will enforce from the project's settings layers.

    A cutoff exists only where pnpm refuses: an age above zero that is strict. An explicit age is
    strict unless `minimumReleaseAgeStrict` says otherwise, while pnpm 11's built-in 1440 is not,
    and pnpm falls back there instead of failing.

    Args:
        layers: Settings mappings, highest precedence first (see `pnpm_settings_layers`).
        now: The instant the age counts back from.

    Returns:
        The cutoff, or None when pnpm applies none.
    """
    raw_age = effective_setting(layers, "minimumReleaseAge")
    raw_strict = effective_setting(layers, "minimumReleaseAgeStrict")
    strict = raw_age is not None if raw_strict is None else str(raw_strict).strip().lower() == "true"
    if not strict:
        return None
    try:
        minutes = IMPLICIT_MINIMUM_RELEASE_AGE if raw_age is None else int(raw_age)
    except (TypeError, ValueError):
        logger.debug("Ignoring pnpm minimumReleaseAge value %r: not a number of minutes", raw_age)
        return None
    if minutes <= 0:
        return None

    exclude = effective_setting(layers, "minimumReleaseAgeExclude")
    per_package: dict[str, datetime | None] = {}
    for entry in exclude if isinstance(exclude, list) else []:
        entry = str(entry).strip()
        # shortcut: versioned entries (`nx@21.6.5`) are ignored, so OSS IQ holds a version pnpm would
        # allow; extend ReleaseCutoff with exempt versions if users hit it.
        if "@" in entry[1:]:
            continue
        # Globs stay raw: normalize_dist_name("react-*") would cut it to "react".
        per_package[entry.lower() if "*" in entry else normalize_dist_name(entry)] = None
    return ReleaseCutoff(MINIMUM_RELEASE_AGE_SOURCE, default=now - timedelta(minutes=minutes), per_package=per_package)


@dataclass(frozen=True)
class InstallCooldown:
    """What a `pnpm install` run needs to hold new packages to OSS IQ's cooldown.

    Attributes:
        environ: The environment to run pnpm in; None to inherit this process's.
        exclusions: `name@version` entries that `pnpm-workspace.yaml` must carry. pnpm 10 reads its
            exclude list nowhere else, and pnpm 11 and later fail a later plain `pnpm install` on a
            locked release younger than the project's own age unless the file exempts it.
    """

    environ: dict[str, str] | None
    exclusions: list[str]


def install_cooldown(
    environ: Mapping[str, str],
    layers: Sequence[Mapping[str, Any]],
    *,
    days: int,
    published: Mapping[NodeKey, datetime],
    picks: Collection[NodeKey],
    forced: Collection[NodeKey] = (),
    now: datetime,
) -> InstallCooldown | None:
    """Plan how `pnpm install` holds new packages to a cooldown without refusing what OSS IQ settled.

    The age is the larger of the project's own and `days`. The run is non-strict unless the project
    itself is strict, so the cooldown never adds a refusal to a project that had none (pnpm 10 has
    no such switch and always refuses).

    Every release in `picks` is exempt from the age, and so is every locked release younger than it,
    since pnpm 11 and later re-check the lockfile on each run. A strict project's own rule still
    applies to them: OSS IQ lifts only the age it added. An `--override` version in `forced` is the
    exception, exempt even from the project's rule.

    The environment carries the exemptions for this run. The ones a later plain `pnpm install` needs
    too come back as `exclusions`: picks younger than the age, `forced` versions the project's rule
    refuses, and, when the project is not strict, locked releases younger than its own age.

    Args:
        environ: The environment this process would hand to pnpm.
        layers: Settings layers, highest precedence first (see `pnpm_settings_layers`).
        days: OSS IQ's cooldown period. Zero or less means no cooldown, and only `forced` versions
            are then exempted.
        published: Publish time of each locked release and each pick. A release missing here is
            never treated as young.
        picks: The releases the plan installs.
        forced: The `--override` versions among them.
        now: The instant ages count back from.

    Returns:
        The environment and the exclusions to persist, or None when the run needs neither.
    """
    cutoff = release_cutoff_from_pnpm_settings(layers, now=now)
    overridden = {
        key for key in forced if key in published and cutoff is not None and not cutoff.admits(key[0], published[key])
    }
    if days <= 0:
        return InstallCooldown(None, [f"{n}@{v}" for n, v in sorted(overridden)]) if overridden else None
    try:
        project_minutes = max(int(effective_setting(layers, "minimumReleaseAge") or 0), 0)
    except (TypeError, ValueError):
        project_minutes = 0
    minutes = max(project_minutes, days * MINUTES_PER_DAY)
    admitted = {key: at for key, at in published.items() if cutoff is None or cutoff.admits(key[0], at)}

    def younger_than(age: int) -> set[NodeKey]:
        return {key for key, at in admitted.items() if at > now - timedelta(minutes=age)}

    held = younger_than(minutes) | overridden
    # A strict project's own rule refuses what it does not admit, so it needs no entry of ours.
    own = set() if cutoff is not None else younger_than(project_minutes or IMPLICIT_MINIMUM_RELEASE_AGE)
    exclusions = [f"{name}@{version}" for name, version in sorted((held & set(picks)) | own)]

    existing = effective_setting(layers, "minimumReleaseAgeExclude")
    kept = [str(entry) for entry in existing] if isinstance(existing, list) else []
    exclude = dict.fromkeys([*kept, *(f"{name}@{version}" for name, version in sorted(held))])

    # Our values replace the inherited ones, whatever the spelling. An inherited strict flag survives
    # when the project is strict, because it is not ours to set.
    replaced = {*env_names("minimumReleaseAge"), *env_names("minimumReleaseAgeExclude")}
    if cutoff is None:
        replaced.update(env_names("minimumReleaseAgeStrict"))
    child = {name: value for name, value in environ.items() if name not in replaced}
    for prefix in ("pnpm_config_", "npm_config_"):
        child[prefix + ENV_SUFFIXES["minimumReleaseAge"]] = str(minutes)
        if cutoff is None:
            child[prefix + ENV_SUFFIXES["minimumReleaseAgeStrict"]] = "false"
    if exclude:
        child["pnpm_config_" + ENV_SUFFIXES["minimumReleaseAgeExclude"]] = json.dumps(list(exclude))
    return InstallCooldown(environ=child, exclusions=exclusions)
