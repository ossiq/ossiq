"""
pnpm's `minimumReleaseAge` family of settings, read the way pnpm reads them, as a ReleaseCutoff.

pnpm refuses to install a release younger than `minimumReleaseAge` minutes, so a target OSS IQ
picks past that age fails `apply` the same way a release past uv's `exclude-newer` does.
"""

import logging
import sys
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from ossiq.adapters.package_managers.pnpm.constants import WORKSPACE_FILE
from ossiq.domain.common import normalize_dist_name
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.release_cutoff import ReleaseCutoff

logger = logging.getLogger(__name__)

MINIMUM_RELEASE_AGE_SOURCE = "pnpm minimumReleaseAge"

# pnpm 11's built-in age when none is set. It is non-strict: pnpm falls back instead of failing.
IMPLICIT_MINIMUM_RELEASE_AGE = 1440

GLOBAL_CONFIG_FILE = "config.yaml"

# Setting -> env var suffix. The exclude list is not read from the environment (see layers).
ENV_SUFFIXES = {
    "minimumReleaseAge": "minimum_release_age",
    "minimumReleaseAgeStrict": "minimum_release_age_strict",
}

# pnpm 11+ reads the first pair and ignores `npm_config_*`; pnpm 10 reads only the second pair.
# Reading both can only add a cutoff pnpm does not apply, which holds a release back, never lets one through.
ENV_PREFIXES = ("pnpm_config_", "PNPM_CONFIG_", "npm_config_", "NPM_CONFIG_")


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


def env_settings(environ: Mapping[str, str]) -> dict[str, str]:
    """Return the cutoff settings the environment carries, under their `camelCase` setting names."""
    found: dict[str, str] = {}
    for setting, suffix in ENV_SUFFIXES.items():
        names = [prefix + (suffix.upper() if prefix.isupper() else suffix) for prefix in ENV_PREFIXES]
        value = next((environ[name] for name in names if environ.get(name)), None)
        if value is not None:
            found[setting] = value
    return found


def pnpm_settings_layers(project_path: Path, environ: Mapping[str, str]) -> list[dict[str, Any]]:
    """Return the settings pnpm reads for this project, highest precedence first.

    shortcut: pnpm 10's `.npmrc` and global `rc`, `minimumReleaseAgeExclude` from the environment,
    and a workspace file above `project_path` are not read; add them if users hit a refused apply.
    """
    return [
        env_settings(environ),
        read_yaml_settings(project_path / WORKSPACE_FILE),
        read_yaml_settings(global_config_path(environ)),
    ]


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

    def setting(key: str) -> Any:
        return next((layer[key] for layer in layers if key in layer), None)

    raw_age = setting("minimumReleaseAge")
    raw_strict = setting("minimumReleaseAgeStrict")
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

    exclude = setting("minimumReleaseAgeExclude")
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
