"""Runtime version pins a project declares for its own tooling (`.nvmrc`, `.python-version`, ...).

These say which runtime the project's developers run, as opposed to `engines`/`requires-python`,
which say the oldest one it promises to support. OSS IQ never takes its runtime from a pin; it
cross-checks the provided or probed runtime against one, so a version read from the wrong shell is
caught rather than trusted.
"""

import json
import logging
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from ossiq.domain.common import ENGINE_CONTEXT_KEY_BY_REGISTRY, ProjectPackagesRegistry

logger = logging.getLogger(__name__)

# A pin is only comparable when it names concrete version components; `lts/*`, `system`, `node`
# or `latest` say nothing a version can be checked against.
CONCRETE_VERSION = re.compile(r"^v?(\d+(?:\.\d+){0,2})")

# `.tool-versions` / mise name the same runtimes differently.
TOOL_NAMES: dict[str, tuple[str, ...]] = {"node": ("nodejs", "node"), "python": ("python",)}


@dataclass(frozen=True)
class RuntimePin:
    """One concrete runtime version the project pins, and the file that pins it."""

    engine: str
    version: str
    pin_file: str


def concrete_version(raw: str) -> str | None:
    """Return the leading numeric version of *raw*, or None for an alias like `lts/*`."""
    match = CONCRETE_VERSION.match(raw.strip())
    return match.group(1) if match else None


def first_line(path: Path) -> str | None:
    """Return the first non-empty, non-comment line of *path*, or None when there is none."""
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.split("#", 1)[0].strip()
        if stripped:
            return stripped
    return None


def pin_from_version_file(path: Path, engine: str) -> str | None:
    """Read a single-engine version file (`.nvmrc`, `.node-version`, `.python-version`)."""
    return first_line(path)


def pin_from_tool_versions(path: Path, engine: str) -> str | None:
    """Read an asdf `.tool-versions` entry; the first listed version is the active one."""
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2 and parts[0] in TOOL_NAMES[engine]:
            return parts[1]
    return None


def pin_from_mise(path: Path, engine: str) -> str | None:
    """Read `[tools] node = "20"` (or a list, first entry active) from a `mise.toml`."""
    tools = tomllib.loads(path.read_text(encoding="utf-8")).get("tools", {})
    for name in TOOL_NAMES[engine]:
        value = tools.get(name)
        if isinstance(value, list) and value:
            value = value[0]
        if isinstance(value, str):
            return value
    return None


def pin_from_volta(path: Path, engine: str) -> str | None:
    """Read `package.json`'s `volta.node`."""
    if engine != "node":
        return None
    volta = json.loads(path.read_text(encoding="utf-8")).get("volta")
    value = volta.get("node") if isinstance(volta, dict) else None
    return value if isinstance(value, str) else None


def pin_from_pyvenv(path: Path, engine: str) -> str | None:
    """Read the interpreter version a project's own `.venv` was created with."""
    if engine != "python":
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        if key.strip() in ("version", "version_info"):
            return value.strip()
    return None


def read_runtime_pin(project_path: str, registry: ProjectPackagesRegistry) -> RuntimePin | None:
    """Return the first concrete runtime pin the project declares for its registry's engine.

    Files are checked in the order a version manager would honour them: the engine's own file
    first, then the multi-tool managers, then the environment the project was last installed into.
    An unreadable or malformed file is skipped rather than failing the scan; it's a cross-check,
    not an input.

    Args:
        project_path: The project root.
        registry: Decides which engine's pins are read (`node` for npm, `python` for PyPI).

    Returns:
        The pin, or None when the project pins nothing concrete.
    """
    engine = ENGINE_CONTEXT_KEY_BY_REGISTRY.get(registry)
    if engine is None:
        return None
    root = Path(project_path)
    readers = {
        "node": (
            (".nvmrc", pin_from_version_file),
            (".node-version", pin_from_version_file),
            (".tool-versions", pin_from_tool_versions),
            ("mise.toml", pin_from_mise),
            ("package.json", pin_from_volta),
        ),
        "python": (
            (".python-version", pin_from_version_file),
            (".tool-versions", pin_from_tool_versions),
            ("mise.toml", pin_from_mise),
            (".venv/pyvenv.cfg", pin_from_pyvenv),
        ),
    }[engine]
    for file_name, reader in readers:
        path = root / file_name
        if not path.is_file():
            continue
        try:
            raw = reader(path, engine)
        except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
            logger.debug("Skipping unreadable runtime pin %s: %s", path, error)
            continue
        version = concrete_version(raw) if raw else None
        if version is not None:
            return RuntimePin(engine=engine, version=version, pin_file=file_name)
    return None


def pin_matches(pinned: str, runtime: str) -> bool:
    """True when *runtime* falls inside what *pinned* names: `20` admits `20.11.0`, `3.11` admits `3.11.9`."""
    runtime_version = concrete_version(runtime)
    if runtime_version is None:
        return True
    pinned_parts = pinned.split(".")
    return runtime_version.split(".")[: len(pinned_parts)] == pinned_parts
