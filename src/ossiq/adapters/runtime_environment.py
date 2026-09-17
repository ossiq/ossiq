"""Best-effort detection of the actually-installed Python/Node/npm runtime.

Enrichment, not a resolution step: every probe here is read-only and must never raise or block a
scan. Contrast with `adapters.package_managers.api_uv.execute_update`/`install_package`, which
legitimately `check=True` and raise on subprocess failure because those commands mutate a user's
manifest — nothing here does.
"""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

PROBE_TIMEOUT = 3
PYVENV_VERSION_RE = re.compile(r"^version\s*=\s*(\S+)", re.MULTILINE)
PYTHON_VERSION_OUTPUT_RE = re.compile(r"(\d+\.\d+\.\d+)")
NODE_VERSION_OUTPUT_RE = re.compile(r"v?(\d+\.\d+\.\d+)")


def run_version_probe(command: list[str], pattern: re.Pattern[str]) -> str | None:
    """Run *command* and extract a version string from its output via *pattern*, or None.

    Never raises: a missing binary, a timeout, or unparseable output all resolve to None.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("runtime probe %r failed: %s", command, exc)
        return None
    output = (result.stdout or "") + (result.stderr or "")
    match = pattern.search(output)
    return match.group(1) if match else None


def detect_actual_python_version(project_path: str) -> str | None:
    """Return the Python version that would actually run this project, or None.

    Tries, in order: `.venv/pyvenv.cfg`'s own `version` line (most authoritative — this project's
    own virtualenv), `.python-version` (pyenv-style), then a bare `python3`/`python` on PATH as a
    last resort.
    """
    pyvenv_cfg = Path(project_path) / ".venv" / "pyvenv.cfg"
    try:
        contents = pyvenv_cfg.read_text(encoding="utf-8")
    except OSError:
        contents = None
    if contents is not None:
        match = PYVENV_VERSION_RE.search(contents)
        if match:
            return match.group(1)

    python_version_file = Path(project_path) / ".python-version"
    try:
        declared = python_version_file.read_text(encoding="utf-8").strip()
    except OSError:
        declared = ""
    if declared:
        return declared

    for binary in ("python3", "python"):
        version = run_version_probe([binary, "--version"], PYTHON_VERSION_OUTPUT_RE)
        if version:
            return version
    return None


def detect_actual_node_version() -> str | None:
    """Return the Node version on PATH right now, or None.

    Deliberately does not fall back to reading `.nvmrc`: nvm/fnm/volta already put the correct
    binary on PATH for the active shell via their own auto-switch. An `.nvmrc` the user has not
    actually `nvm use`d is exactly the declared-vs-actual gap this module exists to close —
    reading the file directly would re-hide it.
    """
    return run_version_probe(["node", "--version"], NODE_VERSION_OUTPUT_RE)


def detect_actual_npm_cli_version() -> str | None:
    """Return the npm CLI version on PATH right now, or None. Display-only, never checked."""
    return run_version_probe(["npm", "--version"], NODE_VERSION_OUTPUT_RE)
