"""The session file and the file snapshots on disk, under `<project>/.ossiq/`."""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterable
from pathlib import Path

from ossiq.domain.exceptions import UpgradeSessionError
from ossiq.service.upgrade.models import UpgradeSession, session_from_json, session_to_json

STATE_DIR = ".ossiq"
SESSION_FILE = "update-progress.json"
SNAPSHOTS_DIR = "snapshots"
START = "start"


def state_dir(root: Path) -> Path:
    return root / STATE_DIR


def exists(root: Path) -> bool:
    return (state_dir(root) / SESSION_FILE).exists()


def load(root: Path) -> UpgradeSession:
    """Read the project's session.

    Raises:
        UpgradeSessionError: There is no session, or the file cannot be read.
    """
    path = state_dir(root) / SESSION_FILE
    if not path.exists():
        raise UpgradeSessionError("No upgrade session in this project.", hint="Run `ossiq upgrade start` to begin one.")
    return session_from_json(path.read_text(encoding="utf-8"))


def save(root: Path, session: UpgradeSession) -> None:
    """Write the session whole, so an interrupted write cannot leave half a file."""
    directory = state_dir(root)
    directory.mkdir(exist_ok=True)
    # The state must not end up in the user's commit; a `*` ignores this file too.
    (directory / ".gitignore").write_text("*\n", encoding="utf-8")
    temporary = directory / f"{SESSION_FILE}.tmp"
    temporary.write_text(session_to_json(session), encoding="utf-8")
    os.replace(temporary, directory / SESSION_FILE)


def snapshot(root: Path, name: str, files: Iterable[str]) -> None:
    """Copy *files* (those that exist) to a named snapshot, replacing an older one of that name."""
    target = state_dir(root) / SNAPSHOTS_DIR / name
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True)
    for file in files:
        if (root / file).exists():
            shutil.copy2(root / file, target / file)


def restore(root: Path, name: str, files: Iterable[str]) -> None:
    """Put *files* back as the snapshot had them; a file the snapshot lacks did not exist, so it is removed."""
    source = state_dir(root) / SNAPSHOTS_DIR / name
    for file in files:
        if (source / file).exists():
            shutil.copy2(source / file, root / file)
        else:
            (root / file).unlink(missing_ok=True)


def drop_snapshot(root: Path, name: str) -> None:
    shutil.rmtree(state_dir(root) / SNAPSHOTS_DIR / name, ignore_errors=True)


def end(root: Path) -> None:
    """Forget the session: remove everything OSS IQ keeps for it."""
    directory = state_dir(root)
    shutil.rmtree(directory / SNAPSHOTS_DIR, ignore_errors=True)
    for name in (SESSION_FILE, f"{SESSION_FILE}.tmp", ".gitignore"):
        (directory / name).unlink(missing_ok=True)
    try:
        directory.rmdir()
    except OSError:
        pass  # something else lives in .ossiq/; not ours to delete
