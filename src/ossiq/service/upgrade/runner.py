"""Run the project's test command and keep the tail of its output."""

from __future__ import annotations

import subprocess
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from ossiq.service.upgrade.models import CommandRun

TAIL_LINES = 200
TAIL_CHARS = 16_000


def run_command(command: str, cwd: Path, on_line: Callable[[str], None] | None = None) -> CommandRun:
    """Run *command* in a shell; it comes from a flag or the committed .ossiq.yaml, so it is the user's own code.

    Args:
        command: The shell command line.
        cwd: The project directory to run it in.
        on_line: Receives each output line as it arrives; None keeps stdout untouched.

    Returns:
        The exit code and the last lines of its combined stdout and stderr.
    """
    if on_line is not None:
        on_line(f"$ {command}")
    tail: deque[str] = deque(maxlen=TAIL_LINES)
    with subprocess.Popen(
        command, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace"
    ) as process:
        assert process.stdout is not None
        for raw in process.stdout:
            line = raw.rstrip("\n")
            tail.append(line)
            if on_line is not None:
                on_line(line)
    return CommandRun(
        exit_code=process.returncode,
        ran_at=datetime.now(UTC).isoformat(timespec="seconds"),
        output_tail="\n".join(tail)[-TAIL_CHARS:],
    )
