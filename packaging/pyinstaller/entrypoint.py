"""PyInstaller entry point for the standalone `ossiq` binary.

Kept separate from ``ossiq.cli`` so the frozen build has a real script file to
analyse, and so multiprocessing-style re-entry is handled before Typer runs.
"""

import multiprocessing
import sys

from ossiq.cli import app

if __name__ == "__main__":
    # No-op outside frozen builds; required so a re-executed child process does
    # not restart the CLI from the top.
    multiprocessing.freeze_support()
    sys.exit(app())
