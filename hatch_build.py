import sys
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        """Build frontend assets before packaging."""
        root = Path(self.root)

        # Import the shared build function from frontend_build.py at project root
        sys.path.insert(0, str(root))
        from frontend_build import build_frontend

        build_frontend(root)
