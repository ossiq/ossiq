import shutil
import subprocess
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        """Build frontend assets before packaging."""
        root = Path(self.root)
        frontend_dir = root / "frontend"
        target_html = root / "src" / "ossiq" / "ui" / "html_templates" / "spa_app.html"

        npm = shutil.which("npm")
        if not npm:
            raise RuntimeError("npm is required to build frontend assets.")

        subprocess.check_call([npm, "install"], cwd=str(frontend_dir))
        subprocess.check_call([npm, "run", "build"], cwd=str(frontend_dir))

        # Vite outputs to frontend/dist/index.html by default
        built_html = frontend_dir / "dist" / "index.html"
        if not built_html.exists():
            raise FileNotFoundError(f"Frontend build did not produce {built_html}")

        target_html.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(built_html), str(target_html))
